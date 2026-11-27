// Copyright 2026 Dunkel Cloud GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package blob

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// An upload URL takes one file into the store without MCP credentials. An
// authenticated caller creates it (the create_upload_url built-in), and
// whoever holds it may PUT one file to it: in one request, or in parts with
// Content-Range, until the file is complete or the URL expires. The file
// counts against the quota of the caller who created the URL. The URL is a
// write-only capability: its token is the only credential, and its answers
// tell how much is stored but never name the blob, whose ID is the credential
// for reading it. Only a hash of the token is kept, and the MCP server writes
// the token as [REDACTED] in its request log and its DEBUG lines.

// UploadURLPathPrefix is the path under which upload URLs are served.
const UploadURLPathPrefix = "/files/upload/"

// UploadURLPartBytes is the part size create_upload_url recommends for a file
// sent in parts. It stays below the 100 MB a single request may carry through
// common proxies such as Cloudflare.
const UploadURLPartBytes = 32 << 20

// Limits on open upload URLs, so that creating URLs cannot use up memory or
// disk: an URL whose file is not complete yet counts until it expires.
const (
	maxUploadURLsPerOwner = 16
	maxUploadURLs         = 256
)

// uploadURLTokenBytes is the length of the random token in an upload URL.
const uploadURLTokenBytes = 32

// partSuffix names the file an upload URL writes to until the file is
// complete. The name matches blobFileName, so a part file a previous run left
// behind is removed at startup.
const partSuffix = ".part"

// Variables, not constants, so that tests can shorten them.
var (
	// uploadURLLifetime is how long an upload URL accepts requests.
	uploadURLLifetime = time.Hour
	// uploadURLRequestTimeout bounds reading the body of one request to an
	// upload URL and writing the answer. It replaces the HTTP server's much
	// shorter timeouts, which are meant for small requests.
	uploadURLRequestTimeout = 10 * time.Minute
)

// ErrTooManyUploadURLs is returned by NewUploadURL when the caller, or the
// server as a whole, holds as many open upload URLs as it may.
var ErrTooManyUploadURLs = errors.New("too many open upload URLs")

// UploadURLRequest describes the file an upload URL is created for.
type UploadURLRequest struct {
	// Owner is the user the file counts against in the quota; empty for none.
	Owner string
	// Filename is recorded with the blob for downstream multipart uploads.
	Filename string
	// ContentType is the media type of the file. When empty, the
	// Content-Type of the first request to the URL is taken, and
	// application/octet-stream when that has none either.
	ContentType string
	// Size is the size of the file in bytes, 0 when not known in advance.
	// When set, the file must have exactly this size.
	Size int64
	// TTL is how long the blob is kept once the file is complete.
	TTL time.Duration
}

// UploadURL is a created upload URL.
type UploadURL struct {
	URL       string    // the URL to PUT the file to; it carries the token
	BlobID    string    // the ID the file is stored under once complete
	ExpiresAt time.Time // when the URL stops accepting requests
	MaxBytes  int64     // the largest file the URL takes
}

// uploadTicket is the state behind one upload URL. The fields are guarded by
// Store.ticketMu, except that the part file is written outside the lock by
// the one request that set busy.
type uploadTicket struct {
	owner       string
	blobID      string
	filename    string
	contentType string
	declared    int64 // size announced when the URL was created; 0 = none
	total       int64 // size of the file once a request named it; -1 before
	received    int64 // bytes in the part file, all counted in the quota
	expires     time.Time
	ttl         time.Duration
	busy        bool      // a request is writing to the part file
	complete    bool      // the file is a blob now
	blobExpires time.Time // when the blob expires, once complete
}

// uploadURLAnswer is the JSON body every answer of an upload URL carries:
// how much of the file is stored. It does not name the blob: its ID would let
// whoever holds the URL read the file, and the caller who created the URL got
// the handle with it.
type uploadURLAnswer struct {
	Error            string     `json:"error,omitempty"`
	Received         int64      `json:"received"`
	Complete         bool       `json:"complete"`
	Size             int64      `json:"size,omitempty"`
	UploadURLExpires *time.Time `json:"upload_url_expires,omitempty"`
	Expires          *time.Time `json:"expires,omitempty"`
	ContentType      string     `json:"content_type,omitempty"`
}

// NewUploadURL creates an upload URL for one file. limits bounds the file
// size (MaxBytes) and the blob TTL (DefaultTTL when req.TTL is not set,
// MaxTTL at most).
func (s *Store) NewUploadURL(req UploadURLRequest, limits UploadLimits) (*UploadURL, error) {
	if req.Size < 0 {
		return nil, fmt.Errorf("invalid size %d: must be 0 (unknown) or more", req.Size)
	}
	if req.Size > limits.MaxBytes {
		return nil, fmt.Errorf("file is %d bytes, exceeding the %d byte limit", req.Size, limits.MaxBytes)
	}
	if req.ContentType != "" {
		if _, _, err := mime.ParseMediaType(req.ContentType); err != nil {
			return nil, fmt.Errorf("invalid content type %q: %w", req.ContentType, err)
		}
	}
	if req.Size > 0 {
		if err := s.CheckQuota(req.Owner, req.Size); err != nil {
			return nil, err
		}
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = limits.DefaultTTL
	}
	if limits.MaxTTL > 0 && ttl > limits.MaxTTL {
		ttl = limits.MaxTTL
	}

	raw := make([]byte, uploadURLTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate upload URL token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	id, err := generateID()
	if err != nil {
		return nil, fmt.Errorf("generate blob id: %w", err)
	}

	now := time.Now()
	s.removeExpiredUploadURLs(now)

	s.ticketMu.Lock()
	defer s.ticketMu.Unlock()
	open, ofOwner := 0, 0
	for _, t := range s.tickets {
		if t.complete {
			continue
		}
		open++
		if t.owner == req.Owner {
			ofOwner++
		}
	}
	if open >= maxUploadURLs {
		return nil, fmt.Errorf("%w: the server holds %d; try again when some are complete or expired", ErrTooManyUploadURLs, open)
	}
	if req.Owner != "" && ofOwner >= maxUploadURLsPerOwner {
		return nil, fmt.Errorf("%w: you hold %d, the most one user may; complete them or wait until they expire (one hour after they were created)", ErrTooManyUploadURLs, ofOwner)
	}
	if s.tickets == nil {
		s.tickets = make(map[string]*uploadTicket)
	}
	t := &uploadTicket{
		owner:       req.Owner,
		blobID:      id,
		filename:    req.Filename,
		contentType: req.ContentType,
		declared:    req.Size,
		total:       -1,
		expires:     now.Add(uploadURLLifetime),
		ttl:         ttl,
	}
	s.tickets[tokenKey(token)] = t
	return &UploadURL{
		URL:       s.baseURL + UploadURLPathPrefix + token,
		BlobID:    id,
		ExpiresAt: t.expires,
		MaxBytes:  limits.MaxBytes,
	}, nil
}

// tokenKey is the key a ticket is kept under: the hash of its token, so the
// token itself is not kept in memory.
func tokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// partPath is the file an upload URL writes to until the file is complete.
func (s *Store) partPath(t *uploadTicket) string {
	return filepath.Join(s.dir, t.blobID+partSuffix)
}

// removeExpiredUploadURLs forgets the upload URLs that have expired at now
// and no request is writing to. The part file of an incomplete one is
// removed and its bytes leave the quota; a complete one only stops answering,
// its blob lives on until its own TTL.
func (s *Store) removeExpiredUploadURLs(now time.Time) {
	type leftover struct {
		path  string
		owner string
		bytes int64
	}
	var gone []leftover
	s.ticketMu.Lock()
	for key, t := range s.tickets {
		if t.busy || !now.After(t.expires) {
			continue
		}
		if !t.complete {
			gone = append(gone, leftover{path: s.partPath(t), owner: t.owner, bytes: t.received})
		}
		delete(s.tickets, key)
	}
	s.ticketMu.Unlock()
	for _, l := range gone {
		if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
			s.logger.Warn("failed to remove the part file of an expired upload URL", "file", filepath.Base(l.path), "error", err)
		}
		s.release(l.owner, l.bytes)
	}
}

// HandleUploadURL serves the requests to an upload URL (UploadURLPathPrefix
// followed by the token): GET or HEAD tells how much of the file is stored,
// PUT stores the file or a part of it. It performs no authentication; the
// token is the credential. limits.MaxBytes bounds the file.
func (s *Store) HandleUploadURL(w http.ResponseWriter, r *http.Request, limits UploadLimits) {
	token := strings.TrimPrefix(r.URL.Path, UploadURLPathPrefix)
	if token == "" || strings.Contains(token, "/") {
		writeUploadURLError(w, http.StatusNotFound, "unknown or expired upload URL")
		return
	}
	key := tokenKey(token)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.uploadURLStatus(w, r, key)
	case http.MethodPut:
		s.uploadURLPut(w, r, key, limits)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT")
		writeUploadURLError(w, http.StatusMethodNotAllowed, "an upload URL takes PUT, and GET or HEAD for its state")
	}
}

// liveTicketLocked returns the ticket under key unless it is unknown or has
// expired. A request already writing to an expired ticket may finish, but no
// new one starts. The caller holds s.ticketMu.
func (s *Store) liveTicketLocked(key string, now time.Time) *uploadTicket {
	t := s.tickets[key]
	if t == nil || now.After(t.expires) {
		return nil
	}
	return t
}

func (s *Store) uploadURLStatus(w http.ResponseWriter, r *http.Request, key string) {
	s.ticketMu.Lock()
	t := s.liveTicketLocked(key, time.Now())
	var answer uploadURLAnswer
	if t != nil {
		answer = answerFor(t)
	}
	s.ticketMu.Unlock()
	if t == nil {
		writeUploadURLError(w, http.StatusNotFound, "unknown or expired upload URL")
		return
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		return
	}
	writeUploadURLAnswer(w, http.StatusOK, answer)
}

// answerFor describes the state of t. The caller holds s.ticketMu.
func answerFor(t *uploadTicket) uploadURLAnswer {
	a := uploadURLAnswer{
		Received: t.received,
		Complete: t.complete,
	}
	switch {
	case t.total >= 0:
		a.Size = t.total
	case t.declared > 0:
		a.Size = t.declared
	}
	if t.complete {
		expires := t.blobExpires
		a.Expires, a.ContentType = &expires, t.contentType
		return a
	}
	expires := t.expires
	a.UploadURLExpires = &expires
	return a
}

// putRange is what one PUT writes: bytes first to last of a file of total
// bytes. total is -1 for a whole-file PUT of unknown length.
type putRange struct {
	ranged      bool
	first, last int64
	total       int64
}

// parseContentRange reads a Content-Range header of the form
// "bytes FIRST-LAST/TOTAL". Every other form is refused, the status query
// "bytes */TOTAL" included: GET on the URL serves that purpose.
func parseContentRange(v string) (putRange, error) {
	errForm := fmt.Errorf("the Content-Range header %q must have the form bytes FIRST-LAST/TOTAL (to see how much is stored, GET the URL)", v)
	rest, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return putRange{}, errForm
	}
	span, totalText, ok := strings.Cut(rest, "/")
	if !ok {
		return putRange{}, errForm
	}
	firstText, lastText, ok := strings.Cut(span, "-")
	if !ok {
		return putRange{}, errForm
	}
	var nums [3]int64
	for i, text := range []string{firstText, lastText, totalText} {
		if text == "" || strings.TrimLeft(text, "0123456789") != "" {
			return putRange{}, errForm
		}
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return putRange{}, errForm
		}
		nums[i] = n
	}
	first, last, total := nums[0], nums[1], nums[2]
	if last < first || total <= last {
		return putRange{}, fmt.Errorf("the Content-Range header %q is not a range inside the file", v)
	}
	return putRange{ranged: true, first: first, last: last, total: total}, nil
}

// uploadURLPut stores the body of a PUT: the whole file, or with
// Content-Range the next part of it. A part is stored completely or not at
// all, so the bytes stored always end where a part ended, and a part whose
// answer got lost can be sent again: it is answered with 409 and the stored
// size, and the client goes on with the next one.
func (s *Store) uploadURLPut(w http.ResponseWriter, r *http.Request, key string, limits UploadLimits) {
	var pr putRange
	if v := r.Header.Get("Content-Range"); v != "" {
		var err error
		if pr, err = parseContentRange(v); err != nil {
			writeUploadURLError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		pr = putRange{total: r.ContentLength}
		if pr.total >= 0 {
			pr.last = pr.total - 1
		}
	}

	s.ticketMu.Lock()
	t := s.liveTicketLocked(key, time.Now())
	if t == nil {
		s.ticketMu.Unlock()
		writeUploadURLError(w, http.StatusNotFound, "unknown or expired upload URL")
		return
	}
	if t.complete {
		// The file is complete: a part sent again because its answer got
		// lost gets the same answer, without storing anything.
		answer := answerFor(t)
		s.ticketMu.Unlock()
		writeUploadURLAnswer(w, http.StatusOK, answer)
		return
	}
	status, msg := s.checkPutLocked(t, pr, r, limits)
	if status != 0 {
		answer := answerFor(t)
		s.ticketMu.Unlock()
		answer.Error = msg
		writeUploadURLAnswer(w, status, answer)
		return
	}
	// The first request that writes may name the content type and the size;
	// both are taken back when nothing of it is stored.
	typeFromRequest := t.contentType == ""
	if typeFromRequest {
		t.contentType = r.Header.Get("Content-Type")
	}
	if pr.total >= 0 {
		t.total = pr.total
	}
	t.busy = true
	owner, offset, declared, path := t.owner, t.received, t.declared, s.partPath(t)
	s.ticketMu.Unlock()
	// Every way out clears busy before it answers, so that the next part is
	// not refused; a panic would skip that and lock the URL for good.
	defer func() {
		if p := recover(); p != nil {
			s.ticketMu.Lock()
			t.busy = false
			s.ticketMu.Unlock()
			panic(p)
		}
	}()

	// Only a request to a valid URL gets the longer deadline, so a client
	// without a token cannot hold a connection open for long.
	extendUploadDeadline(w)
	n, status, msg, lost := s.writePart(r, path, owner, offset, pr, declared, limits)
	if status != 0 {
		s.ticketMu.Lock()
		if lost {
			// writePart removed what was left and gave the bytes back.
			t.received = 0
		}
		if t.received == 0 {
			t.total = -1
			if typeFromRequest {
				t.contentType = ""
			}
		}
		t.busy = false
		answer := answerFor(t)
		s.ticketMu.Unlock()
		answer.Error = msg
		writeUploadURLAnswer(w, status, answer)
		return
	}

	s.ticketMu.Lock()
	t.received += n
	if t.total < 0 {
		t.total = t.received
	}
	complete := t.received == t.total
	if !complete {
		t.busy = false
		answer := answerFor(t)
		s.ticketMu.Unlock()
		writeUploadURLAnswer(w, http.StatusAccepted, answer)
		return
	}
	s.ticketMu.Unlock()
	s.completeUploadURL(w, t, path)
}

// checkPutLocked decides whether the PUT described by pr may write to t. It
// returns 0 when it may, else the status and message to answer with. The
// caller holds s.ticketMu.
func (s *Store) checkPutLocked(t *uploadTicket, pr putRange, r *http.Request, limits UploadLimits) (status int, msg string) {
	switch {
	case t.busy:
		return http.StatusConflict, "another request is writing to this upload URL; wait for it to end, then GET the URL to see how much is stored"
	case !pr.ranged && t.received > 0:
		return http.StatusConflict, "part of the file is stored already: send the rest in parts with Content-Range, starting at the received byte count"
	case pr.total == 0:
		return http.StatusBadRequest, "the file is empty"
	case pr.total > limits.MaxBytes:
		return http.StatusRequestEntityTooLarge, fmt.Sprintf("the file is %d bytes, exceeding the %d byte limit", pr.total, limits.MaxBytes)
	case t.declared > 0 && pr.total >= 0 && pr.total != t.declared:
		return http.StatusBadRequest, fmt.Sprintf("the file is %d bytes, but the upload URL was created for %d bytes", pr.total, t.declared)
	case pr.ranged && t.total >= 0 && pr.total != t.total:
		return http.StatusBadRequest, fmt.Sprintf("Content-Range names a file of %d bytes, the parts before named %d bytes", pr.total, t.total)
	case pr.ranged && pr.first != t.received:
		return http.StatusConflict, fmt.Sprintf("the part starts at byte %d, but %d bytes are stored: send the part that starts there", pr.first, t.received)
	case pr.ranged && r.ContentLength >= 0 && r.ContentLength != pr.last-pr.first+1:
		return http.StatusBadRequest, fmt.Sprintf("the body has %d bytes, Content-Range announces %d", r.ContentLength, pr.last-pr.first+1)
	}
	if t.contentType == "" {
		if v := r.Header.Get("Content-Type"); v != "" {
			if _, _, err := mime.ParseMediaType(v); err != nil {
				return http.StatusBadRequest, fmt.Sprintf("invalid Content-Type %q", v)
			}
		}
	}
	if pr.total >= 0 {
		if err := s.CheckQuota(t.owner, pr.last-pr.first+1); err != nil {
			return http.StatusInsufficientStorage, err.Error()
		}
	}
	return 0, ""
}

// writePart appends the body of r to the part file at path, which holds
// offset bytes. It returns the bytes written, or a status and message when
// the part is refused; then the part file is cut back to offset and the
// bytes leave the quota again, so a part is stored completely or not at all.
// lost reports that the part file no longer held the offset bytes stored
// before: then it is removed, those bytes leave the quota, and the upload
// has to start again.
func (s *Store) writePart(r *http.Request, path, owner string, offset int64, pr putRange, declared int64, limits UploadLimits) (n int64, status int, msg string, lost bool) {
	// The most the body may carry: the announced part, else the limit. One
	// byte more tells a longer body from one of exactly that size.
	want := limits.MaxBytes
	switch {
	case pr.total >= 0:
		want = pr.last - pr.first + 1
	case declared > 0:
		want = declared
	}

	// The first request creates the part file; a later one finds it with
	// exactly the bytes stored before, else they are lost.
	flags := os.O_WRONLY
	if offset == 0 {
		flags |= os.O_CREATE | os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // path is constructed from trusted dir + generated ID
	gone := offset > 0 && os.IsNotExist(err)
	if err == nil && offset > 0 {
		var fi os.FileInfo
		if fi, err = f.Stat(); err == nil && fi.Size() != offset {
			err = fmt.Errorf("part file holds %d bytes, %d were stored", fi.Size(), offset)
			gone = true
		}
		if err != nil {
			_ = f.Close()
		}
	}
	switch {
	case gone:
		s.logger.Error("upload URL: part file is gone or changed", "file", filepath.Base(path), "error", err)
		_ = os.Remove(path)
		s.release(owner, offset)
		return 0, http.StatusInternalServerError, "the parts stored so far are lost; send the file again from the start", true
	case err != nil:
		s.logger.Error("upload URL: open part file", "file", filepath.Base(path), "error", err)
		return 0, http.StatusInternalServerError, "could not store the file; send the part again", false
	}
	qw := &quotaWriter{s: s, owner: owner, w: f}
	// A panic below would skip the cleanup at the end: close the file, cut it
	// back and give the bytes of this request back before it goes on.
	defer func() {
		if p := recover(); p != nil {
			_ = f.Close()
			s.cutBack(path, offset)
			s.release(owner, qw.reserved)
			panic(p)
		}
	}()
	body := &readErrReader{r: io.LimitReader(r.Body, want+1)}
	if _, err = f.Seek(offset, io.SeekStart); err == nil {
		n, err = io.Copy(qw, body)
	}
	closeErr := f.Close()

	switch {
	case errors.Is(err, ErrQuotaExceeded):
		status, msg = http.StatusInsufficientStorage, err.Error()
	case err != nil && body.err != nil:
		status, msg = http.StatusBadRequest, "the body ended before it was complete; nothing of this request is stored"
	case err != nil || closeErr != nil:
		s.logger.Error("upload URL: write part file", "file", filepath.Base(path), "error", errors.Join(err, closeErr))
		status, msg = http.StatusInternalServerError, "could not store the file"
	case n == 0 && !pr.ranged:
		status, msg = http.StatusBadRequest, "the file is empty"
	case n > want && pr.total < 0 && declared == 0:
		status, msg = http.StatusRequestEntityTooLarge, fmt.Sprintf("the file exceeds the %d byte limit", limits.MaxBytes)
	case n > want || ((pr.total >= 0 || declared > 0) && n < want):
		status, msg = http.StatusBadRequest, fmt.Sprintf("the body has %s bytes, %d were announced; nothing of this request is stored", bodyCount(n, want), want)
	}
	if status == 0 {
		return n, 0, "", false
	}
	s.cutBack(path, offset)
	s.release(owner, qw.reserved)
	return 0, status, msg, false
}

// cutBack takes the bytes of a refused request out of the part file at path,
// which held offset bytes before it: the file goes when it held none.
func (s *Store) cutBack(path string, offset int64) {
	if offset == 0 {
		_ = os.Remove(path)
	} else if err := os.Truncate(path, offset); err != nil {
		s.logger.Error("upload URL: cut back part file", "error", err)
	}
}

// readErrReader remembers the error reading the body failed with, so that a
// body that broke off can be told from a write that failed.
type readErrReader struct {
	r   io.Reader
	err error
}

func (e *readErrReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		e.err = err
	}
	return n, err
}

// bodyCount names how many bytes a body had: n, or "more than want" when the
// read stopped one byte past it.
func bodyCount(n, want int64) string {
	if n > want {
		return fmt.Sprintf("more than %d", want)
	}
	return strconv.FormatInt(n, 10)
}

// completeUploadURL makes the complete part file a blob under the ID the
// upload URL announced and answers with it. The bytes stay counted in the
// quota: from now on for the blob.
func (s *Store) completeUploadURL(w http.ResponseWriter, t *uploadTicket, path string) {
	s.ticketMu.Lock()
	contentType, filename, owner, size, ttl, id := t.contentType, t.filename, t.owner, t.total, t.ttl, t.blobID
	s.ticketMu.Unlock()
	if contentType == "" {
		contentType = defaultContentType
	}

	final := filepath.Join(s.dir, id+extensionForType(contentType))
	if err := os.Rename(path, final); err != nil {
		s.logger.Error("upload URL: move part file into place", "error", err)
		_ = os.Remove(path)
		s.release(owner, size)
		s.ticketMu.Lock()
		t.received, t.total, t.busy = 0, -1, false
		answer := answerFor(t)
		s.ticketMu.Unlock()
		answer.Error = "could not store the file; send it again from the start"
		writeUploadURLAnswer(w, http.StatusInternalServerError, answer)
		return
	}

	expires := time.Now().Add(ttl)
	s.mu.Lock()
	s.blobs[id] = &blobEntry{
		FilePath:    final,
		ContentType: contentType,
		Size:        size,
		Filename:    filename,
		Owner:       owner,
		ExpiresAt:   expires,
	}
	s.mu.Unlock()
	s.logger.Info("blob stored",
		"blob_id", id,
		"content_type", contentType,
		"size_bytes", size,
		"ttl", ttl.String(),
		"source", "upload_url",
	)

	s.ticketMu.Lock()
	t.complete, t.blobExpires, t.contentType = true, expires, contentType
	t.busy = false
	answer := answerFor(t)
	s.ticketMu.Unlock()
	writeUploadURLAnswer(w, http.StatusCreated, answer)
}

// extendUploadDeadline gives the request behind w uploadURLRequestTimeout to
// send its body and get the answer: a large file or part takes longer than
// the HTTP server's timeouts allow, which are meant for small requests. Best
// effort, since a test recorder cannot set deadlines.
func extendUploadDeadline(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	deadline := time.Now().Add(uploadURLRequestTimeout)
	_ = rc.SetReadDeadline(deadline)
	_ = rc.SetWriteDeadline(deadline)
}

func writeUploadURLAnswer(w http.ResponseWriter, status int, answer uploadURLAnswer) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(answer)
}

func writeUploadURLError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
