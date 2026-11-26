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

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/urlredact"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// A resumable upload (tool key upload, protocol google_resumable) runs in
// one tool call:
//
//  1. The tool's request, with uploadType=resumable and the tool's body
//     parameters as JSON metadata, opens a session. The API answers with
//     the session URI in the Location header.
//  2. The file goes to the session URI in chunks: PUT with Content-Range.
//     While the file is incomplete the API answers 308 with a Range header
//     naming the bytes it has stored.
//  3. After an interruption a PUT with "Content-Range: bytes */<size>" asks
//     how far the API got, and the transfer continues from there.
//  4. The answer to the last chunk is the API's response to the upload; it
//     runs through the response pipeline like any other.
//
// The sessions are kept in uploadSessions, keyed by the call's arguments,
// so that the same call again continues an upload instead of starting a
// second one: after the call ran out of time, after the transfer kept
// failing, or after the response to the last chunk was lost. Once the chunk
// with the file's last byte has gone out, the API may complete the upload
// at any moment, so from then on a session is never given up silently:
// either it is kept for the next call, or the call says that the outcome is
// unknown. Before that, nothing can exist, and a session can go.
//
// The session URI is a capability: whoever has it can send the file. It is
// never logged and never part of a result, an error or metadata.

// Sizes and times of the transfer. They are variables only so that tests
// can shrink them.
var (
	// uploadChunkSize is the size of one chunk. Google requires every chunk
	// but the last to be a multiple of 256 KiB. 8 MiB keeps one request
	// short on a slow link and the number of requests small.
	uploadChunkSize int64 = 8 << 20

	// uploadDeadlineReserve is how long before the call's deadline a chunk
	// is cut off, so that a status query still fits and the call can say
	// how far the upload got.
	uploadDeadlineReserve = 5 * time.Second

	// uploadMinChunkWindow is the least time a new chunk is started with.
	// With less left, the call stops and reports the upload incomplete.
	uploadMinChunkWindow = 15 * time.Second
)

const (
	// uploadMaxRetryAfter caps a Retry-After wait of the API.
	uploadMaxRetryAfter = time.Minute

	// uploadDrainLimit caps how much of a body the upload reads and
	// discards where the body carries no result (308 answers, errors).
	uploadDrainLimit = 64 << 10

	// uploadKeptBodyLimit caps the final response kept for a repeated call.
	// A resource description is a few KB; the cap bounds what the APIs can
	// make the session store hold.
	uploadKeptBodyLimit = 64 << 10

	// uploadSessionTTL is how long a session that has not finished is kept
	// after its last use. Google keeps a session for about a week.
	uploadSessionTTL = 24 * time.Hour

	// uploadCompletedTTL is how long a finished upload answers a repeated
	// call with its response instead of uploading again.
	uploadCompletedTTL = time.Hour

	// maxUploadSessions bounds the session store.
	maxUploadSessions = 1024
)

// Metadata keys of the result of an upload tool.
const (
	metadataKeyUploadSize     = "upload_size"     // size of the file in bytes
	metadataKeyUploadStored   = "upload_stored"   // bytes the API confirmed when the upload stopped incomplete
	metadataKeyUploadResumed  = "upload_resumed"  // this call continued a session of an earlier call
	metadataKeyUploadRepeated = "upload_repeated" // the upload finished in an earlier call; the result is its response
)

// Query parameters of the google_resumable protocol.
const (
	uploadTypeParam     = "uploadType"
	uploadTypeResumable = "resumable"
)

// Headers of the google_resumable protocol.
const (
	headerUploadContentType   = "X-Upload-Content-Type"
	headerUploadContentLength = "X-Upload-Content-Length"
	headerContentRange        = "Content-Range"
	headerRange               = "Range"
	headerRetryAfter          = "Retry-After"
	headerLocation            = "Location"
)

// statusResumeIncomplete is the 308 Google answers while a file is
// incomplete. It is no redirect: the upload client follows none.
const statusResumeIncomplete = http.StatusPermanentRedirect

// uploadKeptNote is added to an error after the last byte went out: the
// session stays, because the API may already have completed the upload.
const uploadKeptNote = "The whole file was already sent, so the upload session is kept: calling the tool again with the same arguments " +
	"asks the API how far the upload got and continues it or returns the result. To start over on purpose, " +
	"store the file again and pass the new handle."

// uploadSizeKey is the key of an upload tool's max_body_size in
// RESTAdapter.maxBodySizes. It differs from the key of the same string on
// other tools, which is clamped to the per-request ceiling.
func uploadSizeKey(declared string) string {
	return "upload:" + declared
}

// uploadFileLimit returns the largest file an upload tool takes: its
// max_body_size, or 0 for no limit of its own. The file comes from the file
// broker, which the operator bounds.
func (a *RESTAdapter) uploadFileLimit(tool *dadl.ToolDef) int64 {
	if tool.MaxBodySize == "" {
		return 0
	}
	if limit, ok := a.maxBodySizes[uploadSizeKey(tool.MaxBodySize)]; ok {
		return limit
	}
	// Unreachable for adapters built by NewRESTAdapter; fall back to the
	// per-request ceiling rather than to no limit at all.
	return maxUploadBytes
}

// uploadFile is the file of an upload: read in sections, by offset.
type uploadFile interface {
	io.ReaderAt
	io.Closer
}

// uploadSource is the file of an upload with its size and media type.
type uploadSource struct {
	file        uploadFile
	size        int64
	contentType string
}

// checkUploadSource refuses a file argument that is not a tm-blob:// handle.
// Only a blob stays the same between the calls that continue an upload: a
// web address would be fetched again by every call, a file on disk could be
// replaced, and either could change the file in the middle of an upload.
func checkUploadSource(paramName, raw string) error {
	if raw == "" {
		return fmt.Errorf("missing required file parameter %q", paramName)
	}
	if !blob.IsHandle(raw) {
		return fmt.Errorf("file parameter %q: an upload takes a tm-blob:// handle; store the file with upload_file or POST /files/upload first and pass the handle", paramName)
	}
	return nil
}

// errUploadFileGone marks the error of a file that is no longer stored
// (expired or deleted), as opposed to one that cannot be used.
var errUploadFileGone = errors.New("the file is not stored (expired or deleted)")

// openUploadSource opens the blob an upload tool sends.
func (a *RESTAdapter) openUploadSource(paramName, raw string, limit int64) (*uploadSource, error) {
	if a.blobStore == nil {
		return nil, fmt.Errorf("file parameter %q: %s requires the built-in file broker, which is not configured on this server", paramName, raw)
	}
	id, fragment, _, err := blob.ParseHandle(raw)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: %w", paramName, err)
	}
	if fragment != blob.FragmentNone {
		return nil, fmt.Errorf("file parameter %q: blob handle %q must not carry a format fragment — file_url parameters take the bare handle", paramName, raw)
	}
	rc, info, err := a.blobStore.Open(id)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: %w: %w", paramName, errUploadFileGone, err)
	}
	file, ok := rc.(uploadFile)
	if !ok {
		_ = rc.Close()
		return nil, fmt.Errorf("file parameter %q: blob %q cannot be read by offset", paramName, id)
	}
	if limit > 0 && info.Size > limit {
		_ = file.Close()
		return nil, fmt.Errorf("file parameter %q: file is %s, exceeding the %s limit for this tool", paramName, dadl.FormatByteSize(info.Size), dadl.FormatByteSize(limit))
	}
	if info.Size <= 0 {
		_ = file.Close()
		return nil, fmt.Errorf("file parameter %q: the file is empty", paramName)
	}
	contentType := info.ContentType
	if contentType == "" {
		contentType = contentTypeOctetStream
	}
	return &uploadSource{file: file, size: info.Size, contentType: contentType}, nil
}

// uploadSession is the state of one upload, shared by the calls that carry
// the same arguments. While busy, only the call that acquired it touches its
// fields; the store reads busy and, for idle entries, the rest.
type uploadSession struct {
	uri       *url.URL // session URI: a capability, never logged or returned
	size      int64    // size of the file the session was opened for
	mediaType string   // its media type
	secrets   []string // query values the API added to the session URI (the upload ID), redacted from every text
	stored    int64    // bytes the API last said it has
	sentLast  bool     // the chunk with the file's last byte went out: from then on the API may complete the upload
	completed bool     // the API answered the upload with 2xx
	status    int      // status of that answer
	body      []byte   // its body, nil when it could not be kept
	busy      bool
	touched   time.Time
}

// uploadSessionStore holds the upload sessions of the process. It is not
// tied to one adapter, so a hot reload of backends.yaml does not forget
// the sessions of the uploads running or stopped at that moment.
type uploadSessionStore struct {
	mu      sync.Mutex
	entries map[string]*uploadSession
	max     int
	now     func() time.Time
}

// uploadSessions is the session store of all upload tools; the keys carry
// the backend name.
var uploadSessions = newUploadSessionStore(maxUploadSessions)

func newUploadSessionStore(maxEntries int) *uploadSessionStore {
	return &uploadSessionStore{entries: make(map[string]*uploadSession), max: maxEntries, now: time.Now}
}

// acquire returns the session for key, a new empty one when there is none,
// and marks it busy. ok is false when another call holds it.
func (s *uploadSessionStore) acquire(key string) (sess *uploadSession, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.expireLocked(now)
	sess = s.entries[key]
	if sess != nil && sess.busy {
		return nil, false
	}
	if sess == nil {
		s.makeRoomLocked()
		sess = &uploadSession{}
		s.entries[key] = sess
	}
	sess.busy = true
	sess.touched = now
	return sess, true
}

// release ends a call's hold on the session. A session with nothing to
// continue or to answer with (no session URI, not completed) is removed,
// and so is one the call dropped.
func (s *uploadSessionStore) release(key string, sess *uploadSession, drop bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess.busy = false
	sess.touched = s.now()
	if drop || (sess.uri == nil && !sess.completed) {
		if s.entries[key] == sess {
			delete(s.entries, key)
		}
	}
}

// expireLocked removes idle sessions past their time.
func (s *uploadSessionStore) expireLocked(now time.Time) {
	for key, sess := range s.entries {
		if sess.busy {
			continue
		}
		ttl := uploadSessionTTL
		if sess.completed {
			ttl = uploadCompletedTTL
		}
		if now.Sub(sess.touched) > ttl {
			delete(s.entries, key)
		}
	}
}

// makeRoomLocked removes idle sessions while the store is full: first the
// one used longest ago among those whose last byte never went out
// (forgetting it can create nothing twice), then the one used longest ago
// of all. Busy sessions stay, so the store can exceed its bound by the
// number of uploads running at once.
func (s *uploadSessionStore) makeRoomLocked() {
	for len(s.entries) >= s.max {
		key := s.oldestIdleLocked(func(sess *uploadSession) bool { return !sess.sentLast && !sess.completed })
		if key == "" {
			key = s.oldestIdleLocked(func(*uploadSession) bool { return true })
		}
		if key == "" {
			return
		}
		delete(s.entries, key)
	}
}

// oldestIdleLocked returns the key of the idle session used longest ago
// among those match accepts, or "".
func (s *uploadSessionStore) oldestIdleLocked(match func(*uploadSession) bool) string {
	oldestKey := ""
	var oldest time.Time
	for key, sess := range s.entries {
		if sess.busy || !match(sess) {
			continue
		}
		if oldestKey == "" || sess.touched.Before(oldest) {
			oldestKey, oldest = key, sess.touched
		}
	}
	return oldestKey
}

// uploadKey identifies an upload by everything that makes it this upload:
// backend, tool, the calling user and account, and the call's arguments,
// the blob handle of the file among them. A blob never changes, so equal
// arguments mean the same file. encoding/json writes map keys sorted, so
// equal arguments give equal keys.
func uploadKey(ctx context.Context, backendName, toolName string, params map[string]any) (string, error) {
	args, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("encode upload arguments: %w", err)
	}
	user := ""
	if uc := userctx.FromContext(ctx); uc != nil {
		user = uc.UserID
	}
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00", backendName, toolName, user, credentials.AccountFromContext(ctx))
	_, _ = h.Write(args)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// executeUpload carries out a call of an upload tool. Every outcome is a
// tool result: the API's response, its error, or an upload error that says
// whether calling again continues the upload.
func (a *RESTAdapter) executeUpload(ctx context.Context, toolName string, tool *dadl.ToolDef, params map[string]any) *ToolResult {
	fileParam, _ := singleFileURLParam(tool)
	raw, _ := params[fileParam].(string)
	if err := checkUploadSource(fileParam, raw); err != nil {
		return a.paramErrorResult(ctx, toolName, err)
	}
	key, err := uploadKey(ctx, a.spec.Backend.Name, toolName, params)
	if err != nil {
		return a.paramErrorResult(ctx, toolName, err)
	}
	sess, ok := uploadSessions.acquire(key)
	if !ok {
		return a.apiErrorResult(&dadl.APIError{
			Code:       dadl.ErrCodeUploadInProgress,
			HTTPStatus: http.StatusConflict,
			Message:    "an upload with the same arguments is running in another call; wait for it, then call again to get its result",
		})
	}
	u := &uploadRun{a: a, ctx: ctx, toolName: toolName, tool: tool, params: params, fileParam: fileParam, sess: sess}
	// Deferred, so that a panic further down leaves the session idle, not
	// busy for good.
	defer func() { uploadSessions.release(key, sess, u.drop) }()
	return u.run(raw)
}

// uploadRun is one call's work on an upload.
type uploadRun struct {
	a         *RESTAdapter
	ctx       context.Context
	toolName  string
	tool      *dadl.ToolDef
	params    map[string]any
	fileParam string
	src       *uploadSource // nil while the file is not open
	sess      *uploadSession
	drop      bool // remove the session when the call ends
	resumed   bool
	requests  int
}

// answerKind classifies the API's answer to a request of the session.
type answerKind int

const (
	answerDone         answerKind = iota // 2xx: the upload is complete; status and body are the response
	answerIncomplete                     // 308: offset is where to continue
	answerGone                           // 404 or 410: the API no longer knows the session
	answerUnauthorized                   // 401: renew the credential, then ask how far the upload got
	answerAuthFailed                     // the credential could not be applied to the request
	answerTransient                      // transport error, 408, 429, 5xx or a retry_on status: wait, then ask
	answerFailed                         // anything else
)

// sessionAnswer is the API's answer to a request of the session.
type sessionAnswer struct {
	kind       answerKind
	offset     int64
	status     int
	body       []byte
	retryAfter time.Duration
	cutOff     bool // a chunk ran into the end of its context, not into an error of the API
	sent       *http.Request
	err        error
}

// run drives the upload to an end and returns the call's result.
func (u *uploadRun) run(raw string) *ToolResult {
	a, sess := u.a, u.sess
	if sess.completed {
		return u.repeatedResult()
	}
	if sess.uri != nil {
		u.resumed = true
		if res := u.checkSessionHome(); res != nil {
			return res
		}
	}

	src, err := a.openUploadSource(u.fileParam, raw, a.uploadFileLimit(u.tool))
	if err != nil {
		switch {
		case sess.uri == nil || !sess.sentLast:
			// Nothing can exist yet: forget the session.
			u.drop = true
		case errors.Is(err, errUploadFileGone):
			// The file is gone, but the API may have all of it already.
			return u.settleWithoutFile(err)
		}
		return a.paramErrorResult(u.ctx, u.toolName, err)
	}
	defer func() { _ = src.file.Close() }()
	u.src = src

	retryer := dadl.NewRetryer(u.retryStrategy(), a.logger)
	maxFailures := retryer.MaxRetries()
	// sess.stored is where the next chunk starts: what the API last said it
	// has. best is the most it said in this call; an answer at or below it
	// is no progress. answered is false until the first 308 of this call,
	// which sets the starting point without counting either way.
	var best int64
	answered := false
	failures := 0
	query := sess.uri != nil

	if sess.uri == nil {
		if res := u.openSession(retryer); res != nil {
			return res
		}
	}

	for {
		if err := u.ctx.Err(); err != nil {
			return u.incomplete(fmt.Sprintf("the call ended (%v)", err))
		}
		var ans sessionAnswer
		if query || sess.stored >= sess.size {
			ans = u.send(u.ctx, -1, 0)
		} else {
			if !timeLeft(u.ctx, uploadMinChunkWindow) {
				return u.incomplete("too little time was left in this call for another chunk")
			}
			n := min(uploadChunkSize, sess.size-sess.stored)
			if sess.stored+n == sess.size {
				sess.sentLast = true
			}
			chunkCtx, cancel := chunkContext(u.ctx)
			ans = u.send(chunkCtx, sess.stored, n)
			if ans.kind == answerTransient && chunkCtx.Err() != nil && u.ctx.Err() == nil {
				ans.cutOff = true
			}
			cancel()
		}
		query = false

		switch ans.kind {
		case answerDone:
			return u.completed(ans)
		case answerIncomplete:
			switch {
			case ans.offset > best:
				best, failures = ans.offset, 0
			case answered:
				// No progress: a stuck or shrinking Range must not keep
				// the call busy.
				failures++
			}
			if !answered && u.resumed {
				a.logger.InfoContext(u.ctx, "resumable upload resumed",
					"backend", a.spec.Backend.Name, "tool", u.toolName, "stored", ans.offset, "size", sess.size)
			}
			answered = true
			sess.stored = ans.offset
		case answerGone:
			if sess.sentLast {
				return u.outcomeUnknown(ans.status, "the API no longer knows the upload session")
			}
			// The last byte never went out: nothing can exist, start over.
			failures++
			sess.uri = nil
			if failures > maxFailures {
				u.drop = true
				return u.apiError(&dadl.APIError{Code: dadl.ErrCodeUploadIncomplete, HTTPStatus: ans.status, Message: "the API kept dropping new upload sessions"}, "")
			}
			if res := u.openSession(retryer); res != nil {
				return res
			}
			best, answered = 0, false
			continue
		case answerUnauthorized:
			failures++
			if err := a.auth.HandleUnauthorizedFor(u.ctx, ans.sent); err != nil {
				return u.incomplete(fmt.Sprintf("renewing the credential failed: %v", err))
			}
			query = true
		case answerAuthFailed:
			if remedy, ok := userCredentialResult(ans.err); ok {
				return remedy
			}
			return u.incomplete(fmt.Sprintf("the credential could not be applied: %v", ans.err))
		case answerTransient:
			query = true
			if ans.cutOff {
				// The chunk ran out of this call's time, not into an error:
				// ask at once how far it got, while the reserve lasts.
				continue
			}
			failures++
			if failures <= maxFailures {
				wait := retryer.Delay(failures)
				if ans.retryAfter > 0 {
					wait = ans.retryAfter
				}
				if !u.sleep(wait) {
					return u.incomplete("too little time was left in this call to wait for the API")
				}
			}
		case answerFailed:
			if !sess.sentLast {
				// Without the last byte the API cannot have created
				// anything: the session can go.
				u.drop = true
				return u.apiError(ans.err, "")
			}
			return u.apiError(ans.err, uploadKeptNote)
		}
		if failures > maxFailures {
			reason := "the transfer failed too often in a row"
			if ans.err != nil {
				reason += fmt.Sprintf(" (last: %v)", ans.err)
			}
			return u.incomplete(reason)
		}
	}
}

// checkSessionHome makes sure a kept session still belongs to the tool as
// it is configured now: after a reload of backends.yaml the backend may
// point elsewhere, and the old session must not get the new credentials.
// It returns a result when the call cannot go on; otherwise the session is
// either kept or, when the last byte had not been sent, forgotten.
func (u *uploadRun) checkSessionHome() *ToolResult {
	reqURL, err := u.sessionRequestURL()
	if err == nil {
		_, err = sessionLocation(reqURL, u.sess.uri.String())
	}
	if err == nil {
		return nil
	}
	if u.sess.sentLast {
		return u.outcomeUnknown(http.StatusConflict, "the tool's address changed since the upload began, so the upload session cannot be asked how far it got")
	}
	u.sess.uri, u.sess.stored = nil, 0
	u.resumed = false
	return nil
}

// settleWithoutFile ends a call whose file is no longer stored while the
// API may already have all of it: one status query tells. Without the file
// the upload cannot go on.
func (u *uploadRun) settleWithoutFile(fileErr error) *ToolResult {
	ans := u.send(u.ctx, -1, 0)
	switch ans.kind {
	case answerDone:
		return u.completed(ans)
	case answerGone:
		return u.outcomeUnknown(ans.status, fmt.Sprintf("the file is no longer stored (%v), and the API no longer knows the upload session", fileErr))
	case answerIncomplete:
		u.sess.stored = ans.offset
		if ans.offset >= u.sess.size {
			// The API has the whole file and is still finishing: keep
			// asking in later calls, never start a second upload.
			return u.incomplete("the API has the whole file but has not answered with the result yet")
		}
		u.drop = true
		return u.apiError(&dadl.APIError{
			Code:       dadl.ErrCodeInvalidInput,
			HTTPStatus: ans.status,
			Message: fmt.Sprintf("the file is no longer stored (%v); the API has %d of %d bytes and the upload cannot go on without the file. "+
				"An unfinished upload creates nothing: store the file again and call with the new handle to start a new upload", fileErr, ans.offset, u.sess.size),
		}, "")
	case answerAuthFailed:
		if remedy, ok := userCredentialResult(ans.err); ok {
			return remedy
		}
	case answerUnauthorized, answerTransient, answerFailed:
		// The answer says nothing about the upload: report it below.
	}
	reason := fmt.Sprintf("HTTP %d", ans.status)
	if ans.err != nil {
		reason = ans.err.Error()
	}
	return u.apiErrorText(fmt.Errorf("the file is no longer stored (%v), and the API could not be asked how far the upload got: %s. "+
		"The upload session is kept; calling again with the same arguments asks again", fileErr, reason))
}

// retryStrategy returns the tool's effective retry strategy, or the
// defaults when it declares none.
func (u *uploadRun) retryStrategy() dadl.RetryStrategyConfig {
	if cfg := u.a.effectiveErrorConfig(u.tool); cfg != nil && cfg.RetryStrategy != nil {
		return *cfg.RetryStrategy
	}
	return dadl.RetryStrategyConfig{}
}

// errorMapper returns the mapper of the tool's error config; without one,
// the defaults of spec §8.2.
func (u *uploadRun) errorMapper() *dadl.ErrorMapper {
	if cfg := u.a.effectiveErrorConfig(u.tool); cfg != nil {
		return dadl.NewErrorMapper(*cfg)
	}
	return dadl.NewErrorMapper(dadl.ErrorConfig{})
}

// openSession sends the session request and stores the session URI. The
// request creates no resource, so it is repeated after a transient failure.
// It returns a result only when the upload cannot start.
func (u *uploadRun) openSession(retryer *dadl.Retryer) *ToolResult {
	a, sess := u.a, u.sess
	mediaType := u.tool.ContentType
	if mediaType == "" {
		mediaType = u.src.contentType
	}
	reauthed := false
	attempt := 0
	for {
		req, err := u.sessionRequest(mediaType)
		if err != nil {
			u.drop = true
			if remedy, ok := userCredentialResult(err); ok {
				return remedy
			}
			return u.apiErrorText(err)
		}
		resp, err := a.uploadHTTPClient.Do(req)
		u.requests++
		var retryAfter time.Duration
		var failure error
		switch {
		case err != nil:
			failure = fmt.Errorf("session request: %w", redactTransportError(err))
		default:
			body, tooLarge := u.readBody(resp, a.responseLimit())
			retryAfter = parseRetryAfter(resp.Header.Get(headerRetryAfter))
			_ = resp.Body.Close()
			if tooLarge != nil {
				u.drop = true
				return u.apiErrorText(tooLarge)
			}
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				sessionURI, err := sessionLocation(req.URL, resp.Header.Get(headerLocation))
				if err != nil {
					u.drop = true
					return u.apiErrorText(err)
				}
				sess.uri, sess.size, sess.mediaType, sess.stored, sess.sentLast = sessionURI, u.src.size, mediaType, 0, false
				sess.secrets = addedQueryValues(req.URL, sessionURI)
				a.logger.InfoContext(u.ctx, "resumable upload session opened",
					"backend", a.spec.Backend.Name, "tool", u.toolName,
					"size", sess.size, "content_type", mediaType,
					"endpoint", loggableEndpoint(sessionURI.String()))
				return nil
			}
			if resp.StatusCode == http.StatusUnauthorized && !reauthed {
				reauthed = true
				if err := a.auth.HandleUnauthorizedFor(u.ctx, sentRequest(resp)); err == nil {
					continue
				}
			}
			apiErr, retryable := u.errorMapper().CheckResponse(resp.StatusCode, body)
			if !retryable && !transientStatus(resp.StatusCode) {
				u.drop = true
				return u.apiError(apiErr, "")
			}
			failure = apiErr
		}
		attempt++
		if attempt > retryer.MaxRetries() {
			u.drop = true
			return u.apiErrorText(fmt.Errorf("opening the upload session failed: %w", failure))
		}
		wait := retryer.Delay(attempt)
		if retryAfter > 0 {
			wait = retryAfter
		}
		if !u.sleep(wait) {
			u.drop = true
			return u.apiErrorText(fmt.Errorf("opening the upload session failed, and too little time is left to try again: %w", failure))
		}
	}
}

// sessionRequestURL returns the URL of the session request: the tool's URL
// with uploadType=resumable.
func (u *uploadRun) sessionRequestURL() (*url.URL, error) {
	urlStr, err := u.a.buildToolURL(u.tool, u.params)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("session request URL: %w", err)
	}
	q := target.Query()
	q.Set(uploadTypeParam, uploadTypeResumable)
	target.RawQuery = q.Encode()
	return target, nil
}

// sessionRequest builds the request that opens the session: the session
// request URL, the tool's headers and auth, the body parameters but the
// file as JSON metadata, and the size and media type of the file.
func (u *uploadRun) sessionRequest(mediaType string) (*http.Request, error) {
	a := u.a
	target, err := u.sessionRequestURL()
	if err != nil {
		return nil, err
	}
	metaParams := make(map[string]any, len(u.params))
	for k, v := range u.params {
		if k != u.fileParam {
			metaParams[k] = v
		}
	}
	var body io.Reader
	contentLen := int64(0)
	contentType := ""
	if meta := a.buildBody(u.tool, metaParams); meta != nil {
		encoded, err := json.Marshal(meta)
		if err != nil {
			return nil, fmt.Errorf("encode upload metadata: %w", err)
		}
		if err := checkBodySize(int64(len(encoded)), maxUploadBytes); err != nil {
			return nil, err
		}
		body, contentLen, contentType = bytes.NewReader(encoded), int64(len(encoded)), contentTypeJSON+"; charset=UTF-8"
	}
	req, err := a.newToolRequest(u.ctx, u.tool, u.params, target.String(), body, contentLen, contentType)
	if err != nil {
		return nil, err
	}
	req.Header.Set(headerUploadContentType, mediaType)
	req.Header.Set(headerUploadContentLength, strconv.FormatInt(u.src.size, 10))
	return req, nil
}

// sessionLocation resolves the Location of the session request's answer
// and checks it: every later request carries the backend's auth to it, so
// it must stay with the scheme, host, port and path of the session request.
// A redirect elsewhere, to another API on the same host among them, is
// refused. Only the query (the upload ID) may differ.
func sessionLocation(requestURL *url.URL, location string) (*url.URL, error) {
	if location == "" {
		return nil, errors.New("the API opened no upload session: its answer has no Location header")
	}
	loc, err := requestURL.Parse(location)
	if err != nil {
		return nil, errors.New("the API answered with a Location header that is not a URL")
	}
	if loc.Scheme != requestURL.Scheme || loc.Host != requestURL.Host || loc.EscapedPath() != requestURL.EscapedPath() || loc.User != nil {
		// Only the origin of the other address: its path can be the
		// session's capability.
		return nil, fmt.Errorf("the API answered with an upload session on %s that is not the address of the session request (%s); refused",
			urlredact.Origin(loc.String()), loggableEndpoint(requestURL.String()))
	}
	loc.Fragment = ""
	return loc, nil
}

// addedQueryValues returns the query values the session URI has beyond the
// session request's: what the API added, the upload ID among them. Values
// shorter than 8 characters are left out; they cannot be a capability and
// would garble texts when redacted.
func addedQueryValues(requestURL, sessionURI *url.URL) []string {
	asked := requestURL.Query()
	var added []string
	for key, values := range sessionURI.Query() {
		for _, v := range values {
			if len(v) >= 8 && !slices.Contains(asked[key], v) {
				added = append(added, v)
			}
		}
	}
	return added
}

// send sends n bytes of the file from offset to the session URI, or, with
// n < 0, asks how much of the file the API has. It classifies the answer.
func (u *uploadRun) send(ctx context.Context, offset, n int64) sessionAnswer {
	a, sess := u.a, u.sess
	var body io.Reader = http.NoBody
	contentLen := int64(0)
	contentRange := fmt.Sprintf("bytes */%d", sess.size)
	if n > 0 {
		body = io.NewSectionReader(u.src.file, offset, n)
		contentLen = n
		contentRange = fmt.Sprintf("bytes %d-%d/%d", offset, offset+n-1, sess.size)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, sess.uri.String(), body)
	if err != nil {
		return sessionAnswer{kind: answerFailed, err: errors.New("cannot build a request to the upload session")}
	}
	req.ContentLength = contentLen
	for k, v := range a.spec.Backend.Defaults.Headers {
		req.Header.Set(k, v)
	}
	if n > 0 {
		req.Header.Set("Content-Type", sess.mediaType)
	}
	req.Header.Set(headerContentRange, contentRange)
	if err := a.auth.InjectAuth(ctx, req); err != nil {
		return sessionAnswer{kind: answerAuthFailed, err: err}
	}

	resp, err := a.uploadHTTPClient.Do(req)
	u.requests++
	if err != nil {
		a.logger.DebugContext(u.ctx, "resumable upload request failed",
			"backend", a.spec.Backend.Name, "tool", u.toolName, "offset", offset, "bytes", n, "error", redactTransportError(err))
		return sessionAnswer{kind: answerTransient, err: redactTransportError(err)}
	}
	defer func() { _ = resp.Body.Close() }()
	a.logger.DebugContext(u.ctx, "resumable upload request",
		"backend", a.spec.Backend.Name, "tool", u.toolName, "offset", offset, "bytes", n, "status", resp.StatusCode)

	ans := sessionAnswer{status: resp.StatusCode, sent: sentRequest(resp)}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// The upload is complete even when its answer cannot be read
		// (err set): it must count as done, or the next call would
		// upload the file again.
		ans.kind = answerDone
		ans.body, ans.err = u.readBody(resp, a.responseLimit())
	case resp.StatusCode == statusResumeIncomplete:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, uploadDrainLimit))
		next, err := parseUploadRange(resp.Header.Get(headerRange), sess.size)
		if err != nil {
			ans.kind, ans.err = answerFailed, err
			return ans
		}
		ans.kind, ans.offset = answerIncomplete, next
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		ans.kind = answerGone
	case resp.StatusCode == http.StatusUnauthorized:
		ans.kind = answerUnauthorized
	default:
		b, _ := u.readBody(resp, uploadDrainLimit)
		apiErr, retryable := u.errorMapper().CheckResponse(resp.StatusCode, b)
		ans.err = apiErr
		if retryable || transientStatus(resp.StatusCode) {
			ans.kind = answerTransient
			ans.retryAfter = parseRetryAfter(resp.Header.Get(headerRetryAfter))
		} else {
			ans.kind = answerFailed
		}
	}
	return ans
}

// readBody reads a response body up to limit. A larger body is an error.
func (u *uploadRun) readBody(resp *http.Response, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", redactTransportError(err))
	}
	if int64(len(b)) > limit {
		return nil, u.a.responseTooLarge(u.ctx, u.tool, resp, int64(len(b)), limit, false)
	}
	return b, nil
}

// transientStatus reports whether a status says the request may succeed
// when sent again: timeouts, rate limits and the server errors Google names
// for resumable uploads.
func transientStatus(status int) bool {
	switch status {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// parseUploadRange returns the offset to continue from after a 308: one past
// the last byte of "Range: bytes=0-N", or 0 without a Range header (the API
// has stored nothing). Anything else, and an N at or past the end of the
// file, is a protocol error: a value the API chose must not make the upload
// read outside the file or skip bytes.
func parseUploadRange(header string, size int64) (int64, error) {
	if header == "" {
		return 0, nil
	}
	rest, ok := strings.CutPrefix(header, "bytes=0-")
	if !ok {
		return 0, errors.New("the API answered with a Range header that does not start at byte 0")
	}
	last, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || last < 0 || last >= size {
		return 0, errors.New("the API answered with a Range header outside the file")
	}
	return last + 1, nil
}

// parseRetryAfter reads a Retry-After header (seconds or an HTTP date),
// capped at uploadMaxRetryAfter. 0 means none.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = time.Until(t)
	}
	if d <= 0 {
		return 0
	}
	return min(d, uploadMaxRetryAfter)
}

// timeLeft reports whether the call has at least need left before its
// deadline. A call without a deadline always has.
func timeLeft(ctx context.Context, need time.Duration) bool {
	deadline, ok := ctx.Deadline()
	return !ok || time.Until(deadline) >= need
}

// chunkContext returns the context of one chunk: it ends
// uploadDeadlineReserve before the call's deadline, so that a status query
// still fits after a chunk that was cut off.
func chunkContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(ctx, deadline.Add(-uploadDeadlineReserve))
	}
	return context.WithCancel(ctx)
}

// sleep waits d unless that would leave less than uploadDeadlineReserve of
// the call, or the call ends first. It reports whether it waited.
func (u *uploadRun) sleep(d time.Duration) bool {
	if !timeLeft(u.ctx, d+uploadDeadlineReserve) {
		return false
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-u.ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// completed records the finished upload and returns its response through
// the response pipeline. A response that could not be read still marks the
// upload finished, so that calling again does not upload the file a second
// time.
func (u *uploadRun) completed(ans sessionAnswer) *ToolResult {
	a := u.a
	u.sess.completed, u.sess.status = true, ans.status
	if ans.err == nil && len(ans.body) <= uploadKeptBodyLimit {
		u.sess.body = ans.body
	}
	a.logger.InfoContext(u.ctx, "resumable upload finished",
		"backend", a.spec.Backend.Name, "tool", u.toolName,
		"size", u.sess.size, "status", ans.status, "requests", u.requests, "resumed", u.resumed)
	if ans.err != nil {
		return u.apiError(ans.err, "The upload itself is complete; calling again does not upload the file a second time.")
	}
	result := a.finishResult(u.ctx, u.toolName, u.tool, ans.status, ans.body)
	return u.withUploadMetadata(result, map[string]any{metadataKeyUploadResumed: u.resumed})
}

// repeatedResult answers a call whose upload finished in an earlier call:
// with the response of that call, so that repeating the call does not
// upload the file a second time.
func (u *uploadRun) repeatedResult() *ToolResult {
	a := u.a
	a.logger.InfoContext(u.ctx, "resumable upload already finished, returning its response",
		"backend", a.spec.Backend.Name, "tool", u.toolName, "status", u.sess.status)
	if u.sess.body == nil {
		return u.apiError(&dadl.APIError{
			Code:       dadl.ErrCodeConflict,
			HTTPStatus: u.sess.status,
			Message:    "this upload finished in an earlier call, and its response could not be kept; it is not uploaded again",
		}, "")
	}
	result := a.finishResult(u.ctx, u.toolName, u.tool, u.sess.status, u.sess.body)
	return u.withUploadMetadata(result, map[string]any{metadataKeyUploadRepeated: true})
}

// incomplete ends a call whose upload stopped before the file was complete.
// The session is kept: the same call again continues it.
func (u *uploadRun) incomplete(reason string) *ToolResult {
	a, sess := u.a, u.sess
	a.logger.WarnContext(u.ctx, "resumable upload stopped incomplete",
		"backend", a.spec.Backend.Name, "tool", u.toolName,
		"stored", sess.stored, "size", sess.size, "requests", u.requests, "reason", u.redact(reason))
	result := u.apiError(&dadl.APIError{
		Code:       dadl.ErrCodeUploadIncomplete,
		HTTPStatus: statusResumeIncomplete,
		Message: fmt.Sprintf("the upload stopped with %d of %d bytes confirmed by the API: %s. "+
			"Call the tool again with the same arguments to continue the upload; it does not start over.", sess.stored, sess.size, reason),
	}, "")
	return u.withUploadMetadata(result, map[string]any{metadataKeyUploadStored: sess.stored, metadataKeyUploadResumed: u.resumed})
}

// outcomeUnknown ends a call that cannot learn whether the API created the
// resource: the whole file was sent, and the session can no longer be
// asked. The session is dropped, so the next call starts a new upload.
func (u *uploadRun) outcomeUnknown(status int, reason string) *ToolResult {
	u.drop = true
	u.a.logger.WarnContext(u.ctx, "resumable upload outcome unknown",
		"backend", u.a.spec.Backend.Name, "tool", u.toolName, "stored", u.sess.stored, "size", u.sess.size, "reason", u.redact(reason))
	return u.apiError(&dadl.APIError{
		Code:       dadl.ErrCodeUploadOutcomeUnknown,
		HTTPStatus: status,
		Message: reason + " after the whole file was sent, so the API may or may not have created the resource; " +
			"check before calling again, because the next call starts a new upload",
	}, "")
}

// redact removes the session's capability from a text: the queries of the
// URLs in it, and the values the API added to the session URI wherever
// they stand, since an API may echo them without a URL around them.
func (u *uploadRun) redact(text string) string {
	for _, secret := range u.sess.secrets {
		text = strings.ReplaceAll(text, secret, dadl.RedactedPlaceholder)
	}
	return urlredact.Text(text)
}

// apiError returns err as the call's error result, with note appended to
// its message. Messages can come from the API, which may echo the request
// URL, so they are redacted.
func (u *uploadRun) apiError(err error, note string) *ToolResult {
	var apiErr *dadl.APIError
	if errors.As(err, &apiErr) {
		c := *apiErr
		c.Message = u.redact(c.Message)
		c.ProviderCode = u.redact(c.ProviderCode)
		if note != "" {
			c.Message += ". " + note
		}
		return u.withUploadMetadata(u.a.apiErrorResult(&c), nil)
	}
	text := ""
	if err != nil {
		text = err.Error()
	}
	if note != "" {
		text += ". " + note
	}
	return u.apiErrorText(errors.New(text))
}

// apiErrorText returns an error that is not an API error as the call's
// error result.
func (u *uploadRun) apiErrorText(err error) *ToolResult {
	return u.withUploadMetadata(&ToolResult{
		Content: []any{textContent("Error: " + u.redact(err.Error()))},
		IsError: true,
	}, nil)
}

// withUploadMetadata adds the upload's metadata to a result.
func (u *uploadRun) withUploadMetadata(result *ToolResult, extra map[string]any) *ToolResult {
	if result.Metadata == nil {
		result.Metadata = map[string]any{}
	}
	if u.sess.size > 0 {
		result.Metadata[metadataKeyUploadSize] = u.sess.size
	} else if u.src != nil {
		result.Metadata[metadataKeyUploadSize] = u.src.size
	}
	for k, v := range extra {
		result.Metadata[k] = v
	}
	return result
}
