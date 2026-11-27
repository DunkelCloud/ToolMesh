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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testURLOwner = "uploader"
	testURLType  = "video/mp4"
	testURLBase  = "http://localhost:8080"

	testMsgInvalidType = "invalid content type"
)

// testURLLimits are the limits the upload URL tests run with.
func testURLLimits() UploadLimits {
	return UploadLimits{MaxBytes: 64, DefaultTTL: time.Hour, MaxTTL: 24 * time.Hour}
}

// newTestURL creates an upload URL and returns it with the path to send
// requests to.
func newTestURL(t *testing.T, s *Store, req UploadURLRequest) (*UploadURL, string) {
	t.Helper()
	u, err := s.NewUploadURL(req, testURLLimits())
	if err != nil {
		t.Fatalf("NewUploadURL: %v", err)
	}
	path, ok := strings.CutPrefix(u.URL, testURLBase)
	if !ok || !strings.HasPrefix(path, UploadURLPathPrefix) {
		t.Fatalf("URL = %q, want it under %s%s", u.URL, testURLBase, UploadURLPathPrefix)
	}
	return u, path
}

// sendToURL sends one request to an upload URL and decodes the answer.
// contentRange and contentType are left out when empty; a body of unknown
// length is sent when unknownLength is set.
func sendToURL(t *testing.T, s *Store, method, path string, body []byte, contentRange, contentType string, unknownLength bool) (int, uploadURLAnswer) {
	t.Helper()
	var r io.Reader = bytes.NewReader(body)
	if body == nil {
		r = http.NoBody
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, r)
	if unknownLength {
		req.ContentLength = -1
	}
	if contentRange != "" {
		req.Header.Set("Content-Range", contentRange)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	s.HandleUploadURL(rec, req, testURLLimits())
	var a uploadURLAnswer
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
			t.Fatalf("answer is not JSON: %q", rec.Body.String())
		}
		// No answer names the blob: its ID is the credential for reading it.
		var fields map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &fields)
		for _, k := range []string{"handle", "file_id", "url"} {
			if _, ok := fields[k]; ok {
				t.Errorf("answer names the blob (%s): %s", k, rec.Body.String())
			}
		}
	}
	return rec.Code, a
}

// put sends a PUT with a known body length.
func put(t *testing.T, s *Store, path string, body []byte, contentRange string) (int, uploadURLAnswer) {
	t.Helper()
	return sendToURL(t, s, http.MethodPut, path, body, contentRange, "", false)
}

// blobContent reads the blob with the given ID.
func blobContent(t *testing.T, s *Store, id string) ([]byte, *BlobInfo) {
	t.Helper()
	rc, info, err := s.Open(id)
	if err != nil {
		t.Fatalf("Open(%s): %v", id, err)
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	return data, info
}

func TestUploadURL_WholeFile(t *testing.T) {
	s := newTestStore(t)
	file := []byte("a whole file in one request")
	u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner, Filename: "clip.mp4", ContentType: testURLType, TTL: 2 * time.Hour})

	code, a := put(t, s, path, file, "")
	if code != http.StatusCreated {
		t.Fatalf("PUT = %d (%+v), want 201", code, a)
	}
	if !a.Complete || a.Received != int64(len(file)) || a.Size != int64(len(file)) {
		t.Errorf("answer = %+v, want complete with %d bytes", a, len(file))
	}
	if a.ContentType != testURLType || a.Expires == nil || a.UploadURLExpires != nil {
		t.Errorf("answer = %+v, want the type and the blob's expiry", a)
	}
	data, info := blobContent(t, s, u.BlobID)
	if !bytes.Equal(data, file) || info.Filename != "clip.mp4" || info.ContentType != testURLType {
		t.Errorf("blob = %q %+v, want the file with its name and type", data, info)
	}
	if d := time.Until(info.ExpiresAt); d < 119*time.Minute || d > 2*time.Hour {
		t.Errorf("blob expires in %v, want the TTL of 2h", d)
	}
	assertUsage(t, s, testURLOwner, int64(len(file)), int64(len(file)))
	if _, err := os.Stat(filepath.Join(s.dir, u.BlobID+partSuffix)); !os.IsNotExist(err) {
		t.Errorf("part file still there: %v", err)
	}

	// The same PUT again, as after a lost answer: the same blob, nothing new.
	code, again := put(t, s, path, file, "")
	if code != http.StatusOK || !again.Complete || again.Received != int64(len(file)) {
		t.Errorf("repeated PUT = %d %+v, want 200 with the complete file", code, again)
	}
	assertUsage(t, s, testURLOwner, int64(len(file)), int64(len(file)))
	if n := filesOnDisk(t, s); n != 1 {
		t.Errorf("%d files on disk, want 1", n)
	}
	code, state := sendToURL(t, s, http.MethodGet, path, nil, "", "", false)
	if code != http.StatusOK || !state.Complete {
		t.Errorf("GET = %d %+v, want the complete state", code, state)
	}
}

func TestUploadURL_Parts(t *testing.T) {
	s := newTestStore(t)
	file := []byte("0123456789")
	u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})

	code, a := sendToURL(t, s, http.MethodPut, path, file[0:4], "bytes 0-3/10", "image/png", false)
	if code != http.StatusAccepted || a.Received != 4 || a.Complete || a.Size != 10 || a.UploadURLExpires == nil {
		t.Fatalf("part 1 = %d %+v, want 202 with 4 of 10 bytes", code, a)
	}
	code, a = sendToURL(t, s, http.MethodGet, path, nil, "", "", false)
	if code != http.StatusOK || a.Received != 4 {
		t.Errorf("GET = %d %+v, want 4 bytes stored", code, a)
	}
	// The first part again, as after a lost answer: refused with the count.
	code, a = put(t, s, path, file[0:4], "bytes 0-3/10")
	if code != http.StatusConflict || a.Received != 4 || a.Error == "" {
		t.Errorf("part 1 again = %d %+v, want 409 with 4 bytes stored", code, a)
	}
	// A part that skips ahead: refused with the count.
	code, a = put(t, s, path, file[8:10], "bytes 8-9/10")
	if code != http.StatusConflict || a.Received != 4 {
		t.Errorf("part 3 first = %d %+v, want 409 with 4 bytes stored", code, a)
	}
	if code, a = put(t, s, path, file[4:8], "bytes 4-7/10"); code != http.StatusAccepted || a.Received != 8 {
		t.Fatalf("part 2 = %d %+v, want 202 with 8 bytes", code, a)
	}
	code, a = put(t, s, path, file[8:10], "bytes 8-9/10")
	if code != http.StatusCreated || !a.Complete || a.Size != 10 || a.ContentType != "image/png" {
		t.Fatalf("part 3 = %d %+v, want 201 with the complete file of the first part's type", code, a)
	}
	data, _ := blobContent(t, s, u.BlobID)
	if !bytes.Equal(data, file) {
		t.Errorf("blob = %q, want %q", data, file)
	}
	// The last part again after completion: the same answer.
	if code, a = put(t, s, path, file[8:10], "bytes 8-9/10"); code != http.StatusOK || !a.Complete {
		t.Errorf("last part again = %d %+v, want 200 complete", code, a)
	}
	assertUsage(t, s, testURLOwner, 10, 10)
}

// A refused request stores nothing of its body, counts nothing in the quota,
// and the upload goes on as before.
func TestUploadURL_RefusedBodyLeavesNothing(t *testing.T) {
	s := newTestStore(t)
	file := []byte("0123456789")
	u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner, ContentType: testURLType})
	if code, _ := put(t, s, path, file[0:4], "bytes 0-3/10"); code != http.StatusAccepted {
		t.Fatalf("part 1 = %d, want 202", code)
	}

	for _, tt := range []struct {
		name string
		body []byte
	}{
		{name: "shorter than announced", body: file[4:6]},
		{name: "longer than announced", body: file[4:10]},
	} {
		t.Run(tt.name, func(t *testing.T) {
			code, a := sendToURL(t, s, http.MethodPut, path, tt.body, "bytes 4-7/10", "", true)
			if code != http.StatusBadRequest || a.Received != 4 {
				t.Errorf("PUT = %d %+v, want 400 with 4 bytes stored", code, a)
			}
			assertUsage(t, s, testURLOwner, 4, 4)
			info, err := os.Stat(filepath.Join(s.dir, u.BlobID+partSuffix))
			if err != nil || info.Size() != 4 {
				t.Errorf("part file = %v %v, want 4 bytes", info, err)
			}
		})
	}
	if code, _ := put(t, s, path, file[4:10], "bytes 4-9/10"); code != http.StatusCreated {
		t.Errorf("rest = %d, want 201", code)
	}

	// A first request that fails leaves neither a file nor a size behind.
	_, path2 := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	if code, _ := sendToURL(t, s, http.MethodPut, path2, file[:3], "bytes 0-4/5", "text/plain", true); code != http.StatusBadRequest {
		t.Errorf("short first part = %d, want 400", code)
	}
	if code, a := put(t, s, path2, file, ""); code != http.StatusCreated || a.Size != 10 || a.ContentType != defaultContentType {
		t.Errorf("whole file after = %d %+v, want 201 of 10 bytes without the refused request's type", code, a)
	}
}

// A whole file of unknown length that turns out empty is refused like one
// announced as empty, and the URL stays usable.
func TestUploadURL_EmptyBodyOfUnknownLength(t *testing.T) {
	s := newTestStore(t)
	u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	code, a := sendToURL(t, s, http.MethodPut, path, []byte{}, "", "", true)
	if code != http.StatusBadRequest || a.Complete || !strings.Contains(a.Error, "empty") {
		t.Errorf("empty PUT = %d %+v, want 400", code, a)
	}
	if _, err := s.Stat(u.BlobID); err == nil {
		t.Error("an empty blob was stored")
	}
	if code, _ := put(t, s, path, []byte("now with content"), ""); code != http.StatusCreated {
		t.Errorf("PUT after = %d, want 201", code)
	}
}

// A part file that lost the bytes stored before is not padded: the upload
// starts again, and the lost bytes leave the quota.
func TestUploadURL_LostPartFile(t *testing.T) {
	for _, tt := range []struct {
		name string
		lose func(path string) error
	}{
		{"removed", os.Remove},
		{"shortened", func(path string) error { return os.Truncate(path, 2) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestStore(t)
			u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
			if code, _ := put(t, s, path, []byte("0123"), "bytes 0-3/10"); code != http.StatusAccepted {
				t.Fatalf("part 1 = %d, want 202", code)
			}
			if err := tt.lose(filepath.Join(s.dir, u.BlobID+partSuffix)); err != nil {
				t.Fatalf("lose the part file: %v", err)
			}
			code, a := put(t, s, path, []byte("4567"), "bytes 4-7/10")
			if code != http.StatusInternalServerError || a.Received != 0 || !strings.Contains(a.Error, "from the start") {
				t.Errorf("part 2 = %d %+v, want 500 with nothing stored", code, a)
			}
			assertUsage(t, s, testURLOwner, 0, 0)
			if code, a := put(t, s, path, []byte("0123456789"), ""); code != http.StatusCreated || a.Size != 10 {
				t.Errorf("whole file after = %d %+v, want 201", code, a)
			}
			data, _ := blobContent(t, s, u.BlobID)
			if string(data) != "0123456789" {
				t.Errorf("blob = %q", data)
			}
		})
	}
}

// bodyThatFails gives three bytes, then fails or panics.
type bodyThatFails struct {
	sent  bool
	panic bool
}

func (b *bodyThatFails) Read(p []byte) (int, error) {
	if !b.sent {
		b.sent = true
		return copy(p, "abc"), nil
	}
	if b.panic {
		panic("reading the body broke")
	}
	return 0, errors.New("connection reset")
}

// A body that breaks off is the client's fault (400) and leaves nothing; a
// panic while writing leaves the URL usable and the quota as before.
func TestUploadURL_BrokenBody(t *testing.T) {
	for _, panics := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic=%v", panics), func(t *testing.T) {
			s := newTestStore(t)
			u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
			if code, _ := put(t, s, path, []byte("0123"), "bytes 0-3/10"); code != http.StatusAccepted {
				t.Fatalf("part 1 = %d, want 202", code)
			}
			rec := httptest.NewRecorder()
			func() {
				defer func() {
					if p := recover(); (p != nil) != panics {
						t.Errorf("recovered %v, want a panic: %v", p, panics)
					}
				}()
				req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, path, io.NopCloser(&bodyThatFails{panic: panics}))
				req.ContentLength = 6
				req.Header.Set("Content-Range", "bytes 4-9/10")
				s.HandleUploadURL(rec, req, testURLLimits())
			}()
			if !panics && rec.Code != http.StatusBadRequest {
				t.Errorf("broken body = %d %s, want 400", rec.Code, rec.Body.String())
			}
			assertUsage(t, s, testURLOwner, 4, 4)
			if info, err := os.Stat(filepath.Join(s.dir, u.BlobID+partSuffix)); err != nil || info.Size() != 4 {
				t.Errorf("part file = %v %v, want 4 bytes", info, err)
			}
			if code, a := put(t, s, path, []byte("456789"), "bytes 4-9/10"); code != http.StatusCreated {
				t.Errorf("part 2 after = %d %+v, want 201", code, a)
			}
			data, _ := blobContent(t, s, u.BlobID)
			if string(data) != "0123456789" {
				t.Errorf("blob = %q", data)
			}
		})
	}
}

func TestUploadURL_Refusals(t *testing.T) {
	s := newTestStore(t)
	_, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	_, sized := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner, Size: 10})
	_, started := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	if code, _ := put(t, s, started, []byte("0123"), "bytes 0-3/10"); code != http.StatusAccepted {
		t.Fatalf("first part = %d, want 202", code)
	}

	tests := []struct {
		name         string
		method, path string
		body         []byte
		contentRange string
		contentType  string
		want         int
	}{
		{"unknown token", http.MethodPut, UploadURLPathPrefix + "nope", []byte("x"), "", "", http.StatusNotFound},
		{"no token", http.MethodGet, UploadURLPathPrefix, nil, "", "", http.StatusNotFound},
		{"token with a slash", http.MethodGet, path + "/x", nil, "", "", http.StatusNotFound},
		{"POST", http.MethodPost, path, []byte("x"), "", "", http.StatusMethodNotAllowed},
		{"DELETE", http.MethodDelete, path, nil, "", "", http.StatusMethodNotAllowed},
		{"status query form", http.MethodPut, path, nil, "bytes */10", "", http.StatusBadRequest},
		{"other unit", http.MethodPut, path, []byte("ab"), "items 0-1/2", "", http.StatusBadRequest},
		{"last before first", http.MethodPut, path, []byte("ab"), "bytes 5-3/10", "", http.StatusBadRequest},
		{"range past the end", http.MethodPut, path, []byte("ab"), "bytes 0-10/10", "", http.StatusBadRequest},
		{"total not a number", http.MethodPut, path, []byte("ab"), "bytes 0-1/x", "", http.StatusBadRequest},
		{"signed number", http.MethodPut, path, []byte("ab"), "bytes +0-1/2", "", http.StatusBadRequest},
		{"empty file", http.MethodPut, path, []byte{}, "", "", http.StatusBadRequest},
		{"too large", http.MethodPut, path, make([]byte, 65), "", "", http.StatusRequestEntityTooLarge},
		{"too large in parts", http.MethodPut, path, []byte("ab"), "bytes 0-1/65", "", http.StatusRequestEntityTooLarge},
		{"invalid content type", http.MethodPut, path, []byte("ab"), "", "not a type;;", http.StatusBadRequest},
		{"other size than created for", http.MethodPut, sized, []byte("abc"), "", "", http.StatusBadRequest},
		{"other total than before", http.MethodPut, started, []byte("4567"), "bytes 4-7/11", "", http.StatusBadRequest},
		{"whole file after a part", http.MethodPut, started, []byte("0123456789"), "", "", http.StatusConflict},
		{"announced length differs from body", http.MethodPut, started, []byte("45"), "bytes 4-7/10", "", http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, a := sendToURL(t, s, tt.method, tt.path, tt.body, tt.contentRange, tt.contentType, false)
			if code != tt.want {
				t.Errorf("%s = %d (%+v), want %d", tt.method, code, a, tt.want)
			}
			if a.Error == "" {
				t.Errorf("answer %+v has no error text", a)
			}
		})
	}
	assertUsage(t, s, testURLOwner, 4, 4)
	if code, a := put(t, s, path, []byte("still fine"), ""); code != http.StatusCreated {
		t.Errorf("PUT after the refusals = %d %+v, want 201", code, a)
	}
}

func TestNewUploadURL_Refusals(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxBytesPerUser: 20})
	for _, tt := range []struct {
		name string
		req  UploadURLRequest
		want string
	}{
		{"negative size", UploadURLRequest{Size: -1}, "invalid size"},
		{"over the size limit", UploadURLRequest{Size: 65}, "exceeding the 64 byte limit"},
		{testMsgInvalidType, UploadURLRequest{ContentType: "a;;b"}, testMsgInvalidType},
		{"over the quota", UploadURLRequest{Owner: testURLOwner, Size: 21}, ErrQuotaExceeded.Error()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := s.NewUploadURL(tt.req, testURLLimits()); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("NewUploadURL = %v, want an error with %q", err, tt.want)
			}
		})
	}
}

func TestUploadURL_Quota(t *testing.T) {
	s := newTestStore(t)
	s.SetQuota(Quota{MaxBytesPerUser: 10})

	// A whole file of unknown length stops at the quota, nothing stays.
	_, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	code, a := sendToURL(t, s, http.MethodPut, path, make([]byte, 20), "", "", true)
	if code != http.StatusInsufficientStorage || a.Received != 0 {
		t.Errorf("PUT = %d %+v, want 507 with nothing stored", code, a)
	}
	assertUsage(t, s, testURLOwner, 0, 0)
	if n := filesOnDisk(t, s); n != 0 {
		t.Errorf("%d files on disk, want 0", n)
	}

	// In parts, the part that does not fit is refused before it is read.
	_, path = newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	if code, _ := put(t, s, path, make([]byte, 8), "bytes 0-7/16"); code != http.StatusAccepted {
		t.Fatalf("part 1 = %d, want 202", code)
	}
	if code, a := put(t, s, path, make([]byte, 8), "bytes 8-15/16"); code != http.StatusInsufficientStorage || a.Received != 8 {
		t.Errorf("part 2 = %d %+v, want 507 with 8 bytes stored", code, a)
	}
	assertUsage(t, s, testURLOwner, 8, 8)
}

// While one request writes, a second one to the same URL is refused.
func TestUploadURL_OneRequestAtATime(t *testing.T) {
	s := newTestStore(t)
	_, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})

	pr, pw := io.Pipe()
	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPut, path, pr)
		req.ContentLength = 10
		rec := httptest.NewRecorder()
		s.HandleUploadURL(rec, req, testURLLimits())
		done <- rec.Code
	}()
	if _, err := pw.Write([]byte("01234")); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The first request is writing once its first bytes were taken.
	if code, a := put(t, s, path, []byte("0123456789"), ""); code != http.StatusConflict || !strings.Contains(a.Error, "another request") {
		t.Errorf("second PUT = %d %+v, want 409", code, a)
	}
	if _, err := pw.Write([]byte("56789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = pw.Close()
	if code := <-done; code != http.StatusCreated {
		t.Errorf("first PUT = %d, want 201", code)
	}
}

func TestUploadURL_Expiry(t *testing.T) {
	s := newTestStore(t)
	u, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	if code, _ := put(t, s, path, []byte("0123"), "bytes 0-3/10"); code != http.StatusAccepted {
		t.Fatalf("part 1 = %d, want 202", code)
	}
	done, donePath := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	if code, _ := put(t, s, donePath, []byte("abc"), ""); code != http.StatusCreated {
		t.Fatalf("whole file = %d, want 201", code)
	}
	assertUsage(t, s, testURLOwner, 7, 7)

	s.ticketMu.Lock()
	for _, tk := range s.tickets {
		tk.expires = time.Now().Add(-time.Second)
	}
	s.ticketMu.Unlock()
	if code, _ := put(t, s, path, []byte("4567"), "bytes 4-7/10"); code != http.StatusNotFound {
		t.Errorf("PUT after expiry = %d, want 404", code)
	}
	if code, _ := sendToURL(t, s, http.MethodGet, donePath, nil, "", "", false); code != http.StatusNotFound {
		t.Errorf("GET after expiry = %d, want 404", code)
	}

	s.removeExpiredUploadURLs(time.Now())
	if _, err := os.Stat(filepath.Join(s.dir, u.BlobID+partSuffix)); !os.IsNotExist(err) {
		t.Errorf("part file of the expired URL is still there: %v", err)
	}
	// The incomplete file leaves the quota, the complete one stays a blob.
	assertUsage(t, s, testURLOwner, 3, 3)
	if _, err := s.Stat(done.BlobID); err != nil {
		t.Errorf("blob of the complete upload: %v", err)
	}
	s.ticketMu.Lock()
	left := len(s.tickets)
	s.ticketMu.Unlock()
	if left != 0 {
		t.Errorf("%d upload URLs left, want 0", left)
	}
}

func TestNewUploadURL_LimitsPerOwner(t *testing.T) {
	s := newTestStore(t)
	paths := make([]string, 0, maxUploadURLsPerOwner)
	for range maxUploadURLsPerOwner {
		_, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
		paths = append(paths, path)
	}
	if _, err := s.NewUploadURL(UploadURLRequest{Owner: testURLOwner}, testURLLimits()); !errors.Is(err, ErrTooManyUploadURLs) {
		t.Errorf("URL %d = %v, want ErrTooManyUploadURLs", maxUploadURLsPerOwner+1, err)
	}
	if _, err := s.NewUploadURL(UploadURLRequest{Owner: "someone-else"}, testURLLimits()); err != nil {
		t.Errorf("URL of another owner: %v", err)
	}
	// A complete upload no longer counts.
	if code, _ := put(t, s, paths[0], []byte("x"), ""); code != http.StatusCreated {
		t.Fatalf("PUT = %d, want 201", code)
	}
	if _, err := s.NewUploadURL(UploadURLRequest{Owner: testURLOwner}, testURLLimits()); err != nil {
		t.Errorf("URL after one completed: %v", err)
	}
}

func TestNewUploadURL_TokenAndTTL(t *testing.T) {
	s := newTestStore(t)
	u, path := newTestURL(t, s, UploadURLRequest{TTL: 48 * time.Hour})
	token := strings.TrimPrefix(path, UploadURLPathPrefix)
	if len(token) != 43 || strings.ContainsAny(token, "/+=") {
		t.Errorf("token %q, want 43 characters of base64url", token)
	}
	s.ticketMu.Lock()
	_, keptAsIs := s.tickets[token]
	tk := s.tickets[tokenKey(token)]
	s.ticketMu.Unlock()
	if keptAsIs || tk == nil {
		t.Fatalf("ticket kept under the token itself (%v) or not under its hash (%v)", keptAsIs, tk)
	}
	if tk.ttl != 24*time.Hour {
		t.Errorf("TTL = %v, want the 24h maximum", tk.ttl)
	}
	if d := time.Until(u.ExpiresAt); d > uploadURLLifetime || d < uploadURLLifetime-time.Minute {
		t.Errorf("URL expires in %v, want %v", d, uploadURLLifetime)
	}
	if u.MaxBytes != testURLLimits().MaxBytes {
		t.Errorf("MaxBytes = %d, want the limit", u.MaxBytes)
	}
}

// A request to a valid upload URL may take longer than the HTTP server's
// read timeout; one to an unknown URL may not.
func TestUploadURL_SlowBodyOutlastsServerTimeout(t *testing.T) {
	s := newTestStore(t)
	_, path := newTestURL(t, s, UploadURLRequest{Owner: testURLOwner})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.HandleUploadURL(w, r, testURLLimits())
	}))
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("01234"))
		time.Sleep(700 * time.Millisecond)
		_, _ = pw.Write([]byte("56789"))
		_ = pw.Close()
	}()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, srv.URL+path, pr)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.ContentLength = 10
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("slow PUT = %d, want 201", resp.StatusCode)
	}
}

func TestParseContentRange(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want putRange
		ok   bool
	}{
		{"bytes 0-0/1", putRange{ranged: true, first: 0, last: 0, total: 1}, true},
		{"bytes 4-7/10", putRange{ranged: true, first: 4, last: 7, total: 10}, true},
		{"bytes 0-9/10", putRange{ranged: true, first: 0, last: 9, total: 10}, true},
		{"bytes */10", putRange{}, false},
		{"bytes 0-9/*", putRange{}, false},
		{"bytes 0-9", putRange{}, false},
		{"bytes -1-9/10", putRange{}, false},
		{"bytes 0-9/10 ", putRange{}, false},
		{"bytes  0-9/10", putRange{}, false},
		{"bytes 9223372036854775808-9/10", putRange{}, false},
		{"Bytes 0-9/10", putRange{}, false},
	} {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parseContentRange(tt.in)
			if (err == nil) != tt.ok || (tt.ok && got != tt.want) {
				t.Errorf("parseContentRange(%q) = %+v, %v; want %+v, ok %v", tt.in, got, err, tt.want, tt.ok)
			}
		})
	}
}

func TestNewStore_RemovesLeftoverPartFiles(t *testing.T) {
	dir := t.TempDir()
	part := filepath.Join(dir, fmt.Sprintf("%032x%s", 7, partSuffix))
	if err := os.WriteFile(part, []byte("left over"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := NewStore(dir, testURLBase, newTestStore(t).logger); err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := os.Stat(part); !os.IsNotExist(err) {
		t.Errorf("part file of an earlier run is still there: %v", err)
	}
}
