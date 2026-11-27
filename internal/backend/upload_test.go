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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Fixtures of the upload tests.
const (
	upTool        = "upload_video"
	upPath        = "/upload/videos"
	upSecret      = "SeSsIoNsEcReT" // part of every upload_id: must never show up in a log or result
	upToken       = "upload-test-token"
	upTitle       = "A title"
	upParamTitle  = "snippet.title"
	upParamFile   = "file"
	upVideoID     = "VIDEO0001"
	upContentType = "video/mp4"
	upChunk       = 256 << 10 // smallest chunk Google takes
	upKindQuery   = "query"
	upKindChunk   = "chunk"
)

// uploadDADL is the fixture DADL: one upload tool with nested metadata, as
// youtube.dadl declares it. %s is the base URL.
const uploadDADL = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
requires:
  features: [resumable_upload]
backend:
  name: tube
  type: rest
  base_url: %s
  auth:
    type: bearer
    credential: tube_token
    inject_into: header
    header_name: Authorization
    prefix: "Bearer "
  defaults:
    errors:
      format: json
      message_path: "$.error.message"
      retry_on: [500, 502, 503, 504]
      retry_strategy:
        max_retries: 3
        backoff: fixed
        initial_delay: 1ms
  tools:
    upload_video:
      method: POST
      path: /upload/videos
      access: write
      upload:
        protocol: google_resumable
      nest_body_keys: true
      params:
        part:
          type: string
          in: query
          default: "snippet,status"
        snippet.title:
          type: string
          in: body
          required: true
        status.privacyStatus:
          type: string
          in: body
          default: private
        file:
          type: file_url
          in: body
          required: true
      response:
        result_path: "$"
`

// fakeSession is one upload session of fakeUploadServer.
type fakeSession struct {
	size int64
	data []byte
	done bool
}

// fakeUploadServer imitates Google's resumable upload protocol. hook, when
// set, sees every session request first (kind upKindQuery or upKindChunk,
// n counting the requests of that kind from 1) and may answer it itself by
// returning true.
type fakeUploadServer struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	sessions    map[string]*fakeSession
	initiations int
	queries     int
	chunks      int
	metadata    map[string]any
	initHeaders http.Header
	location    func(id string) string // overrides the Location of a new session
	hook        func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool
}

func newFakeUploadServer(t *testing.T) *fakeUploadServer {
	t.Helper()
	f := &fakeUploadServer{t: t, sessions: map[string]*fakeSession{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeUploadServer) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(testHeaderAuth) != "Bearer "+upToken {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		f.open(w, r)
	case http.MethodPut:
		f.put(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeUploadServer) open(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.URL.Query().Get(uploadTypeParam) != uploadTypeResumable || r.URL.Path != upPath {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	size, err := strconv.ParseInt(r.Header.Get(headerUploadContentLength), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.initiations++
	f.initHeaders = r.Header.Clone()
	f.metadata = nil
	_ = json.NewDecoder(r.Body).Decode(&f.metadata)
	id := fmt.Sprintf("%s%d", upSecret, f.initiations)
	f.sessions[id] = &fakeSession{size: size}
	loc := f.srv.URL + upPath + "?uploadType=resumable&part=snippet,status&upload_id=" + id
	if f.location != nil {
		loc = f.location(id)
	}
	w.Header().Set(headerLocation, loc)
	w.WriteHeader(http.StatusOK)
}

func (f *fakeUploadServer) put(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	s := f.sessions[r.URL.Query().Get("upload_id")]
	cr := r.Header.Get(headerContentRange)
	kind := upKindChunk
	if strings.HasPrefix(cr, "bytes */") {
		kind = upKindQuery
		f.queries++
	} else {
		f.chunks++
	}
	n := f.chunks
	if kind == upKindQuery {
		n = f.queries
	}
	hook := f.hook
	f.mu.Unlock()

	if s == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if hook != nil && hook(kind, n, s, w, r) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if kind == upKindChunk {
		var start, end, total int64
		if _, err := fmt.Sscanf(cr, "bytes %d-%d/%d", &start, &end, &total); err != nil || total != s.size {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if start == int64(len(s.data)) && int64(len(body)) == end-start+1 {
			s.data = append(s.data, body...)
		}
		if int64(len(s.data)) == s.size {
			s.done = true
		}
	}
	f.answer(w, s)
}

// answer writes the protocol's answer for the state of s.
func (f *fakeUploadServer) answer(w http.ResponseWriter, s *fakeSession) {
	if s.done {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + upVideoID + `","status":{"uploadStatus":"uploaded"}}`))
		return
	}
	if len(s.data) > 0 {
		w.Header().Set(headerRange, fmt.Sprintf("bytes=0-%d", len(s.data)-1))
	}
	w.WriteHeader(statusResumeIncomplete)
}

// store appends the chunk to s and answers like the protocol, or closes the
// connection instead when drop, given whether the upload is now complete,
// says so.
func (f *fakeUploadServer) store(s *fakeSession, w http.ResponseWriter, r *http.Request, drop func(done bool) bool) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	s.data = append(s.data, body...)
	s.done = int64(len(s.data)) == s.size
	done := s.done
	f.mu.Unlock()
	if drop(done) {
		dropConnection(w)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer(w, s)
}

// setHook replaces the hook while requests may be running.
func (f *fakeUploadServer) setHook(hook func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = hook
}

// initiation returns the metadata and headers of the last session request.
func (f *fakeUploadServer) initiation() (map[string]any, http.Header) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.metadata, f.initHeaders
}

// counts returns the numbers of session requests, status queries and chunks.
func (f *fakeUploadServer) counts() (initiations, queries, chunks int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.initiations, f.queries, f.chunks
}

// received returns what the server stored for the only session.
func (f *fakeUploadServer) received() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.done {
			return s.data
		}
	}
	return nil
}

// dropConnection closes the connection without an answer, as a broken
// network does.
func dropConnection(w http.ResponseWriter) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

// lockedBuffer is a log sink the test reads while the adapter writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// uploadFixture is an adapter on a fakeUploadServer with a blob store, and
// the log it writes.
type uploadFixture struct {
	srv   *fakeUploadServer
	a     *RESTAdapter
	store *blob.Store
	log   *lockedBuffer
	creds *switchableCredStore
}

// newUploadFixture shrinks chunks and time windows for the test and gives
// it a session store of its own.
func newUploadFixture(t *testing.T) *uploadFixture {
	t.Helper()
	chunk, reserve, window, sessions := uploadChunkSize, uploadDeadlineReserve, uploadMinChunkWindow, uploadSessions
	uploadChunkSize, uploadDeadlineReserve, uploadMinChunkWindow = upChunk, 50*time.Millisecond, 100*time.Millisecond
	uploadSessions = newUploadSessionStore(maxUploadSessions)
	t.Cleanup(func() {
		uploadChunkSize, uploadDeadlineReserve, uploadMinChunkWindow, uploadSessions = chunk, reserve, window, sessions
	})

	srv := newFakeUploadServer(t)
	log := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	store, err := blob.NewStore(t.TempDir(), "http://broker.local", logger)
	if err != nil {
		t.Fatal(err)
	}
	fx := &uploadFixture{srv: srv, store: store, log: log, creds: &switchableCredStore{}}
	fx.a = fx.adapterFor(t, srv.srv.URL)
	return fx
}

// adapterFor builds an adapter of the fixture DADL on baseURL that shares
// the fixture's blob store, credentials and log, as a reload of
// backends.yaml would build it anew.
func (fx *uploadFixture) adapterFor(t *testing.T, baseURL string) *RESTAdapter {
	t.Helper()
	spec, err := dadl.ParseBytes([]byte(fmt.Sprintf(uploadDADL, baseURL)))
	if err != nil {
		t.Fatalf("parse fixture DADL: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(fx.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := NewRESTAdapter(spec, fx.creds, logger, testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	a.SetBlobStore(fx.store)
	return a
}

// switchableCredStore hands out the upload token until a test makes it
// fail, as a credential store that becomes unreachable does.
type switchableCredStore struct {
	fail atomic.Bool
}

func (s *switchableCredStore) Get(context.Context, string, credentials.TenantInfo) (string, error) {
	if s.fail.Load() {
		return "", errors.New("credential store unreachable")
	}
	return upToken, nil
}

func (s *switchableCredStore) Healthy(context.Context) error { return nil }

// file stores size bytes of a recognizable pattern and returns the handle
// and the bytes.
func (fx *uploadFixture) file(t *testing.T, size int) (string, []byte) {
	t.Helper()
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + i/251)
	}
	id, _, err := fx.store.Put(bytes.NewReader(data), upContentType, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return blob.Handle(id), data
}

// call runs the upload tool on handle within timeout.
func (fx *uploadFixture) call(t *testing.T, handle string, timeout time.Duration) *ToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	result, err := fx.a.Execute(ctx, upTool, map[string]any{upParamTitle: upTitle, upParamFile: handle})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	return result
}

// assertNoSecret fails when the session URI's upload ID shows up in the
// log or in the result.
func (fx *uploadFixture) assertNoSecret(t *testing.T, result *ToolResult) {
	t.Helper()
	if strings.Contains(fx.log.String(), upSecret) {
		t.Errorf("the log contains the upload session ID:\n%s", fx.log.String())
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), upSecret) {
		t.Errorf("the result contains the upload session ID: %s", encoded)
	}
}

func wantSuccess(t *testing.T, result *ToolResult) {
	t.Helper()
	if result.IsError {
		t.Fatalf("upload failed: %s", resultText(t, result))
	}
	if text := resultText(t, result); !strings.Contains(text, upVideoID) {
		t.Fatalf("result = %s, want the created resource", text)
	}
}

func wantErrorCode(t *testing.T, result *ToolResult, code string) {
	t.Helper()
	if !result.IsError {
		t.Fatalf("upload succeeded, want error %q: %s", code, resultText(t, result))
	}
	if got := result.Metadata[metadataKeyErrorCode]; got != code {
		t.Fatalf("error code = %v, want %q (%s)", got, code, resultText(t, result))
	}
}

func TestUpload_ChunksMetadataAndHeaders(t *testing.T) {
	fx := newUploadFixture(t)
	handle, data := fx.file(t, 2*upChunk+1000)

	result := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, result)
	fx.assertNoSecret(t, result)

	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want the %d bytes of the file", len(got), len(data))
	}
	initiations, queries, chunks := fx.srv.counts()
	if initiations != 1 || queries != 0 || chunks != 3 {
		t.Errorf("requests = %d session, %d queries, %d chunks; want 1, 0, 3", initiations, queries, chunks)
	}
	// The metadata is the nested body params, without the file.
	metadata, headers := fx.srv.initiation()
	want := map[string]any{"snippet": map[string]any{"title": upTitle}, "status": map[string]any{"privacyStatus": "private"}}
	if got := mustJSON(t, metadata); got != mustJSON(t, want) {
		t.Errorf("metadata = %s, want %s", got, mustJSON(t, want))
	}
	if got := headers.Get(headerUploadContentType); got != upContentType {
		t.Errorf("%s = %q, want %q", headerUploadContentType, got, upContentType)
	}
	if got := headers.Get(headerUploadContentLength); got != strconv.Itoa(len(data)) {
		t.Errorf("%s = %q, want %d", headerUploadContentLength, got, len(data))
	}
	if result.Metadata[metadataKeyUploadSize] != int64(len(data)) || result.Metadata[metadataKeyUploadResumed] != false {
		t.Errorf("metadata = %v", result.Metadata)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUpload_ResumesAfterInterruptions(t *testing.T) {
	// Each case disturbs the second chunk (the first for the rate limit).
	tests := []struct {
		name    string
		chunk   int
		disturb func(f *fakeUploadServer, s *fakeSession, w http.ResponseWriter, r *http.Request)
	}{
		{"server error on a chunk", 2, func(_ *fakeUploadServer, _ *fakeSession, w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusServiceUnavailable)
		}},
		{"connection lost during a chunk", 2, func(_ *fakeUploadServer, _ *fakeSession, w http.ResponseWriter, _ *http.Request) {
			dropConnection(w)
		}},
		{"chunk stored but its answer lost", 2, func(f *fakeUploadServer, s *fakeSession, w http.ResponseWriter, r *http.Request) {
			f.store(s, w, r, func(bool) bool { return true })
		}},
		{"rate limited with Retry-After", 1, func(_ *fakeUploadServer, _ *fakeSession, w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set(headerRetryAfter, "0")
			w.WriteHeader(http.StatusTooManyRequests)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUploadFixture(t)
			fx.srv.setHook(func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
				if kind == upKindChunk && n == tc.chunk {
					tc.disturb(fx.srv, s, w, r)
					return true
				}
				return false
			})
			handle, data := fx.file(t, 2*upChunk+1000)

			result := fx.call(t, handle, 10*time.Second)
			wantSuccess(t, result)
			fx.assertNoSecret(t, result)
			if got := fx.srv.received(); !bytes.Equal(got, data) {
				t.Fatalf("server stored %d bytes, want the %d bytes of the file", len(got), len(data))
			}
			if initiations, queries, _ := fx.srv.counts(); initiations != 1 || queries == 0 {
				t.Errorf("session requests = %d, status queries = %d; want 1 and at least 1", initiations, queries)
			}
		})
	}
}

// The answer to the last chunk is lost: the status query brings the
// created resource, and no second upload starts.
func TestUpload_LostFinalAnswer(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, _ int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind != upKindChunk {
			return false
		}
		fx.srv.store(s, w, r, func(done bool) bool { return done })
		return true
	})
	handle, _ := fx.file(t, upChunk+10)
	result := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, result)
	fx.assertNoSecret(t, result)
	if initiations, queries, _ := fx.srv.counts(); initiations != 1 || queries != 1 {
		t.Errorf("session requests = %d, status queries = %d; want 1 and 1", initiations, queries)
	}
}

// A call that runs out of time keeps the session; the same call again
// continues it, and once finished, a third call returns the same response
// without uploading again.
func TestUpload_DeadlineThenResumeThenRepeat(t *testing.T) {
	fx := newUploadFixture(t)
	release := make(chan struct{})
	fx.srv.setHook(func(kind string, n int, _ *fakeSession, _ http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n == 2 {
			// Hang until the client gives up on this chunk.
			select {
			case <-r.Context().Done():
			case <-release:
			}
			return true
		}
		return false
	})
	defer close(release)
	handle, data := fx.file(t, 3*upChunk)

	first := fx.call(t, handle, 600*time.Millisecond)
	wantErrorCode(t, first, dadl.ErrCodeUploadIncomplete)
	if !strings.Contains(resultText(t, first), "same arguments") {
		t.Errorf("incomplete result does not say how to continue: %s", resultText(t, first))
	}
	if stored := first.Metadata[metadataKeyUploadStored]; stored != int64(upChunk) {
		t.Errorf("stored = %v, want %d", stored, upChunk)
	}
	fx.assertNoSecret(t, first)

	fx.srv.setHook(nil)
	second := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, second)
	if second.Metadata[metadataKeyUploadResumed] != true {
		t.Errorf("second call metadata = %v, want upload_resumed", second.Metadata)
	}
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want the %d bytes of the file", len(got), len(data))
	}

	initiations, queries, chunks := fx.srv.counts()
	third := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, third)
	fx.assertNoSecret(t, third)
	if third.Metadata[metadataKeyUploadRepeated] != true {
		t.Errorf("third call metadata = %v, want upload_repeated", third.Metadata)
	}
	if i, q, c := fx.srv.counts(); i != initiations || q != queries || c != chunks || initiations != 1 {
		t.Errorf("the repeated call sent requests (session %d→%d, queries %d→%d, chunks %d→%d)", initiations, i, queries, q, chunks, c)
	}
}

// Two calls with the same arguments: the second is refused while the first
// sends the file.
func TestUpload_ConcurrentCallRefused(t *testing.T) {
	fx := newUploadFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	fx.srv.setHook(func(kind string, _ int, _ *fakeSession, _ http.ResponseWriter, _ *http.Request) bool {
		if kind == upKindChunk {
			once.Do(func() { close(entered) })
			<-release
		}
		return false
	})
	handle, _ := fx.file(t, upChunk)

	type outcome struct {
		result *ToolResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, err := fx.a.Execute(context.Background(), upTool, map[string]any{upParamTitle: upTitle, upParamFile: handle})
		done <- outcome{r, err}
	}()
	<-entered
	second := fx.call(t, handle, 10*time.Second)
	close(release)
	wantErrorCode(t, second, dadl.ErrCodeUploadInProgress)
	first := <-done
	if first.err != nil {
		t.Fatal(first.err)
	}
	wantSuccess(t, first.result)
	// The refused call left the session alone: the same call now gets the
	// finished upload's answer.
	if again := fx.call(t, handle, 10*time.Second); again.Metadata[metadataKeyUploadRepeated] != true {
		t.Errorf("follow-up call metadata = %v, want upload_repeated", again.Metadata)
	}
}

// The API forgets a session after bytes went out: the outcome is unknown,
// and the next call starts a new upload.
func TestUpload_SessionGoneAfterBytes(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, n int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n == 2 {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusGone)
			return true
		}
		return false
	})
	handle, _ := fx.file(t, 2*upChunk)
	result := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, result, dadl.ErrCodeUploadOutcomeUnknown)
	fx.assertNoSecret(t, result)

	fx.srv.setHook(nil)
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if initiations, _, _ := fx.srv.counts(); initiations != 2 {
		t.Errorf("session requests = %d, want a new session after the unknown outcome", initiations)
	}
}

// A session that never got a byte is opened anew when the API has forgotten
// it: nothing can exist yet.
func TestUpload_SessionGoneBeforeBytes(t *testing.T) {
	fx := newUploadFixture(t)
	handle, data := fx.file(t, upChunk)
	// Too little time for a chunk: the call opens the session and stops.
	uploadMinChunkWindow = time.Hour
	first := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, first, dadl.ErrCodeUploadIncomplete)
	uploadMinChunkWindow = 100 * time.Millisecond

	fx.srv.mu.Lock()
	for id := range fx.srv.sessions {
		delete(fx.srv.sessions, id)
	}
	fx.srv.mu.Unlock()
	second := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, second)
	fx.assertNoSecret(t, second)
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want %d", len(got), len(data))
	}
	if initiations, _, _ := fx.srv.counts(); initiations != 2 {
		t.Errorf("session requests = %d, want 2", initiations)
	}
}

// The session URI must stay with the address of the session request, and
// a redirect is never followed.
func TestUpload_SessionLocationChecked(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a request reached the foreign server")
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()

	tests := []struct {
		name     string
		location func(fx *uploadFixture, id string) string
	}{
		{"other host", func(_ *uploadFixture, id string) string { return foreign.URL + upPath + "?upload_id=" + id }},
		{"other path", func(fx *uploadFixture, id string) string { return fx.srv.srv.URL + "/other?upload_id=" + id }},
		{"no location", func(*uploadFixture, string) string { return "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUploadFixture(t)
			fx.srv.location = func(id string) string { return tc.location(fx, id) }
			handle, _ := fx.file(t, 100)
			result := fx.call(t, handle, 10*time.Second)
			if !result.IsError {
				t.Fatalf("upload succeeded with Location %q", tc.location(fx, "x"))
			}
			fx.assertNoSecret(t, result)
			if _, _, chunks := fx.srv.counts(); chunks != 0 {
				t.Errorf("%d chunks were sent", chunks)
			}
		})
	}

	t.Run("redirect on the session request", func(t *testing.T) {
		fx := newUploadFixture(t)
		redirecting := httptest.NewServer(http.RedirectHandler(foreign.URL+upPath, http.StatusTemporaryRedirect))
		defer redirecting.Close()
		spec, err := dadl.ParseBytes([]byte(fmt.Sprintf(uploadDADL, redirecting.URL)))
		if err != nil {
			t.Fatal(err)
		}
		a, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{"tube_token": upToken}}, slog.Default(), testRESTOpts)
		if err != nil {
			t.Fatal(err)
		}
		a.SetBlobStore(fx.store)
		handle, _ := fx.file(t, 100)
		result, err := a.Execute(context.Background(), upTool, map[string]any{upParamTitle: upTitle, upParamFile: handle})
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("upload succeeded through a redirect")
		}
	})
}

// A Range the API chose must not make the upload read outside the file,
// and a Range that does not move must not keep the call busy.
func TestUpload_RangeChecked(t *testing.T) {
	tests := []struct {
		name  string
		rng   string
		wantC string
		want  string
	}{
		{"beyond the file", "bytes=0-999999999", "", "Range header outside the file"},
		{"not from zero", "bytes=5-10", "", "does not start at byte 0"},
		{"stuck", "", dadl.ErrCodeUploadIncomplete, "failed too often"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUploadFixture(t)
			fx.srv.setHook(func(_ string, _ int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
				_, _ = io.Copy(io.Discard, r.Body)
				if tc.rng != "" {
					w.Header().Set(headerRange, tc.rng)
				}
				w.WriteHeader(statusResumeIncomplete)
				return true
			})
			handle, _ := fx.file(t, 2*upChunk)
			result := fx.call(t, handle, 10*time.Second)
			if !result.IsError {
				t.Fatal("upload succeeded")
			}
			if tc.wantC != "" {
				wantErrorCode(t, result, tc.wantC)
			}
			if text := resultText(t, result); !strings.Contains(text, tc.want) {
				t.Errorf("result = %s, want it to contain %q", text, tc.want)
			}
			fx.assertNoSecret(t, result)
			if _, _, chunks := fx.srv.counts(); chunks > 10 {
				t.Errorf("%d chunks sent for a stuck upload", chunks)
			}
		})
	}
}

// An upload takes a blob handle or a file URL, not a web address, and a
// declared max_body_size bounds the file.
func TestUpload_SourceChecks(t *testing.T) {
	fx := newUploadFixture(t)
	for _, src := range []string{"https://example.com/video.mp4", "file:///tmp/toolmesh-uploads/video.mp4"} {
		result := fx.call(t, src, 10*time.Second)
		if !result.IsError || !strings.Contains(resultText(t, result), "upload_file") {
			t.Fatalf("source %s: %v", src, result.Content)
		}
	}

	tool := fx.a.spec.Backend.Tools[upTool]
	tool.MaxBodySize = "1KB"
	fx.a.spec.Backend.Tools[upTool] = tool
	sizes, err := resolveMaxBodySizes(fx.a.spec, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	fx.a.maxBodySizes = sizes
	handle, _ := fx.file(t, 2000)
	result := fx.call(t, handle, 10*time.Second)
	if !result.IsError || !strings.Contains(resultText(t, result), testWantExceeding) {
		t.Fatalf("oversized file: %v", result.Content)
	}
	if initiations, _, _ := fx.srv.counts(); initiations != 0 {
		t.Errorf("%d session requests for refused files", initiations)
	}
}

// Without an upload block a declared max_body_size of the same string is
// still clamped to the per-request ceiling; on an upload tool it is not.
func TestUpload_MaxBodySizeNotClamped(t *testing.T) {
	const huge = "2GB"
	spec := &dadl.Spec{Backend: dadl.BackendDef{Name: testBackendNameAPI, Tools: map[string]dadl.ToolDef{
		"up":     {MaxBodySize: huge, Upload: &dadl.UploadConfig{Protocol: dadl.UploadProtocolGoogleResumable}},
		"simple": {MaxBodySize: huge},
	}}}
	sizes, err := resolveMaxBodySizes(spec, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	a := &RESTAdapter{spec: spec, maxBodySizes: sizes}
	up, plain := spec.Backend.Tools["up"], spec.Backend.Tools["simple"]
	want, err := dadl.ParseByteSize(huge)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.uploadFileLimit(&up); got != want {
		t.Errorf("upload tool limit = %d, want %d", got, want)
	}
	if got := a.effectiveMaxBodySize(&plain); got != maxUploadBytes {
		t.Errorf("plain tool limit = %d, want the ceiling %d", got, maxUploadBytes)
	}
}

func TestParseUploadRange(t *testing.T) {
	tests := []struct {
		header string
		want   int64
		ok     bool
	}{
		{"", 0, true},
		{"bytes=0-0", 1, true},
		{"bytes=0-99", 100, true},
		{"bytes=0-100", 0, false},
		{"bytes=1-99", 0, false},
		{"bytes=0--1", 0, false},
		{"bytes=0-x", 0, false},
	}
	for _, tc := range tests {
		got, err := parseUploadRange(tc.header, 100)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseUploadRange(%q) = %d, %v; want %d, ok=%v", tc.header, got, err, tc.want, tc.ok)
		}
	}
}

func TestUploadSessionStore_Bounds(t *testing.T) {
	s := newUploadSessionStore(2)
	now := time.Now()
	s.now = func() time.Time { return now }
	u := &url.URL{Scheme: urlSchemeHTTPS, Host: "example.com"}

	// An entry without a session URI is not kept.
	d, _ := s.acquire("d")
	s.release("d", d, false)
	if _, ok := s.entries["d"]; ok {
		t.Error("an empty session was kept")
	}

	a, _ := s.acquire("a")
	a.uri = u
	s.release("a", a, false)
	now = now.Add(time.Second)
	b, _ := s.acquire("b")
	b.uri = u
	s.release("b", b, false)
	now = now.Add(time.Second)
	c, _ := s.acquire("c") // full: evicts a, the oldest idle one
	if _, ok := s.entries["a"]; ok {
		t.Error("the oldest idle session was not evicted")
	}
	if _, ok := s.acquire("c"); ok {
		t.Error("a busy session was handed out twice")
	}
	c.uri, c.completed = u, true
	s.release("c", c, false)

	// Finished uploads expire sooner than open ones.
	now = now.Add(uploadCompletedTTL + time.Minute)
	s.mu.Lock()
	s.expireLocked(now)
	_, keptB := s.entries["b"]
	_, keptC := s.entries["c"]
	s.mu.Unlock()
	if !keptB || keptC {
		t.Errorf("after the completed TTL: open kept=%v, completed kept=%v; want true, false", keptB, keptC)
	}
}

// A terminal answer after file bytes went out does not drop the session:
// the API may already have the whole file, so the next call asks first.
func TestUpload_TerminalAnswerAfterBytesKeepsSession(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, _ int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		switch kind {
		case upKindChunk:
			// Every chunk is stored, the answer to the last one is lost.
			fx.srv.store(s, w, r, func(done bool) bool { return done })
		default:
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"message":"rate limit exceeded"}}`))
		}
		return true
	})
	handle, data := fx.file(t, upChunk+10)
	first := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, first, dadl.ErrCodeForbidden)
	if !strings.Contains(resultText(t, first), "session is kept") {
		t.Errorf("result does not say the session is kept: %s", resultText(t, first))
	}

	fx.srv.setHook(nil)
	second := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, second)
	if initiations, _, _ := fx.srv.counts(); initiations != 1 {
		t.Errorf("session requests = %d, want 1: the second call must not upload again", initiations)
	}
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want %d", len(got), len(data))
	}
}

// A credential that cannot be applied in the middle of an upload ends the
// call incomplete and keeps the session.
func TestUpload_CredentialFailsMidUpload(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n == 1 {
			fx.srv.store(s, w, r, func(bool) bool { return false })
			fx.creds.fail.Store(true)
			return true
		}
		return false
	})
	handle, data := fx.file(t, 2*upChunk)
	first := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, first, dadl.ErrCodeUploadIncomplete)

	fx.creds.fail.Store(false)
	fx.srv.setHook(nil)
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if initiations, _, _ := fx.srv.counts(); initiations != 1 {
		t.Errorf("session requests = %d, want 1", initiations)
	}
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want %d", len(got), len(data))
	}
}

// A 401 on a chunk renews the credential, asks how far the upload got and
// continues.
func TestUpload_UnauthorizedOnChunk(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, n int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n == 2 {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusUnauthorized)
			return true
		}
		return false
	})
	handle, data := fx.file(t, 3*upChunk)
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want %d", len(got), len(data))
	}
}

// The blob expires after the API got the whole file but before the call
// learned it: the next call finds the finished upload without the file.
func TestUpload_BlobGoneAfterLostFinalAnswer(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, _ int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk {
			fx.srv.store(s, w, r, func(done bool) bool { return done })
			return true
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		return true
	})
	handle, _ := fx.file(t, upChunk)
	wantErrorCode(t, fx.call(t, handle, 10*time.Second), dadl.ErrCodeUploadIncomplete)

	id, _, _, _ := blob.ParseHandle(handle)
	if err := fx.store.Delete(id); err != nil {
		t.Fatal(err)
	}
	fx.srv.setHook(nil)
	result := fx.call(t, handle, 10*time.Second)
	wantSuccess(t, result)
	fx.assertNoSecret(t, result)
	if initiations, _, _ := fx.srv.counts(); initiations != 1 {
		t.Errorf("session requests = %d, want 1", initiations)
	}
}

// The blob expires in the middle of an upload: the call says the file is
// gone and how far the API got, and starts nothing new.
func TestUpload_BlobGoneMidUpload(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(failChunksAfterFirst())
	handle, _ := fx.file(t, 2*upChunk)
	wantErrorCode(t, fx.call(t, handle, 10*time.Second), dadl.ErrCodeUploadIncomplete)

	id, _, _, _ := blob.ParseHandle(handle)
	if err := fx.store.Delete(id); err != nil {
		t.Fatal(err)
	}
	result := fx.call(t, handle, 10*time.Second)
	text := resultText(t, result)
	if !result.IsError || !strings.Contains(text, "no longer stored") || !strings.Contains(text, fmt.Sprintf("%d of %d bytes", upChunk, 2*upChunk)) {
		t.Fatalf("result = %s, want the file-gone error with the stored bytes", text)
	}
	fx.assertNoSecret(t, result)
	if initiations, _, _ := fx.srv.counts(); initiations != 1 {
		t.Errorf("session requests = %d, want 1", initiations)
	}
}

// failChunksAfterFirst stores the first chunk and answers every later one with 503.
func failChunksAfterFirst() func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
	return func(kind string, n int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n >= 2 {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return false
	}
}

// After a reload points the backend elsewhere, a kept session is not asked
// with the new credentials: the outcome is unknown, and neither host gets a
// request.
func TestUpload_SessionOfAnotherAddress(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(failChunksAfterFirst())
	handle, _ := fx.file(t, 2*upChunk)
	wantErrorCode(t, fx.call(t, handle, 10*time.Second), dadl.ErrCodeUploadIncomplete)
	initiations, queries, chunks := fx.srv.counts()

	other := newFakeUploadServer(t)
	fx.a = fx.adapterFor(t, other.srv.URL)
	result := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, result, dadl.ErrCodeUploadOutcomeUnknown)
	fx.assertNoSecret(t, result)
	if i, q, c := fx.srv.counts(); i != initiations || q != queries || c != chunks {
		t.Errorf("the old host got requests after the reload")
	}
	if i, q, c := other.counts(); i+q+c != 0 {
		t.Errorf("the new host got %d requests", i+q+c)
	}
}

// An API error that echoes the session URI or the upload ID does not hand
// either to the caller.
func TestUpload_ErrorEchoRedacted(t *testing.T) {
	echoes := map[string]func(r *http.Request) string{
		"absolute URL": func(r *http.Request) string { return "https://" + r.Host + r.URL.String() },
		"relative URL": func(r *http.Request) string { return r.URL.String() },
		"bare ID":      func(r *http.Request) string { return "id " + r.URL.Query().Get("upload_id") },
	}
	for name, echo := range echoes {
		t.Run(name, func(t *testing.T) {
			fx := newUploadFixture(t)
			fx.srv.setHook(func(kind string, _ int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
				if kind == upKindChunk {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set(testHeaderContentType, testContentTypeJSON)
					w.WriteHeader(http.StatusBadRequest)
					//nolint:gosec // G705: the test server echoes the request on purpose, as an API might
					_, _ = fmt.Fprintf(w, `{"error":{"message":"bad chunk for %s"}}`, echo(r))
					return true
				}
				return false
			})
			handle, _ := fx.file(t, upChunk)
			result := fx.call(t, handle, 10*time.Second)
			if !result.IsError {
				t.Fatal("upload succeeded")
			}
			fx.assertNoSecret(t, result)
		})
	}
}

// A terminal answer before the last byte went out drops the session:
// nothing can exist, so the next call starts a new upload.
func TestUpload_TerminalAnswerBeforeLastByte(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, n int, _ *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk && n == 1 {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(http.StatusForbidden)
			return true
		}
		return false
	})
	handle, data := fx.file(t, 2*upChunk)
	first := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, first, dadl.ErrCodeForbidden)
	if strings.Contains(resultText(t, first), "session is kept") {
		t.Errorf("a session that never got the last byte is reported kept: %s", resultText(t, first))
	}
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if initiations, _, _ := fx.srv.counts(); initiations != 2 {
		t.Errorf("session requests = %d, want a new session", initiations)
	}
	if got := fx.srv.received(); !bytes.Equal(got, data) {
		t.Fatalf("server stored %d bytes, want %d", len(got), len(data))
	}
}

// The file expires while the API has all of it but still finishes: the
// session is kept, and nothing tells the caller to upload again.
func TestUpload_BlobGoneWhileAPIFinishes(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(func(kind string, _ int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindChunk {
			// Stored in full, but the API answers 308 with the whole range.
			body, _ := io.ReadAll(r.Body)
			fx.srv.mu.Lock()
			s.data = append(s.data, body...)
			w.Header().Set(headerRange, fmt.Sprintf("bytes=0-%d", len(s.data)-1))
			fx.srv.mu.Unlock()
			w.WriteHeader(statusResumeIncomplete)
			return true
		}
		fx.srv.mu.Lock()
		w.Header().Set(headerRange, fmt.Sprintf("bytes=0-%d", len(s.data)-1))
		fx.srv.mu.Unlock()
		w.WriteHeader(statusResumeIncomplete)
		return true
	})
	handle, _ := fx.file(t, upChunk)
	wantErrorCode(t, fx.call(t, handle, 10*time.Second), dadl.ErrCodeUploadIncomplete)

	id, _, _, _ := blob.ParseHandle(handle)
	if err := fx.store.Delete(id); err != nil {
		t.Fatal(err)
	}
	second := fx.call(t, handle, 10*time.Second)
	wantErrorCode(t, second, dadl.ErrCodeUploadIncomplete)
	if strings.Contains(resultText(t, second), "store the file again") {
		t.Errorf("caller is told to upload again although the API has the whole file: %s", resultText(t, second))
	}

	// The API finishes; the same call returns the result.
	fx.srv.setHook(func(kind string, _ int, s *fakeSession, w http.ResponseWriter, _ *http.Request) bool {
		fx.srv.mu.Lock()
		defer fx.srv.mu.Unlock()
		s.done = true
		fx.srv.answer(w, s)
		return true
	})
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if initiations, _, _ := fx.srv.counts(); initiations != 1 {
		t.Errorf("session requests = %d, want 1", initiations)
	}
}

// A reload that moves the tool before the last byte went out starts a new
// upload at the new address; the old host gets nothing more.
func TestUpload_AddressChangedBeforeLastByte(t *testing.T) {
	fx := newUploadFixture(t)
	fx.srv.setHook(failChunksAfterFirst())
	handle, data := fx.file(t, 3*upChunk)
	wantErrorCode(t, fx.call(t, handle, 10*time.Second), dadl.ErrCodeUploadIncomplete)
	initiations, queries, chunks := fx.srv.counts()

	other := newFakeUploadServer(t)
	fx.a = fx.adapterFor(t, other.srv.URL)
	wantSuccess(t, fx.call(t, handle, 10*time.Second))
	if i, q, c := fx.srv.counts(); i != initiations || q != queries || c != chunks {
		t.Errorf("the old host got requests after the reload")
	}
	if got := other.received(); !bytes.Equal(got, data) {
		t.Fatalf("new host stored %d bytes, want %d", len(got), len(data))
	}
}

// A call whose status queries fail reports what the API confirmed in an
// earlier call, not zero.
func TestUpload_ResumedCallReportsStoredBytes(t *testing.T) {
	fx := newUploadFixture(t)
	failChunks := failChunksAfterFirst()
	fx.srv.setHook(func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		if kind == upKindQuery {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		return failChunks(kind, n, s, w, r)
	})
	handle, _ := fx.file(t, 2*upChunk)
	for i := range 2 {
		result := fx.call(t, handle, 10*time.Second)
		wantErrorCode(t, result, dadl.ErrCodeUploadIncomplete)
		if stored := result.Metadata[metadataKeyUploadStored]; stored != int64(upChunk) {
			t.Errorf("call %d: stored = %v, want %d", i+1, stored, upChunk)
		}
	}
}

// A 308 that carries a Location is the protocol's answer, not a redirect,
// and every request says exactly which bytes it carries.
func TestUpload_RequestsOnTheWire(t *testing.T) {
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a request reached the Location of a 308")
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()

	fx := newUploadFixture(t)
	var mu sync.Mutex
	var seen []string
	failSecond := failChunksAfterFirst()
	fx.srv.setHook(func(kind string, n int, s *fakeSession, w http.ResponseWriter, r *http.Request) bool {
		mu.Lock()
		seen = append(seen, fmt.Sprintf("%s %s %d", kind, r.Header.Get(headerContentRange), r.ContentLength))
		mu.Unlock()
		switch {
		case kind == upKindChunk && n == 1:
			w.Header().Set(headerLocation, foreign.URL)
			fx.srv.store(s, w, r, func(bool) bool { return false })
			return true
		case kind == upKindChunk && n == 2:
			return failSecond(kind, n, s, w, r)
		}
		return false
	})
	size := 2*upChunk + 5
	handle, _ := fx.file(t, size)
	wantSuccess(t, fx.call(t, handle, 10*time.Second))

	want := []string{
		fmt.Sprintf("%s bytes 0-%d/%d %d", upKindChunk, upChunk-1, size, upChunk),
		fmt.Sprintf("%s bytes %d-%d/%d %d", upKindChunk, upChunk, 2*upChunk-1, size, upChunk),
		fmt.Sprintf("%s bytes */%d 0", upKindQuery, size),
		fmt.Sprintf("%s bytes %d-%d/%d %d", upKindChunk, upChunk, 2*upChunk-1, size, upChunk),
		fmt.Sprintf("%s bytes %d-%d/%d %d", upKindChunk, 2*upChunk, size-1, size, 5),
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests:\n%s\nwant:\n%s", strings.Join(seen, "\n"), strings.Join(want, "\n"))
	}
}
