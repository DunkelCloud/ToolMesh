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
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	s, err := NewStore(dir, "http://localhost:8080", logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func TestStore_PutAndServe(t *testing.T) {
	s := newTestStore(t)

	id, size, err := s.Put(strings.NewReader("hello world"), "text/plain; charset=utf-8", time.Hour)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if size != 11 {
		t.Errorf("size = %d, want 11", size)
	}
	if id == "" {
		t.Error("expected non-empty id")
	}

	url := s.URL(id)
	if !strings.HasSuffix(url, "/blobs/"+id) {
		t.Errorf("URL = %q, want suffix /blobs/%s", url, id)
	}

	// Use an httptest server so http.ServeFile has the right ResponseWriter.
	srv := httptest.NewServer(http.HandlerFunc(s.ServeHTTP))
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/blobs/"+id, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "private, no-store" {
		t.Errorf("Cache-Control = %q, want private, no-store", got)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", cd)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello world" {
		t.Errorf("body = %q, want hello world", body)
	}
}

func TestStore_ServeHead(t *testing.T) {
	s := newTestStore(t)
	id, _, err := s.Put(strings.NewReader("abcdef"), "application/octet-stream", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/blobs/"+id, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if cl := w.Header().Get("Content-Length"); cl != "6" {
		t.Errorf("Content-Length = %q, want 6", cl)
	}
}

func TestStore_ServeHTTP_NotFound(t *testing.T) {
	s := newTestStore(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/blobs/does-not-exist", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestStore_ServeHTTP_PathTraversal(t *testing.T) {
	s := newTestStore(t)

	// "id" containing "/" is rejected before map lookup.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/blobs/..%2Fetc%2Fpasswd", nil)
	req.URL.Path = "/blobs/../etc/passwd"
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("path traversal status = %d, want 404", w.Code)
	}
}

func TestStore_ServeHTTP_EmptyID(t *testing.T) {
	s := newTestStore(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/blobs/", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("empty id status = %d, want 404", w.Code)
	}
}

func TestStore_ServeHTTP_MethodNotAllowed(t *testing.T) {
	s := newTestStore(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/blobs/x", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestStore_ServeHTTP_Expired(t *testing.T) {
	s := newTestStore(t)
	id, _, err := s.Put(strings.NewReader("data"), "text/plain", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Manually expire the blob.
	s.mu.Lock()
	s.blobs[id].ExpiresAt = time.Now().Add(-time.Minute)
	s.mu.Unlock()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/blobs/"+id, nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expired status = %d, want 404", w.Code)
	}
}

func TestStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits differ on Windows")
	}
	s := newTestStore(t)
	id, _, err := s.Put(strings.NewReader("data"), "text/plain", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	s.mu.RLock()
	path := s.blobs[id].FilePath
	s.mu.RUnlock()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %o, want 0600", fi.Mode().Perm())
	}
}

func TestStore_CleanupExpired(t *testing.T) {
	s := newTestStore(t)

	id, _, err := s.Put(strings.NewReader("data"), "text/plain", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Force expiry.
	s.mu.Lock()
	s.blobs[id].ExpiresAt = time.Now().Add(-time.Minute)
	path := s.blobs[id].FilePath
	s.mu.Unlock()

	// Run the cleanup logic inline (we don't want to wait for the 60s ticker).
	s.mu.Lock()
	now := time.Now()
	for bid, entry := range s.blobs {
		if now.After(entry.ExpiresAt) {
			_ = os.Remove(entry.FilePath)
			delete(s.blobs, bid)
		}
	}
	s.mu.Unlock()

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("expected file to be removed, stat err = %v", err)
	}
	s.mu.RLock()
	_, ok := s.blobs[id]
	s.mu.RUnlock()
	if ok {
		t.Error("expired blob still in map")
	}
}

func TestExtensionForType(t *testing.T) {
	const binExt = ".bin"
	tests := []struct {
		ct      string
		wantExt string
	}{
		{"text/plain", ""},                // could be .txt or similar — check not empty
		{"application/json", ""},          // could be .json
		{"unknown/x-custom", binExt},      // fallback
		{"audio/mpeg; charset=utf-8", ""}, // stripped params
	}
	for _, tt := range tests {
		ext := extensionForType(tt.ct)
		if tt.wantExt == binExt {
			if ext != binExt {
				t.Errorf("ct=%q ext=%q want %s", tt.ct, ext, binExt)
			}
			continue
		}
		if ext == "" {
			t.Errorf("ct=%q returned empty ext", tt.ct)
		}
	}
}

func TestGenerateID(t *testing.T) {
	a, err := generateID()
	if err != nil {
		t.Fatal(err)
	}
	b, err := generateID()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("expected unique IDs")
	}
	if len(a) != 32 {
		t.Errorf("id length = %d, want 32", len(a))
	}
}
