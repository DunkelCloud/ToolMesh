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
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

const testBlobID = "abc123"

func TestParseHandle(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		id       string
		fragment string
		ok       bool
		wantErr  bool
	}{
		{"not a handle", "https://example.com/x", "", "", false, false},
		{"bare handle", "tm-blob://" + testBlobID, testBlobID, "", true, false},
		{"base64 fragment", "tm-blob://" + testBlobID + "#base64", testBlobID, "base64", true, false},
		{"dataurl fragment", "tm-blob://" + testBlobID + "#dataurl", testBlobID, "dataurl", true, false},
		{"url fragment", "tm-blob://" + testBlobID + "#url", testBlobID, "url", true, false},
		{"empty id", "tm-blob://", "", "", true, true},
		{"empty id with fragment", "tm-blob://#base64", "", "", true, true},
		{"slash in id", "tm-blob://a/b", "", "", true, true},
		{"unknown fragment", "tm-blob://abc123#hex", "", "", true, true},
		{"embedded handle is not parsed", "see tm-blob://abc123#base64", "", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, fragment, ok, err := ParseHandle(tt.in)
			if ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && (id != tt.id || fragment != tt.fragment) {
				t.Errorf("got (%q, %q), want (%q, %q)", id, fragment, tt.id, tt.fragment)
			}
		})
	}
}

func TestHandleRoundTrip(t *testing.T) {
	h := Handle("deadbeef")
	if h != "tm-blob://deadbeef" {
		t.Fatalf("Handle = %q", h)
	}
	if !IsHandle(h) {
		t.Error("IsHandle(Handle(id)) = false")
	}
	id, fragment, ok, err := ParseHandle(h)
	if !ok || err != nil || id != "deadbeef" || fragment != "" {
		t.Errorf("ParseHandle round trip failed: %q %q %v %v", id, fragment, ok, err)
	}
}

func TestStore_OpenStatDelete(t *testing.T) {
	s := newTestStore(t)

	id, _, err := s.PutNamed(strings.NewReader("scan bytes"), "image/jpeg", "IMG_1614.jpg", time.Hour)
	if err != nil {
		t.Fatalf("PutNamed: %v", err)
	}

	info, err := s.Stat(id)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Filename != "IMG_1614.jpg" || info.ContentType != "image/jpeg" || info.Size != 10 {
		t.Errorf("Stat = %+v", info)
	}

	rc, info2, err := s.Open(id)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, err := io.ReadAll(rc)
	_ = rc.Close()
	if err != nil || string(data) != "scan bytes" {
		t.Errorf("Open content = %q, err %v", data, err)
	}
	if info2.ID != id {
		t.Errorf("Open info.ID = %q, want %q", info2.ID, id)
	}

	if err := s.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Stat(id); err == nil {
		t.Error("Stat after Delete should fail")
	}
	if err := s.Delete(id); err == nil {
		t.Error("second Delete should fail")
	}
}

func TestStore_OpenExpired(t *testing.T) {
	s := newTestStore(t)
	id, _, err := s.Put(strings.NewReader("x"), "text/plain", -time.Second)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, _, err := s.Open(id); err == nil {
		t.Error("Open of expired blob should fail")
	}
	if _, err := s.Stat(id); err == nil {
		t.Error("Stat of expired blob should fail")
	}
}

func TestStore_ServeHTTPDelete(t *testing.T) {
	s := newTestStore(t)
	id, _, err := s.Put(strings.NewReader("bye"), "text/plain", time.Hour)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	srv := httptest.NewServer(s)
	defer srv.Close()

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodDelete, srv.URL+"/blobs/"+id, http.NoBody)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("DELETE status = %d, want 204", resp.StatusCode)
	}

	getReq, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/blobs/"+id, http.NoBody)
	resp2, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("GET after DELETE status = %d, want 404", resp2.StatusCode)
	}
}

// multipartUpload builds a broker upload request body: a "file" part followed
// by an optional "ttl" field, mirroring FileBrokerClient's wire order.
func multipartUpload(t *testing.T, filename, contentType, content, ttl string) (io.Reader, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="file"; filename="`+filename+`"`)
	h.Set("Content-Type", contentType)
	part, err := w.CreatePart(h)
	if err != nil {
		t.Fatalf("CreatePart: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ttl != "" {
		if err := w.WriteField("ttl", ttl); err != nil {
			t.Fatalf("WriteField: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return &buf, w.FormDataContentType()
}

func TestStore_HandleUpload(t *testing.T) {
	s := newTestStore(t)
	limits := UploadLimits{MaxBytes: 1 << 20, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour}

	body, ct := multipartUpload(t, "IMG_1614.jpg", "image/jpeg", "jpeg bytes", "30m")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
	req.Header.Set("Content-Type", ct)
	rec := httptest.NewRecorder()
	s.HandleUpload(rec, req, limits)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var result UploadResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if result.FileID == "" || result.Handle != Handle(result.FileID) {
		t.Errorf("result = %+v", result)
	}
	if result.Size != 10 || result.ContentType != "image/jpeg" {
		t.Errorf("result = %+v", result)
	}
	if !strings.HasSuffix(result.URL, "/blobs/"+result.FileID) {
		t.Errorf("URL = %q", result.URL)
	}

	// TTL 30m must be honored (default is 1h, so expiry must be well before now+1h).
	if until := time.Until(result.Expires); until > 31*time.Minute || until < 29*time.Minute {
		t.Errorf("expires in %v, want ~30m", until)
	}

	// Content must round-trip through Open, with the original filename kept.
	rc, info, err := s.Open(result.FileID)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(data) != "jpeg bytes" || info.Filename != "IMG_1614.jpg" {
		t.Errorf("content %q, filename %q", data, info.Filename)
	}
}

func TestStore_HandleUploadErrors(t *testing.T) {
	s := newTestStore(t)
	limits := UploadLimits{MaxBytes: 16, DefaultTTL: time.Hour, MaxTTL: time.Hour}

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/files/upload", http.NoBody)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d", rec.Code)
		}
	})

	t.Run("missing file field", func(t *testing.T) {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("ttl", "1h")
		_ = w.Close()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", &buf)
		req.Header.Set("Content-Type", w.FormDataContentType())
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d", rec.Code)
		}
	})

	t.Run("invalid ttl", func(t *testing.T) {
		body, ct := multipartUpload(t, "a.txt", "text/plain", "hi", "yesterday")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d", rec.Code)
		}
	})

	t.Run("ttl clamped to max", func(t *testing.T) {
		body, ct := multipartUpload(t, "a.txt", "text/plain", "hi", "48h")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits)
		if rec.Code != http.StatusCreated {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		var result UploadResult
		_ = json.Unmarshal(rec.Body.Bytes(), &result)
		if until := time.Until(result.Expires); until > limits.MaxTTL+time.Minute {
			t.Errorf("expires in %v, want <= %v", until, limits.MaxTTL)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		body, ct := multipartUpload(t, "big.bin", "application/octet-stream", strings.Repeat("x", 64), "")
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", body)
		req.Header.Set("Content-Type", ct)
		rec := httptest.NewRecorder()
		s.HandleUpload(rec, req, limits)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, body %s", rec.Code, rec.Body.String())
		}
	})
}
