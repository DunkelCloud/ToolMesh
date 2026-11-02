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

package mcp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	testBrokerUser = "broker-user"
	testBlobPath   = "/blobs/0123456789abcdef"
)

// TestFileBrokerDisabled_RoutesAnswer404 covers a server whose file broker is
// switched off: main passes a nil store, so neither endpoint exists, not even
// for an authenticated caller.
func TestFileBrokerDisabled_RoutesAnswer404(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	handler.SetBlobStore(nil, blob.DefaultUploadLimits())
	srv := NewServer(handler, &config.Config{APIKey: testAPIKey}, logger, nil, nil, nil, nil, nil, nil)
	srv.SetBlobStore(nil, blob.DefaultUploadLimits())
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	for _, tt := range []struct{ method, path string }{
		{http.MethodPost, "/files/upload"},
		{http.MethodGet, testBlobPath},
		{http.MethodHead, testBlobPath},
		{http.MethodDelete, testBlobPath},
	} {
		req := httptest.NewRequestWithContext(context.Background(), tt.method, tt.path, http.NoBody)
		authorize(req)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", tt.method, tt.path, rec.Code)
		}
	}

	tools, err := handler.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("BuildToolList: %v", err)
	}
	for _, tool := range tools {
		if tool.Name == toolUploadFile {
			t.Errorf("%s is listed although the file broker is off", toolUploadFile)
		}
	}
	if handler.isBuiltinTool(toolUploadFile) {
		t.Errorf("%s is dispatched as a built-in although the file broker is off", toolUploadFile)
	}
}

// TestFileUpload_QuotaPerUser checks that POST /files/upload counts against
// the authenticated user and answers 507 once that user's share is used up.
func TestFileUpload_QuotaPerUser(t *testing.T) {
	mux, store := newBlobRouteServer(t, &config.Config{APIKey: testAPIKey, AuthUser: testBrokerUser})
	store.SetQuota(blob.Quota{MaxBytesPerUser: 16})

	upload := func(content string) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		part, err := w.CreateFormFile("file", "a.bin")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = part.Write([]byte(content))
		_ = w.Close()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", &buf)
		req.Header.Set("Content-Type", w.FormDataContentType())
		authorize(req)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	if rec := upload(strings.Repeat("a", 12)); rec.Code != http.StatusCreated {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body.String())
	}
	if _, ofUser := store.Usage(testBrokerUser); ofUser != 12 {
		t.Errorf("usage of %s = %d, want 12", testBrokerUser, ofUser)
	}
	rec := upload(strings.Repeat("b", 12))
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("second upload: status %d, want 507; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "each user may hold 16 bytes") {
		t.Errorf("body = %q", rec.Body.String())
	}
}

// TestHandleUploadFile_Quota checks that upload_file counts against the user
// of the request and reports a refusal as a clear tool error.
func TestHandleUploadFile_Quota(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Content-Length: the quota has to stop the stream, not a pre-check.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte(strings.Repeat("x", 64)))
	}))
	defer src.Close()

	h := newUploadTestHandler(t, blob.UploadLimits{MaxBytes: 1 << 20, DefaultTTL: time.Hour, MaxTTL: time.Hour})
	h.blobStore.SetQuota(blob.Quota{MaxBytesPerUser: 100})
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testBrokerUser, Authenticated: true})

	res, err := h.handleUploadFile(ctx, map[string]any{argNameURL: src.URL + "/a.bin"})
	if err != nil || res.IsError {
		t.Fatalf("first upload: err %v, result %s", err, resultText(t, res))
	}
	if _, ofUser := h.blobStore.Usage(testBrokerUser); ofUser != 64 {
		t.Errorf("usage of %s = %d, want 64", testBrokerUser, ofUser)
	}

	res, err = h.handleUploadFile(ctx, map[string]any{argNameURL: src.URL + "/b.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if text := resultText(t, res); !res.IsError || !strings.Contains(text, blob.ErrQuotaExceeded.Error()) {
		t.Errorf("second upload: IsError %v, text %q; want the quota error", res.IsError, text)
	}
	if _, ofUser := h.blobStore.Usage(testBrokerUser); ofUser != 64 {
		t.Errorf("usage after the refusal = %d, want 64", ofUser)
	}

	// Another user is not affected.
	other := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "someone-else", Authenticated: true})
	if res, _ := h.handleUploadFile(other, map[string]any{argNameURL: src.URL + "/c.bin"}); res.IsError {
		t.Errorf("other user refused: %s", resultText(t, res))
	}
}

// TestHandleUploadFile_PrecheckRefusalIsLogged covers a fetch whose
// Content-Length is over the quota: it is refused before the body is read,
// and that refusal is logged like one found while writing.
func TestHandleUploadFile_PrecheckRefusalIsLogged(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", "64")
		_, _ = w.Write([]byte(strings.Repeat("x", 64)))
	}))
	defer src.Close()

	logs := &loginLogBuffer{}
	store, err := blob.NewStore(t.TempDir(), "http://localhost:8080", slog.New(slog.NewJSONHandler(logs, nil)))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.SetQuota(blob.Quota{MaxBytesPerUser: 32})
	h := &Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h.SetBlobStore(store, blob.UploadLimits{MaxBytes: 1 << 20, DefaultTTL: time.Hour, MaxTTL: time.Hour})
	h.uploadFetchClient = &http.Client{Timeout: 10 * time.Second}
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testBrokerUser, Authenticated: true})

	res, err := h.handleUploadFile(ctx, map[string]any{argNameURL: src.URL + "/a.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(resultText(t, res), blob.ErrQuotaExceeded.Error()) {
		t.Fatalf("result = %s, want the quota error", resultText(t, res))
	}
	lines := logs.lines(t, "blob refused: file broker quota exceeded")
	if len(lines) != 1 {
		t.Fatalf("%d refusal log lines, want 1; log:\n%s", len(lines), logs.String())
	}
	if lines[0]["level"] != testLogLevelWarn || lines[0]["owner"] != testBrokerUser {
		t.Errorf("refusal logged as %v, want WARN for %s", lines[0], testBrokerUser)
	}
}
