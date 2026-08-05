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
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
)

// newUploadTestHandler builds a minimal Handler with a blob store and a plain
// HTTP fetch client. The SSRF-safe transport from SetBlobStore rejects
// loopback destinations by design, which would block httptest sources — the
// transport itself is covered by the urlvalidation tests.
func newUploadTestHandler(t *testing.T, limits blob.UploadLimits) *Handler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := blob.NewStore(t.TempDir(), "http://localhost:8080", logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	h := &Handler{logger: logger}
	h.SetBlobStore(store, limits)
	h.uploadFetchClient = &http.Client{Timeout: 10 * time.Second}
	return h
}

func resultText(t *testing.T, r *backend.ToolResult) string {
	t.Helper()
	if len(r.Content) == 0 {
		t.Fatal("empty result content")
	}
	m, ok := r.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] is %T", r.Content[0])
	}
	s, _ := m[contentKeyText].(string)
	return s
}

func TestHandleUploadFile(t *testing.T) {
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Content-Disposition", `attachment; filename="scan.jpg"`)
		_, _ = w.Write([]byte("jpeg content"))
	}))
	defer src.Close()

	h := newUploadTestHandler(t, blob.UploadLimits{MaxBytes: 1 << 20, DefaultTTL: time.Hour, MaxTTL: 2 * time.Hour})

	res, err := h.handleUploadFile(context.Background(), map[string]any{argNameURL: src.URL + "/scan"})
	if err != nil {
		t.Fatalf("handleUploadFile: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error result: %s", resultText(t, res))
	}

	var result blob.UploadResult
	if err := json.Unmarshal([]byte(resultText(t, res)), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Handle != blob.Handle(result.FileID) || result.Size != 12 || result.ContentType != "image/jpeg" {
		t.Errorf("result = %+v", result)
	}

	rc, info, err := h.blobStore.Open(result.FileID)
	if err != nil {
		t.Fatalf("Open stored blob: %v", err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(data) != "jpeg content" || info.Filename != "scan.jpg" {
		t.Errorf("stored content %q, filename %q", data, info.Filename)
	}
}

func TestHandleUploadFileErrors(t *testing.T) {
	h := newUploadTestHandler(t, blob.UploadLimits{MaxBytes: 8, DefaultTTL: time.Hour, MaxTTL: time.Hour})

	t.Run("missing url", func(t *testing.T) {
		res, _ := h.handleUploadFile(context.Background(), map[string]any{})
		if !res.IsError || !strings.Contains(resultText(t, res), `"url" is required`) {
			t.Errorf("result = %s", resultText(t, res))
		}
	})

	t.Run("non-http scheme", func(t *testing.T) {
		res, _ := h.handleUploadFile(context.Background(), map[string]any{argNameURL: "file:///etc/passwd"})
		if !res.IsError || !strings.Contains(resultText(t, res), "only http(s)") {
			t.Errorf("result = %s", resultText(t, res))
		}
	})

	t.Run("upstream error status", func(t *testing.T) {
		src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "secret upstream detail", http.StatusNotFound)
		}))
		defer src.Close()
		res, _ := h.handleUploadFile(context.Background(), map[string]any{argNameURL: src.URL})
		if !res.IsError || !strings.Contains(resultText(t, res), "HTTP 404") {
			t.Errorf("result = %s", resultText(t, res))
		}
		if strings.Contains(resultText(t, res), "secret upstream detail") {
			t.Error("upstream body must not be echoed to the caller")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("way more than eight bytes"))
		}))
		defer src.Close()
		res, _ := h.handleUploadFile(context.Background(), map[string]any{argNameURL: src.URL})
		if !res.IsError || !strings.Contains(resultText(t, res), "byte limit") {
			t.Errorf("result = %s", resultText(t, res))
		}
	})

	t.Run("invalid ttl", func(t *testing.T) {
		res, _ := h.handleUploadFile(context.Background(), map[string]any{argNameURL: "http://example.com/x", argNameTTL: "-5m"})
		if !res.IsError || !strings.Contains(resultText(t, res), "invalid ttl") {
			t.Errorf("result = %s", resultText(t, res))
		}
	})

	t.Run("not configured", func(t *testing.T) {
		bare := &Handler{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
		res, _ := bare.handleUploadFile(context.Background(), map[string]any{argNameURL: "http://example.com/x"})
		if !res.IsError || !strings.Contains(resultText(t, res), "not configured") {
			t.Errorf("result = %s", resultText(t, res))
		}
	})
}
