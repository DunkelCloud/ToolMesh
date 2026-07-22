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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

// newBlobRouteServer builds a server with a blob store and the given config,
// then wires routes. The blob store must be set before SetupRoutes so /blobs/
// and /files/upload get registered.
func newBlobRouteServer(t *testing.T, cfg *config.Config) (*http.ServeMux, *blob.Store) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, cfg.DebugTools)
	srv := NewServer(handler, cfg, logger, nil, nil, nil, nil, nil, nil)

	store, err := blob.NewStore(t.TempDir(), "http://localhost:8080", logger)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	srv.SetBlobStore(store, blob.DefaultUploadLimits())

	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	return mux, store
}

// TestBlobRoute_DeleteRequiresAuth verifies the capability/auth split on
// /blobs/{id}: GET/HEAD are capability-based (no credentials), while DELETE
// requires MCP authentication.
func TestBlobRoute_DeleteRequiresAuth(t *testing.T) {
	const key = "my-secret-key"
	mux, store := newBlobRouteServer(t, &config.Config{APIKey: key})

	putBlob := func() string {
		id, _, err := store.Put(strings.NewReader("blob body"), "text/plain", time.Hour)
		if err != nil {
			t.Fatalf("Put: %v", err)
		}
		return id
	}

	do := func(method, id, bearer string) int {
		req := httptest.NewRequestWithContext(context.Background(), method, "/blobs/"+id, http.NoBody)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Run("GET is capability-based (no auth)", func(t *testing.T) {
		id := putBlob()
		if code := do(http.MethodGet, id, ""); code != http.StatusOK {
			t.Errorf("GET without auth = %d, want 200", code)
		}
	})

	t.Run("DELETE without auth is rejected", func(t *testing.T) {
		id := putBlob()
		if code := do(http.MethodDelete, id, ""); code != http.StatusUnauthorized {
			t.Errorf("DELETE without auth = %d, want 401", code)
		}
		// The blob must survive the rejected delete.
		if _, err := store.Stat(id); err != nil {
			t.Errorf("blob was deleted despite 401: %v", err)
		}
	})

	t.Run("DELETE with wrong credential is rejected", func(t *testing.T) {
		id := putBlob()
		if code := do(http.MethodDelete, id, "wrong-key"); code != http.StatusUnauthorized {
			t.Errorf("DELETE with wrong key = %d, want 401", code)
		}
		if _, err := store.Stat(id); err != nil {
			t.Errorf("blob was deleted despite bad credential: %v", err)
		}
	})

	t.Run("DELETE with auth succeeds", func(t *testing.T) {
		id := putBlob()
		if code := do(http.MethodDelete, id, key); code != http.StatusNoContent {
			t.Errorf("DELETE with auth = %d, want 204", code)
		}
		if _, err := store.Stat(id); err == nil {
			t.Error("blob still present after authorized DELETE")
		}
	})
}

// TestBlobRoute_OpenServer verifies that when no auth is configured the whole
// server is open, so DELETE passes through like every other route.
func TestBlobRoute_OpenServer(t *testing.T) {
	mux, store := newBlobRouteServer(t, &config.Config{})
	id, _, err := store.Put(strings.NewReader("x"), "text/plain", time.Hour)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/blobs/"+id, http.NoBody)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("DELETE on open server = %d, want 204", rec.Code)
	}
}
