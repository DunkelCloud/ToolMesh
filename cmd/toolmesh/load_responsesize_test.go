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

package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// loadSizeTestBackend loads the test DADL against url with the given
// options.max_response_size and returns the backend and the load log.
func loadSizeTestBackend(t *testing.T, url, maxResponseSize string) (backend.ToolBackend, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "api.dadl"), []byte(testDADLContent), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := "backends:\n  - name: testapi\n    transport: rest\n    dadl: api.dadl\n    url: \"" + url + "\"\n" +
		"    options:\n      max_response_size: \"" + maxResponseSize + "\"\n"
	if err := os.WriteFile(backendsPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, logger, nil, nil, nil, nil)
	b, ok := named["testapi"]
	if !ok {
		t.Fatalf("backend not loaded; log:\n%s", logBuf.String())
	}
	return b, logBuf.String()
}

// TestLoadRESTBackends_MaxResponseSizeOption pins that options.max_response_size
// in backends.yaml reaches the adapter: a body over the configured limit
// fails with response_too_large.
func TestLoadRESTBackends_MaxResponseSizeOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pad": "` + strings.Repeat("x", 2000) + `"}`))
	}))
	defer srv.Close()

	b, log := loadSizeTestBackend(t, srv.URL, "1KB")
	if !strings.Contains(log, "response size limit override") {
		t.Errorf("override not logged; log:\n%s", log)
	}
	result, err := b.Execute(t.Context(), "get_ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.Metadata["error_code"] != dadl.ErrCodeResponseTooLarge {
		t.Fatalf("result = %v, want a response_too_large error", result.Content)
	}
}

// TestLoadRESTBackends_InvalidMaxResponseSizeOption pins that a value that
// does not parse keeps the backend with the default limit and says so.
func TestLoadRESTBackends_InvalidMaxResponseSizeOption(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pad": "` + strings.Repeat("x", 2000) + `"}`))
	}))
	defer srv.Close()

	b, log := loadSizeTestBackend(t, srv.URL, "a lot")
	if !strings.Contains(log, "invalid max_response_size option") || !strings.Contains(log, "default=10MB") {
		t.Errorf("invalid value not reported with the default; log:\n%s", log)
	}
	result, err := b.Execute(t.Context(), "get_ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("2 KB body failed under the 10 MB default: %v", result.Content)
	}
}
