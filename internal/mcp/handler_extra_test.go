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

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
)

func newQuietMCPLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// summarizingBackend wraps mockTestBackend and also implements
// backend.BackendSummarizer so we can test buildBackendDescription.
type summarizingBackend struct {
	mockTestBackend
	infos []backend.BackendInfo
}

func (s *summarizingBackend) BackendSummaries() []backend.BackendInfo { return s.infos }

func TestHandleToolCall_ListTools(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_tools", "arguments": {"pattern": ".*"}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != nil {
		t.Errorf("unexpected error: %v", resp["error"])
	}
}

func TestHandleToolCall_ListToolsMissingPattern(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_tools", "arguments": {}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["isError"] != true {
		t.Errorf("expected isError=true, got %v", resp)
	}
}

func TestHandleToolCall_ListToolsInvalidRegex(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_tools", "arguments": {"pattern": "[invalid"}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["isError"] != true {
		t.Errorf("expected isError=true for invalid regex, got %v", resp)
	}
}

func TestHandleToolCall_ExecuteCodeMissingCode(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_code", "arguments": {}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["isError"] != true {
		t.Errorf("expected isError=true, got %v", resp)
	}
}

func TestHandleToolCall_ExecuteCodeNonStringCode(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_code", "arguments": {"code": 123}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["isError"] != true {
		t.Errorf("expected isError=true, got %v", resp)
	}
}

func TestHandleToolCall_ExecuteCodeEmpty(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_code", "arguments": {"code": "// empty"}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != nil && resp["result"] == nil {
		t.Errorf("expected result, got error: %v", resp["error"])
	}
}

// TestHandleToolCall_ExecuteCodeRuntimeError_SurfacesRealError ensures that
// when JavaScript fails (here: an explicit throw), the response carries the
// real error message — not just the runner's "no tool calls found in code"
// placeholder, which was misleading callers debugging non-trivial code.
func TestHandleToolCall_ExecuteCodeRuntimeError_SurfacesRealError(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_code", "arguments": {"code": "throw new Error('runtime-boom');"}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil || result["isError"] != true {
		t.Fatalf("expected isError=true, got %v", resp)
	}

	contentBytes, _ := json.Marshal(result["content"])
	contentStr := string(contentBytes)
	if !strings.Contains(contentStr, "runtime-boom") {
		t.Errorf("expected response to surface the JS error message 'runtime-boom', got: %s", contentStr)
	}
	if !strings.Contains(contentStr, "execute_code failed") {
		t.Errorf("expected response to be prefixed with 'execute_code failed', got: %s", contentStr)
	}
}

func TestBuildBackendDescription(t *testing.T) {
	mb := &summarizingBackend{
		infos: []backend.BackendInfo{
			{Name: "github", Hint: "GitHub API"},
			{Name: "jira", Hint: "Jira API"},
			{Name: "nohint"},
		},
	}
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger())
	desc := h.buildBackendDescription()
	if !strings.Contains(desc, "github") || !strings.Contains(desc, "jira") {
		t.Errorf("desc missing backend names: %s", desc)
	}
	if !strings.Contains(desc, "GitHub API") {
		t.Errorf("desc missing hint: %s", desc)
	}
}

func TestBuildBackendDescription_NoSummarizer(t *testing.T) {
	// mockTestBackend doesn't implement BackendSummarizer.
	h := NewHandler(nil, &mockTestBackend{}, nil, "", nil, newQuietMCPLogger())
	if desc := h.buildBackendDescription(); desc != "" {
		t.Errorf("expected empty, got %q", desc)
	}
}
