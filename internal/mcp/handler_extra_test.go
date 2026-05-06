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

func TestHandleToolCall_DiscoverTools(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "discover_tools", "arguments": {"pattern": ".*"}}}`
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

func TestHandleToolCall_DiscoverToolsMissingPattern(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "discover_tools", "arguments": {}}}`
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

func TestHandleToolCall_DiscoverToolsInvalidRegex(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "discover_tools", "arguments": {"pattern": "[invalid"}}}`
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
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)
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
	h := NewHandler(nil, &mockTestBackend{}, nil, "", nil, newQuietMCPLogger(), false)
	if desc := h.buildBackendDescription(); desc != "" {
		t.Errorf("expected empty, got %q", desc)
	}
}

// TestBuildToolList_BackendHintsOnExecuteCodeOnly verifies that the per-backend
// "Available backends: ... Hints: ..." block is appended to the execute_code
// description but not to discover_tools. Duplicating that block on both tools
// costs thousands of context tokens for no information gain, so discover_tools
// must stay minimal. Backend names use a unique prefix so the assertion does
// not collide with example patterns ("github", "dokuwiki") that legitimately
// appear in the discover_tools description.
func TestBuildToolList_BackendHintsOnExecuteCodeOnly(t *testing.T) {
	mb := &summarizingBackend{
		infos: []backend.BackendInfo{
			{Name: "tmtest_alpha", Hint: "tmtest backend alpha"},
			{Name: "tmtest_beta", Hint: "tmtest backend beta"},
		},
	}
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)
	tools, err := h.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("BuildToolList: %v", err)
	}

	var discoverDesc, execDesc string
	for _, td := range tools {
		switch td.Name {
		case "discover_tools":
			discoverDesc = td.Description
		case "execute_code":
			execDesc = td.Description
		}
	}
	if discoverDesc == "" || execDesc == "" {
		t.Fatalf("missing tool descriptions: discover=%q exec=%q", discoverDesc, execDesc)
	}

	// discover_tools must not carry the backend block.
	for _, marker := range []string{"Available backends", "Hints:", "tmtest_alpha", "tmtest_beta", "tmtest backend alpha", "tmtest backend beta"} {
		if strings.Contains(discoverDesc, marker) {
			t.Errorf("discover_tools description should not contain %q, got: %s", marker, discoverDesc)
		}
	}

	// execute_code must carry the backend block.
	for _, marker := range []string{"Available backends", "Hints:", "tmtest_alpha", "tmtest_beta", "tmtest backend alpha", "tmtest backend beta"} {
		if !strings.Contains(execDesc, marker) {
			t.Errorf("execute_code description should contain %q, got: %s", marker, execDesc)
		}
	}

	// discover_tools must be no longer than execute_code: the whole point of
	// stripping the backend block from discover_tools is to make it materially
	// smaller, and execute_code grows linearly with the number of backends.
	if len(discoverDesc) > len(execDesc) {
		t.Errorf("discover_tools description (%d chars) is longer than execute_code (%d chars) — backend block may have leaked back in",
			len(discoverDesc), len(execDesc))
	}
}
