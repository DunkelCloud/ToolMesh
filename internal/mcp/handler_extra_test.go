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

// TestHandleToolCall_DiscoverToolsMissingPattern verifies that omitting the
// pattern argument is treated as ".*" (list all). The previous behavior — error
// out demanding the magic string — was friction for the most common case.
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
	if result == nil {
		t.Fatalf("expected result, got %v", resp)
	}
	if result["isError"] == true {
		t.Errorf("expected isError=false (pattern defaults to \".*\"), got %v", result)
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
// real error message — and ONLY that. Earlier behavior emitted both the
// runner's "no tool calls found in code" placeholder and the real error,
// which was contradictory ("no calls found, but here's a TypeError…").
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
	// The "no tool calls found in code" placeholder must NOT appear when a
	// runtime error is the real cause — emitting both messages contradicts
	// itself and obscures the actual error.
	if strings.Contains(contentStr, "no tool calls found in code") {
		t.Errorf("response must not contain 'no tool calls found in code' alongside a runtime error, got: %s", contentStr)
	}
}

// TestHandleToolCall_ExecuteCodeDiscoverToolsGuard verifies that calling
// toolmesh.discover_tools(...) from inside execute_code surfaces the explicit
// guard message — not the bare goja TypeError "Object has no member …" that
// gave callers no clue what they did wrong. The same applies to execute_code.
func TestHandleToolCall_ExecuteCodeDiscoverToolsGuard(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	cases := []struct {
		name string
		code string
	}{
		{name: toolDiscoverTools, code: `await toolmesh.discover_tools({pattern: ".*"});`},
		{name: toolExecuteCode, code: `await toolmesh.execute_code({code: "1"});`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_code", "arguments": {"code": ` + jsonString(tc.code) + `}}}`
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
			if !strings.Contains(contentStr, "toolmesh."+tc.name+" is not a backend tool") {
				t.Errorf("expected guard message naming toolmesh.%s, got: %s", tc.name, contentStr)
			}
			if !strings.Contains(contentStr, "separate MCP tool") {
				t.Errorf("expected guard to point at separate MCP tool semantics, got: %s", contentStr)
			}
			// The placeholder must not leak alongside the guard message.
			if strings.Contains(contentStr, "no tool calls found in code") {
				t.Errorf("response must not contain 'no tool calls found in code' alongside guard message, got: %s", contentStr)
			}
		})
	}
}

// jsonString renders s as a JSON-encoded string literal (with quotes).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestBuildBackendDescription(t *testing.T) {
	mb := &summarizingBackend{
		infos: []backend.BackendInfo{
			{Name: testBackendNameGitHub, Hint: "GitHub API"},
			{Name: "jira", Hint: "Jira API"},
			{Name: "nohint"},
		},
	}
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)
	desc := h.buildBackendDescription()
	if !strings.Contains(desc, testBackendNameGitHub) || !strings.Contains(desc, "jira") {
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

// TestBuildGroupedHints covers the grouping logic that collapses backend
// instances sharing a DADL spec into a single hint line. Edge cases mirror the
// brief: no group, two instances of one spec, three+ instances, mix of DADL
// and native backends, infos without hints, and stable group ordering.
func TestBuildGroupedHints(t *testing.T) {
	cases := []struct {
		name  string
		infos []backend.BackendInfo
		want  string
	}{
		{
			name:  "empty input",
			infos: nil,
			want:  "",
		},
		{
			name: "single instance, no SpecID — renders individually",
			infos: []backend.BackendInfo{
				{Name: testBackendMemorizer, Hint: testHintLocalMemory},
			},
			want: "memorizer: Local memory store",
		},
		{
			name: "two instances of one DADL spec — collapsed to one line",
			infos: []backend.BackendInfo{
				{Name: testHostDokuWikiCloud, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
				{Name: testHostnameDokuWiki, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
			},
			want: "dokuwiki-dunkel.cloud, dokuwiki-dunkel.io: DokuWiki JSON-RPC API",
		},
		{
			name: "three instances of one DADL spec — alphabetical names",
			infos: []backend.BackendInfo{
				{Name: "opnsense_primary", Hint: testHintOPNsense, SpecID: testCredOPNsense},
				{Name: "opnsense_backup", Hint: testHintOPNsense, SpecID: testCredOPNsense},
				{Name: "opnsense_edge", Hint: testHintOPNsense, SpecID: testCredOPNsense},
			},
			want: "opnsense_backup, opnsense_edge, opnsense_primary: OPNsense REST API",
		},
		{
			name: "two distinct DADL specs — two groups in input order",
			infos: []backend.BackendInfo{
				{Name: testBackendNameGitHub, Hint: "GitHub REST API", SpecID: "sha-gh"},
				{Name: "jira", Hint: "Jira API", SpecID: "sha-jira"},
			},
			want: "github: GitHub REST API; jira: Jira API",
		},
		{
			name: "mix of DADL and native backends",
			infos: []backend.BackendInfo{
				{Name: testHostDokuWikiCloud, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
				{Name: testBackendMemorizer, Hint: testHintLocalMemory},
				{Name: testHostnameDokuWiki, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
				{Name: "web_search", Hint: "Web search"},
			},
			want: "dokuwiki-dunkel.cloud, dokuwiki-dunkel.io: DokuWiki JSON-RPC API; memorizer: Local memory store; web_search: Web search",
		},
		{
			name: "group position follows first instance — second spec appears between native entries",
			infos: []backend.BackendInfo{
				{Name: testBackendMemorizer, Hint: testHintLocalMemory},
				{Name: "opnsense_a", Hint: testHintOPNsense, SpecID: testCredOPNsense},
				{Name: "web_search", Hint: "Web search"},
				{Name: "opnsense_b", Hint: testHintOPNsense, SpecID: testCredOPNsense},
			},
			want: "memorizer: Local memory store; opnsense_a, opnsense_b: OPNsense REST API; web_search: Web search",
		},
		{
			name: "infos without hints are skipped",
			infos: []backend.BackendInfo{
				{Name: testBackendNameGitHub, Hint: "GitHub REST API", SpecID: "sha-gh"},
				{Name: userAnonymous, Hint: ""},
				{Name: "another", Hint: "", SpecID: "sha-anon"},
			},
			want: "github: GitHub REST API",
		},
		{
			name: "empty SpecID is not a grouping key — two native backends with the same hint stay separate",
			infos: []backend.BackendInfo{
				{Name: "alpha", Hint: "shared text"},
				{Name: "beta", Hint: "shared text"},
			},
			want: "alpha: shared text; beta: shared text",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildGroupedHints(tc.infos)
			if got != tc.want {
				t.Errorf("buildGroupedHints() = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestBuildBackendDescription_GroupsSharedSpecs is the integration check: it
// runs through buildBackendDescription end to end and verifies that the
// grouping logic surfaces in the final description string used in the
// execute_code tool description.
func TestBuildBackendDescription_GroupsSharedSpecs(t *testing.T) {
	mb := &summarizingBackend{
		infos: []backend.BackendInfo{
			{Name: testHostDokuWikiCloud, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
			{Name: testHostnameDokuWiki, Hint: testHintDokuWiki, SpecID: testCredDokuWiki},
			{Name: testBackendMemorizer, Hint: testHintLocalMemory},
		},
	}
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)
	desc := h.buildBackendDescription()

	// Every instance name must appear in the "Available backends" line.
	for _, name := range []string{testHostDokuWikiCloud, testHostnameDokuWiki, testBackendMemorizer} {
		if !strings.Contains(desc, name) {
			t.Errorf("description missing backend name %q: %s", name, desc)
		}
	}

	// The DokuWiki hint must appear exactly once, prefixed by the comma-separated instance list.
	wantHint := "dokuwiki-dunkel.cloud, dokuwiki-dunkel.io: DokuWiki JSON-RPC API"
	if !strings.Contains(desc, wantHint) {
		t.Errorf("description missing grouped hint %q: %s", wantHint, desc)
	}
	if strings.Count(desc, testHintDokuWiki) != 1 {
		t.Errorf("DokuWiki hint should appear exactly once, got %d occurrences in: %s",
			strings.Count(desc, testHintDokuWiki), desc)
	}
}

// TestBuildToolList_BackendHintsOnExecuteCodeOnly verifies that the per-backend
// "Available backends: ... Hints: ..." block is appended to the execute_code
// description but not to discover_tools. Duplicating that block on both tools
// costs thousands of context tokens for no information gain, so discover_tools
// must stay minimal. Backend names use a unique prefix so the assertion does
// not collide with example patterns (testBackendNameGitHub, "dokuwiki") that legitimately
// appear in the discover_tools description.
func TestBuildToolList_BackendHintsOnExecuteCodeOnly(t *testing.T) {
	mb := &summarizingBackend{
		infos: []backend.BackendInfo{
			{Name: testToolTmtestAlpha, Hint: testHintBackendAlpha},
			{Name: testToolTmtestBeta, Hint: testHintBackendBeta},
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
	for _, marker := range []string{"Available backends", "Hints:", testToolTmtestAlpha, testToolTmtestBeta, testHintBackendAlpha, testHintBackendBeta} {
		if strings.Contains(discoverDesc, marker) {
			t.Errorf("discover_tools description should not contain %q, got: %s", marker, discoverDesc)
		}
	}

	// execute_code must carry the backend block.
	for _, marker := range []string{"Available backends", "Hints:", testToolTmtestAlpha, testToolTmtestBeta, testHintBackendAlpha, testHintBackendBeta} {
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

// promotingBackend wraps mockTestBackend and also implements
// backend.ToolPromoter so we can test BuildToolList's expose_tools handling.
type promotingBackend struct {
	mockTestBackend
	promoted []backend.ToolDescriptor
}

func (p *promotingBackend) PromotedTools() []backend.ToolDescriptor { return p.promoted }

// TestBuildToolList_PromotedToolsAppended verifies that backends opting into
// expose_tools surface their promoted tools at the MCP root in addition to
// discover_tools and execute_code. The promoted descriptors must be passed
// through unchanged so the LLM sees the real input schema and description.
func TestBuildToolList_PromotedToolsAppended(t *testing.T) {
	mb := &promotingBackend{
		promoted: []backend.ToolDescriptor{
			{
				Name:        "brave_web_search",
				Description: "Search the web via Brave",
				InputSchema: map[string]any{contentKeyType: jsonTypeObject},
			},
			{
				Name:        "fetch_fetch_url",
				Description: "Fetch a URL",
				InputSchema: map[string]any{contentKeyType: jsonTypeObject},
			},
		},
	}
	h := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)

	tools, err := h.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("BuildToolList: %v", err)
	}

	got := map[string]ToolDefinition{}
	for _, td := range tools {
		got[td.Name] = td
	}

	for _, must := range []string{toolDiscoverTools, toolExecuteCode, "brave_web_search", "fetch_fetch_url"} {
		if _, ok := got[must]; !ok {
			t.Errorf("missing tool %q in BuildToolList output: %v", must, keysOf(got))
		}
	}

	if d := got["brave_web_search"]; d.Description != "Search the web via Brave" {
		t.Errorf("promoted description not propagated: %q", d.Description)
	}
}

// TestBuildToolList_NoPromoterMeansNoPromotedTools verifies that backends not
// implementing ToolPromoter add nothing — the default surface stays discover/exec.
func TestBuildToolList_NoPromoterMeansNoPromotedTools(t *testing.T) {
	h := NewHandler(nil, &mockTestBackend{}, nil, "", nil, newQuietMCPLogger(), false)
	tools, err := h.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("BuildToolList: %v", err)
	}
	if len(tools) != 2 {
		t.Errorf("expected 2 tools (discover_tools, execute_code), got %d: %v", len(tools), tools)
	}
}

func keysOf(m map[string]ToolDefinition) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
