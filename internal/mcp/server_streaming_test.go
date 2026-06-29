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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// decodeJSONMap unmarshals a JSON object string into a map, failing the test on
// error.
func decodeJSONMap(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decode JSON %q: %v", s, err)
	}
	return m
}

// extractSSEData returns the JSON payload of the single SSE "data:" line in an
// event-stream body.
func extractSSEData(t *testing.T, body string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, "data: "); ok {
			return rest
		}
	}
	t.Fatalf("no SSE data line in body: %q", body)
	return ""
}

// When the client advertises SSE, a tools/call is delivered as a text/event-stream
// whose final "message" event carries the JSON-RPC result.
func TestServer_MCP_ToolsCall_SSE(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"test:tool","arguments":{}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	out := w.Body.String()
	if !strings.Contains(out, "event: message") {
		t.Errorf("body missing SSE message event: %q", out)
	}

	resp := decodeJSONMap(t, extractSSEData(t, out))
	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	if resp["id"].(float64) != 7 {
		t.Errorf("id = %v, want 7", resp["id"])
	}
	if _, ok := resp["result"].(map[string]any); !ok {
		t.Errorf("missing result object: %v", resp["result"])
	}
}

// A client that does not advertise SSE gets a buffered JSON response.
func TestServer_MCP_ToolsCall_JSONFallback(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"test:tool","arguments":{}}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	if strings.Contains(w.Body.String(), "event: message") {
		t.Errorf("non-SSE client should not receive an event-stream body: %q", w.Body.String())
	}
	resp := decodeJSONMap(t, w.Body.String())
	if resp["error"] != nil {
		t.Fatalf("unexpected error: %v", resp["error"])
	}
	if _, ok := resp["result"].(map[string]any); !ok {
		t.Errorf("missing result object: %v", resp["result"])
	}
}

func TestAcceptsSSE(t *testing.T) {
	tests := []struct {
		accept string
		want   bool
	}{
		{"application/json, text/event-stream", true},
		{"text/event-stream", true},
		{"application/json", false},
		{"*/*", false},
		{"", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
		if tt.accept != "" {
			r.Header.Set("Accept", tt.accept)
		}
		if got := acceptsSSE(r); got != tt.want {
			t.Errorf("acceptsSSE(%q) = %v, want %v", tt.accept, got, tt.want)
		}
	}
}

func TestToolCallErrorMessage(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{context.DeadlineExceeded, "Tool call timed out before the backend responded"},
		{context.Canceled, "Tool call was canceled"},
		{errStub("boom"), "Internal error"},
	}
	for _, tt := range tests {
		if got := toolCallErrorMessage(tt.err); got != tt.want {
			t.Errorf("toolCallErrorMessage(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

type errStub string

func (e errStub) Error() string { return string(e) }
