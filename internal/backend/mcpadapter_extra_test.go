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

package backend

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPAdapter_Close_NoSessions(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{},
		logger:   slog.Default(),
	}
	// Does nothing but should not panic.
	a.Close()
}

func TestMCPAdapter_BackendSummaries_Empty(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{},
		logger:   slog.Default(),
	}
	if infos := a.BackendSummaries(); len(infos) != 0 {
		t.Errorf("expected empty, got %d", len(infos))
	}
}

func TestMCPAdapter_BackendSummaries_WithBackends(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			"b1": {entry: BackendEntry{Name: "b1", Hint: "hint-1"}},
		},
		logger: slog.Default(),
	}
	infos := a.BackendSummaries()
	if len(infos) != 1 || infos[0].Name != "b1" || infos[0].Hint != "hint-1" {
		t.Errorf("unexpected infos: %v", infos)
	}
}

func TestMCPAdapter_MatchBackend(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			testBackendNameGitHub: {entry: BackendEntry{Name: testBackendNameGitHub}},
		},
	}
	name, tool, conn := a.matchBackend("github_create_issue")
	if name != testBackendNameGitHub || tool != "create_issue" || conn == nil {
		t.Errorf("match failed: %s %s %v", name, tool, conn)
	}

	name2, _, conn2 := a.matchBackend("unmatched_tool")
	if conn2 != nil || name2 != "" {
		t.Errorf("expected no match, got %s %v", name2, conn2)
	}
}

func TestMCPAdapter_RegisterTools_Extra(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			"b1": {entry: BackendEntry{Name: "b1"}, tools: []ToolDescriptor{}},
		},
		logger: slog.Default(),
	}
	a.RegisterTools("b1", []ToolDescriptor{{Name: "t1"}})
	if len(a.backends["b1"].tools) != 1 {
		t.Error("RegisterTools did not update")
	}
}

func TestMCPAdapter_PromotedTools_BareNameAndCanonical(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			testVendorBrave: {
				entry: BackendEntry{Name: testVendorBrave, ExposeTools: []string{testToolWebSearch, "missing"}},
				tools: []ToolDescriptor{
					{Name: testToolWebSearch, Description: testDescWebSearch, InputSchema: map[string]any{"type": "object"}, Access: accessRead},
					{Name: "summarize", Description: "summarize text"},
				},
			},
			"other": {
				entry: BackendEntry{Name: "other"}, // no expose_tools
				tools: []ToolDescriptor{{Name: "noop"}},
			},
		},
		logger: slog.Default(),
	}

	got := a.PromotedTools()
	if len(got) != 1 {
		t.Fatalf("got %d promoted tools, want 1 (missing entry should be skipped)", len(got))
	}
	if got[0].Descriptor.Name != testToolWebSearch {
		t.Errorf("public name = %q, want bare %q", got[0].Descriptor.Name, testToolWebSearch)
	}
	if got[0].Canonical != "brave_"+testToolWebSearch {
		t.Errorf("canonical = %q, want %q", got[0].Canonical, "brave_"+testToolWebSearch)
	}
	if got[0].Descriptor.Description != testDescWebSearch {
		t.Errorf("description = %q", got[0].Descriptor.Description)
	}
	if got[0].Descriptor.Backend != "mcp:brave" {
		t.Errorf("backend = %q, want mcp:brave", got[0].Descriptor.Backend)
	}
	if got[0].Descriptor.Access != accessRead {
		t.Errorf("access = %q, want %q (carried from upstream descriptor)", got[0].Descriptor.Access, accessRead)
	}
}

// TestMCPAdapter_PromotedTools_BareNameWhenBackendEqualsTool: when a backend
// is named after its single primary tool, the public surface still uses the
// bare name (no "<backend>_<tool>" prefix in the wire form). Canonical
// carries the doubled-up "<backend>_<tool>" form for routing.
func TestMCPAdapter_PromotedTools_BareNameWhenBackendEqualsTool(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			testToolWebSearch: {
				entry: BackendEntry{Name: testToolWebSearch, ExposeTools: []string{testToolWebSearch}},
				tools: []ToolDescriptor{{Name: testToolWebSearch, Description: testDescWebSearch}},
			},
		},
		logger: slog.Default(),
	}
	got := a.PromotedTools()
	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if got[0].Descriptor.Name != testToolWebSearch {
		t.Errorf("public name = %q, want bare %q", got[0].Descriptor.Name, testToolWebSearch)
	}
	wantCanonical := testToolWebSearch + "_" + testToolWebSearch
	if got[0].Canonical != wantCanonical {
		t.Errorf("canonical = %q, want %q", got[0].Canonical, wantCanonical)
	}
}

func TestMCPAdapter_PromotedTools_EmptyWhenNoExpose(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			"b1": {
				entry: BackendEntry{Name: "b1"},
				tools: []ToolDescriptor{{Name: "t1"}},
			},
		},
		logger: slog.Default(),
	}
	if got := a.PromotedTools(); len(got) != 0 {
		t.Errorf("expected no promoted tools, got %d", len(got))
	}
}

func TestBearerTransport_RoundTrip(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get(testHeaderAuth)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	bt := &bearerTransport{base: http.DefaultTransport, token: "secret"}
	client := &http.Client{Transport: bt}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if gotAuth != "Bearer secret" {
		t.Errorf("Authorization = %q", gotAuth)
	}
}

func TestEnvDuration(t *testing.T) {
	t.Setenv("TEST_DURATION", "45")
	if got := envDuration("TEST_DURATION", time.Second); got != 45*time.Second {
		t.Errorf("got %v, want 45s", got)
	}

	t.Setenv("TEST_DURATION", "bad")
	if got := envDuration("TEST_DURATION", 10*time.Second); got != 10*time.Second {
		t.Errorf("bad duration: got %v", got)
	}

	// Unset.
	if got := envDuration("THIS_DOES_NOT_EXIST_XYZ", 5*time.Second); got != 5*time.Second {
		t.Errorf("missing var: got %v", got)
	}
}

func TestMCPAdapter_CreateTransport_Unsupported(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default(), creds: credentials.NewEmbeddedStore()}
	_, err := a.createTransport(context.Background(), BackendEntry{Transport: "unknown"})
	if err == nil {
		t.Error("expected error for unknown transport")
	}
}

func TestMCPAdapter_CreateSTDIOTransport_MissingCommand(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default()}
	_, err := a.createSTDIOTransport(context.Background(), BackendEntry{})
	if err == nil {
		t.Error("expected error for missing command")
	}
}

func TestMCPAdapter_CreateSTDIOTransport_OK(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default()}
	_, err := a.createSTDIOTransport(context.Background(), BackendEntry{Command: "echo", Args: []string{"hi"}})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPAdapter_Execute_NoSuchTool(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{},
		logger:   slog.Default(),
	}
	_, err := a.Execute(context.Background(), "unknown_tool", nil)
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}

func TestMCPAdapter_Execute_NotConnected_Extra(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{
			"b": {entry: BackendEntry{Name: "b"}},
		},
		logger: slog.Default(),
	}
	_, err := a.Execute(context.Background(), "b_tool", nil)
	if err == nil {
		t.Error("expected error for unconnected backend")
	}
}

func TestMCPAdapter_HTTPTransport_BuiltWithAPIKey(t *testing.T) {
	t.Setenv("CREDENTIAL_MY_KEY", "tok-value")
	a := &MCPAdapter{
		logger: slog.Default(),
		creds:  credentials.NewEmbeddedStore(),
	}
	_, err := a.createHTTPTransport(context.Background(), BackendEntry{
		Transport: transportTypeHTTP,
		URL:       testMCPURLExample,
		APIKeyEnv: "MY_KEY",
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMCPAdapter_HTTPTransport_SSE(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default(), creds: credentials.NewEmbeddedStore()}
	tr, err := a.createHTTPTransport(context.Background(), BackendEntry{
		URL: "https://example.com/sse",
	})
	if err != nil {
		t.Fatal(err)
	}
	if tr == nil {
		t.Error("expected non-nil transport")
	}
}

func TestMCPAdapter_HTTPTransport_MissingCredential(t *testing.T) {
	a := &MCPAdapter{logger: slog.Default(), creds: credentials.NewEmbeddedStore()}
	_, err := a.createHTTPTransport(context.Background(), BackendEntry{
		URL:       testMCPURLExample,
		APIKeyEnv: "NONEXISTENT_KEY_XYZ",
	})
	if err == nil {
		t.Error("expected error for missing credential")
	}
}

func TestIsConnectionClosed(t *testing.T) {
	tests := []struct {
		err  string
		want bool
	}{
		{"connection closed: calling \"tools/call\": client is closing", true},
		{"client is closing: sending \"tools/call\"", true},
		{"write: broken pipe", true},
		{"read: connection reset by peer", true},
		{"use of closed network connection", true},
		{"timeout waiting for response", false},
		{"backend returned 500", false},
	}
	for _, tt := range tests {
		if got := isConnectionClosed(fmt.Errorf("%s", tt.err)); got != tt.want {
			t.Errorf("isConnectionClosed(%q) = %v, want %v", tt.err, got, tt.want)
		}
	}
	if isConnectionClosed(nil) {
		t.Error("isConnectionClosed(nil) should be false")
	}
}

func TestMCPAdapter_ReconnectBackend_NotFound(t *testing.T) {
	a := &MCPAdapter{
		backends: map[string]*backendConn{},
		logger:   slog.Default(),
	}
	if err := a.reconnectBackend(context.Background(), "missing"); err == nil {
		t.Error("expected error for missing backend")
	}
}

func TestMCPAdapter_ReconnectBackend_ClosesOldSession(t *testing.T) {
	ctx := context.Background()

	// Create a real in-memory MCP session so we have a non-nil session to close.
	server := mcp.NewServer(&mcp.Implementation{Name: "srv", Version: testVersion01}, nil)
	ct, st := mcp.NewInMemoryTransports()
	go server.Connect(ctx, st, nil) //nolint:errcheck

	client := mcp.NewClient(&mcp.Implementation{Name: "tm", Version: testVersion01}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			testBackendNameTest: {
				entry: BackendEntry{
					Name:      testBackendNameTest,
					Transport: transportTypeHTTP,
					URL:       "https://192.0.2.1/mcp", // unroutable, connect will fail
				},
				session: session,
			},
		},
		logger: slog.Default(),
		creds:  credentials.NewEmbeddedStore(),
		client: client,
	}

	// reconnectBackend should close the old session and attempt a new connection.
	// The new connection will fail (unroutable URL), but the old session should
	// be nil'd out, proving the stale session was cleaned up.
	err = adapter.reconnectBackend(ctx, testBackendNameTest)
	if err == nil {
		t.Fatal("expected error from unroutable URL, got nil")
	}

	if adapter.backends[testBackendNameTest].session != nil {
		t.Error("expected old session to be nil after failed reconnect")
	}
}
