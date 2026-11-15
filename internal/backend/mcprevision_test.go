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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// mcpHelperVar switches TestHelperMCPServer from a skipped test into a
	// child process that is an MCP server of the handshake generation.
	mcpHelperVar = "TOOLMESH_TEST_MCP_SERVER"
	// A server that says nothing to a request before initialize.
	mcpHelperSilent = "silent"
	// A server that ends on a request before initialize.
	mcpHelperClosing = "closing"

	testRevisionStateless = "2026-07-28"
	testHeaderRegion      = "Mcp-Param-Region"
	testToolQuery         = "query"
	testToolAsk           = "ask"
	testMethodInitialize  = "initialize"
	testMethodToolsList   = "tools/list"
	testMethodToolsCall   = "tools/call"

	// Answers of the helper process and of statelessFake, as the JSON that
	// goes into the "result" or "error" of the JSON-RPC answer.
	helperInitializeResult = `{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"helper","version":"1"}}`
	helperToolsResult      = `{"tools":[{"name":"query","description":"a tool","inputSchema":{"type":"object"}}]}`
	helperCallResult       = `{"content":[{"type":"text","text":"ok"}]}`
	helperMethodNotFound   = `{"code":-32601,"message":"Method not found"}`

	fakeDiscoverResult = `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}`
	fakeToolsResult    = `{"resultType":"complete","ttlMs":0,"cacheScope":"private","tools":[
		{"name":"query","description":"runs a query in a region","inputSchema":{"type":"object","properties":{
			"region":{"type":"string","x-mcp-header":"Region"},
			"sql":{"type":"string"}}}},
		{"name":"ask","description":"asks the client","inputSchema":{"type":"object"}}]}`
	fakeCallResult  = `{"resultType":"complete","content":[{"type":"text","text":"done"}]}`
	fakeInputResult = `{"resultType":"input_required","requestState":"opaque","inputRequests":{"who":{
		"method":"elicitation/create",
		"params":{"mode":"form","message":"Who are you?","requestedSchema":{"type":"object","properties":{"name":{"type":"string"}}}}}}}`
)

// rpcAnswer builds a JSON-RPC answer from the id of the request and the
// JSON of its result or error.
func rpcAnswer(id json.RawMessage, field, value string) string {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,%q:%s}`, id, field, value)
}

// TestHelperMCPServer is the child process of the stdio tests: a minimal
// MCP server that knows the initialize handshake only.
func TestHelperMCPServer(t *testing.T) {
	mode := os.Getenv(mcpHelperVar)
	if mode == "" {
		t.Skip("child process for the stdio revision tests")
	}
	initialized := false
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			continue
		}
		if msg.Method == testMethodInitialize {
			initialized = true
			fmt.Println(rpcAnswer(msg.ID, "result", helperInitializeResult))
			continue
		}
		if !initialized {
			if mode == mcpHelperClosing {
				os.Exit(1)
			}
			continue
		}
		if len(msg.ID) == 0 {
			continue
		}
		switch msg.Method {
		case testMethodToolsList:
			fmt.Println(rpcAnswer(msg.ID, "result", helperToolsResult))
		case testMethodToolsCall:
			fmt.Println(rpcAnswer(msg.ID, "result", helperCallResult))
		default:
			fmt.Println(rpcAnswer(msg.ID, "error", helperMethodNotFound))
		}
	}
	os.Exit(0)
}

// helperStdioAdapter returns an adapter with one stdio backend whose child
// is TestHelperMCPServer in the given mode.
func helperStdioAdapter(t *testing.T, mode string, logs io.Writer) *MCPAdapter {
	t.Helper()
	t.Setenv(mcpHelperVar, mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	adapter := NewMCPAdapterFromEntries([]BackendEntry{{
		Name:      testBackendNameTest,
		Transport: transportTypeSTDIO,
		Command:   exe,
		Args:      []string{"-test.run=^TestHelperMCPServer$"},
	}}, credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(adapter.Close)
	return adapter
}

// A stdio server of the older generation that ends on a request before
// initialize, or says nothing to it, is still connected: the handshake is
// tried again with a process of its own, and a reconnect goes straight to
// it.
func TestMCPAdapter_StdioFallsBackToHandshake(t *testing.T) {
	for _, mode := range []string{mcpHelperClosing, mcpHelperSilent} {
		t.Run(mode, func(t *testing.T) {
			var logs bytes.Buffer
			adapter := helperStdioAdapter(t, mode, &logs)
			if mode == mcpHelperSilent {
				adapter.probeTimeout = 3 * time.Second
			}
			ctx := context.Background()

			if err := adapter.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			conn := adapter.backends[testBackendNameTest]
			if conn.session == nil {
				t.Fatalf("backend not connected:\n%s", logs.String())
			}
			if got := sessionRevision(conn.session); got != mcpRevisionHandshake {
				t.Errorf("revision = %q, want %q", got, mcpRevisionHandshake)
			}
			if !conn.handshakeOnly {
				t.Error("the backend is not remembered as one that needs the handshake")
			}

			result, err := adapter.Execute(ctx, testBackendNameTest+"_"+testToolQuery, map[string]any{})
			if err != nil || result.IsError {
				t.Fatalf("call failed: %v %+v", err, result)
			}

			// The reconnect asks for the handshake at once: it is done long
			// before the first attempt of a new connect would have given up.
			start := time.Now()
			if err := adapter.reconnectBackend(ctx, testBackendNameTest); err != nil {
				t.Fatalf("reconnect: %v", err)
			}
			if mode == mcpHelperSilent && time.Since(start) >= adapter.probeTimeout {
				t.Errorf("reconnect took %s, as long as a new probe", time.Since(start))
			}
			if got := sessionRevision(adapter.backends[testBackendNameTest].session); got != mcpRevisionHandshake {
				t.Errorf("revision after reconnect = %q", got)
			}
		})
	}
}

// statelessFake is an MCP server of revision 2026-07-28 only, written by
// hand: it has no initialize. It records what the adapter sends.
type statelessFake struct {
	mu       sync.Mutex
	headers  map[string]http.Header
	lastMeta map[string]any
}

func (f *statelessFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
		Params struct {
			Name string         `json:"name"`
			Meta map[string]any `json:"_meta"`
		} `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	if f.headers == nil {
		f.headers = make(map[string]http.Header)
	}
	key := req.Method
	if req.Params.Name != "" {
		key += " " + req.Params.Name
	}
	f.headers[key] = r.Header.Clone()
	f.lastMeta = req.Params.Meta
	f.mu.Unlock()

	status, field, value := http.StatusOK, "result", ""
	switch {
	case req.Method == "server/discover":
		value = fakeDiscoverResult
	case req.Method == testMethodToolsList:
		value = fakeToolsResult
	case req.Method == testMethodToolsCall && req.Params.Name == testToolAsk:
		value = fakeInputResult
	case req.Method == testMethodToolsCall:
		value = fakeCallResult
	default:
		status, field, value = http.StatusNotFound, "error", helperMethodNotFound
	}
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, rpcAnswer(req.ID, field, value))
}

func (f *statelessFake) header(key, name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.headers[key].Get(name)
}

// newStatelessAdapter connects an adapter to a statelessFake.
func newStatelessAdapter(t *testing.T, logs io.Writer) (*MCPAdapter, *statelessFake) {
	t.Helper()
	fake := &statelessFake{}
	ts := httptest.NewServer(fake)
	t.Cleanup(ts.Close)

	adapter := NewMCPAdapterFromEntries([]BackendEntry{{
		Name:      testBackendNameTest,
		Transport: transportTypeHTTP,
		URL:       ts.URL + "/mcp",
	}}, credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(adapter.Close)
	if err := adapter.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if adapter.backends[testBackendNameTest].session == nil {
		t.Fatal("backend not connected")
	}
	return adapter, fake
}

// queryArgs are the arguments of the fake's query tool; the region is the
// parameter the fake wants repeated in a header.
func queryArgs() map[string]any {
	var args map[string]any
	_ = json.Unmarshal([]byte(`{"region":"eu-1","sql":"select 1"}`), &args)
	return args
}

// The adapter connects to a server that has no initialize at all, in the
// stateless revision, and announces none of the client features.
func TestMCPAdapter_StatelessServer(t *testing.T) {
	var logs bytes.Buffer
	adapter, fake := newStatelessAdapter(t, &logs)

	if got := sessionRevision(adapter.backends[testBackendNameTest].session); got != testRevisionStateless {
		t.Errorf("revision = %q, want %q:\n%s", got, testRevisionStateless, logs.String())
	}
	if fake.header(testMethodInitialize, "Content-Type") != "" {
		t.Error("the adapter sent initialize although the server answered server/discover")
	}

	result, err := adapter.Execute(context.Background(), testBackendNameTest+"_"+testToolQuery, queryArgs())
	if err != nil || result.IsError {
		t.Fatalf("call failed: %v %+v", err, result)
	}

	call := testMethodToolsCall + " " + testToolQuery
	if got := fake.header(call, "Mcp-Method"); got != testMethodToolsCall {
		t.Errorf("Mcp-Method = %q", got)
	}
	if got := fake.header(call, "Mcp-Name"); got != testToolQuery {
		t.Errorf("Mcp-Name = %q", got)
	}
	if got := fake.header(call, "Mcp-Protocol-Version"); got != testRevisionStateless {
		t.Errorf("MCP-Protocol-Version = %q", got)
	}

	fake.mu.Lock()
	caps, ok := fake.lastMeta["io.modelcontextprotocol/clientCapabilities"].(map[string]any)
	fake.mu.Unlock()
	if !ok {
		t.Fatalf("request carried no client capabilities: %v", fake.lastMeta)
	}
	if len(caps) != 0 {
		t.Errorf("client capabilities = %v, want none: ToolMesh offers a server neither roots nor sampling nor elicitation", caps)
	}
}

// The keyword with which a backend asks for a parameter in an HTTP header
// is honored towards the backend and not passed on to callers of ToolMesh.
func TestMCPAdapter_HeaderAnnotationStaysOnTheBackendHop(t *testing.T) {
	adapter, fake := newStatelessAdapter(t, io.Discard)
	ctx := context.Background()

	tools, err := adapter.ListTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	listed := ""
	for _, tool := range tools {
		if tool.Name == testBackendNameTest+"_"+testToolQuery {
			raw, _ := json.Marshal(tool.InputSchema)
			listed = string(raw)
		}
	}
	if !strings.Contains(listed, `"region"`) {
		t.Fatalf("tool or parameter not listed: %v", tools)
	}
	if strings.Contains(listed, schemaKeyHeaderAnnotation) {
		t.Errorf("the listed schema still carries %s: %s", schemaKeyHeaderAnnotation, listed)
	}

	if _, err := adapter.Execute(ctx, testBackendNameTest+"_"+testToolQuery, queryArgs()); err != nil {
		t.Fatal(err)
	}
	if got := fake.header(testMethodToolsCall+" "+testToolQuery, testHeaderRegion); got != "eu-1" {
		t.Errorf("%s sent to the backend = %q, want eu-1", testHeaderRegion, got)
	}
}

// A backend that answers a call by asking the client for input gets no
// input: the caller is told so, and the backend is flagged once.
func TestMCPAdapter_InputRequiredIsAnError(t *testing.T) {
	var logs bytes.Buffer
	adapter, _ := newStatelessAdapter(t, &logs)
	ctx := context.Background()

	for i := 0; i < 2; i++ {
		result, err := adapter.Execute(ctx, testBackendNameTest+"_"+testToolAsk, map[string]any{})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		if !result.IsError {
			t.Fatalf("result is no error: %+v", result)
		}
		text := fmt.Sprint(result.Content)
		if !strings.Contains(text, mcpMethodElicitation) {
			t.Errorf("the error does not name what was asked for: %s", text)
		}
	}
	if n := strings.Count(logs.String(), "backend asked its client for input"); n != 1 {
		t.Errorf("flagged %d times, want once:\n%s", n, logs.String())
	}
}

func TestInputRequiredResult_NoRequests(t *testing.T) {
	var result mcp.CallToolResult
	if err := json.Unmarshal([]byte(`{"resultType":"input_required","requestState":"s"}`), &result); err != nil {
		t.Fatal(err)
	}
	if !result.NeedsInput() {
		t.Fatal("result does not need input")
	}
	adapter := newEmptyMCPAdapter(credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	out := adapter.inputRequiredResult("b", "t", &result)
	if !out.IsError || !strings.Contains(fmt.Sprint(out.Content), "sent again") {
		t.Errorf("unexpected result: %+v", out)
	}
}

func TestStripHeaderAnnotations(t *testing.T) {
	// The second property has the name of the keyword and stays.
	const in = `{
		"type": "object",
		"x-mcp-header": "Root",
		"properties": {
			"region": {"type": "string", "x-mcp-header": "Region"},
			"x-mcp-header": {"type": "string"},
			"inner": {"type": "object", "properties": {"tenant": {"type": "string", "x-mcp-header": "Tenant"}}},
			"many": {"items": {"type": "string", "x-mcp-header": "Item"}}
		},
		"anyOf": [{"properties": {"a": {"x-mcp-header": "A"}}}],
		"$defs": {"d": {"x-mcp-header": "D"}}
	}`
	const want = `{
		"type": "object",
		"properties": {
			"region": {"type": "string"},
			"x-mcp-header": {"type": "string"},
			"inner": {"type": "object", "properties": {"tenant": {"type": "string"}}},
			"many": {"items": {"type": "string"}}
		},
		"anyOf": [{"properties": {"a": {}}}],
		"$defs": {"d": {}}
	}`
	var schema, expected map[string]any
	if err := json.Unmarshal([]byte(in), &schema); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatal(err)
	}
	stripHeaderAnnotations(schema)
	if !reflect.DeepEqual(schema, expected) {
		t.Errorf("stripped schema:\n got %v\nwant %v", schema, expected)
	}

	// A schema nested deeper than any real one does not run away.
	deep := map[string]any{}
	cur := deep
	for i := 0; i < 10*maxSchemaDepth; i++ {
		next := map[string]any{}
		cur[schemaKeyAdditionalProperties] = next
		cur = next
	}
	stripHeaderAnnotations(deep)
	stripHeaderAnnotations(nil)
}

// What a deprecated part of MCP is reported for is reported once per
// backend, not on every reconnect.
func TestMCPAdapter_FlagOnce(t *testing.T) {
	adapter := newEmptyMCPAdapter(credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !adapter.flagOnce("a", mcpMethodSampling) {
		t.Error("first flag not reported")
	}
	if adapter.flagOnce("a", mcpMethodSampling) {
		t.Error("second flag reported again")
	}
	if !adapter.flagOnce("b", mcpMethodSampling) || !adapter.flagOnce("a", mcpFeatureSSETransport) {
		t.Error("another backend or feature was not reported")
	}
}

func TestUsesSSETransport(t *testing.T) {
	tests := []struct {
		entry BackendEntry
		want  bool
	}{
		{BackendEntry{Transport: transportTypeHTTP, URL: "https://mcp.example.com/sse"}, true},
		{BackendEntry{Transport: transportTypeHTTP, URL: testMCPURLExample}, false},
		{BackendEntry{Transport: transportTypeSTDIO, Command: "/sse"}, false},
	}
	for _, tt := range tests {
		if got := usesSSETransport(tt.entry); got != tt.want {
			t.Errorf("usesSSETransport(%+v) = %v, want %v", tt.entry, got, tt.want)
		}
	}
}

// The tools of several backends, their summaries and their promoted tools
// come out in the same order on every call.
func TestMCPAdapter_ListingOrderIsStable(t *testing.T) {
	adapter := newEmptyMCPAdapter(credentials.NewEmbeddedStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, name := range []string{"zeta", "alpha", "mid", "beta", "omega", "gamma"} {
		adapter.backends[name] = &backendConn{
			entry: BackendEntry{Name: name, Transport: transportTypeHTTP, ExposeTools: []string{"t"}},
			tools: []ToolDescriptor{{Name: "t"}},
		}
	}
	wantOrder := []string{"alpha", "beta", "gamma", "mid", "omega", "zeta"}

	for i := 0; i < 20; i++ {
		tools, _ := adapter.ListTools(context.Background())
		summaries := adapter.BackendSummaries()
		promoted := adapter.PromotedTools()
		for j, name := range wantOrder {
			if tools[j].Name != name+"_t" || summaries[j].Name != name || promoted[j].Canonical != name+"_t" {
				t.Fatalf("run %d, position %d: got %s / %s / %s, want %s",
					i, j, tools[j].Name, summaries[j].Name, promoted[j].Canonical, name)
			}
		}
	}
}
