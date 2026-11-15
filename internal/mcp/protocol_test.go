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
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

const (
	// testCountedTool is a tool of countingBackend: calling it is what the
	// tests watch for.
	testCountedTool = "counted_tool"

	// What a client sends in Accept when it takes an answer as a stream.
	testAcceptStream = "application/json, text/event-stream"
	testHeaderOrigin = "Origin"

	// testStatelessMeta is the _meta a client of revision 2026-07-28 sends
	// with every request.
	testStatelessMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}`
)

// countingBackend counts the tool calls that reach it.
type countingBackend struct {
	calls atomic.Int32
}

func (b *countingBackend) Execute(context.Context, string, map[string]any) (*backend.ToolResult, error) {
	b.calls.Add(1)
	return &backend.ToolResult{
		Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ran"}},
	}, nil
}

func (b *countingBackend) ListTools(context.Context) ([]backend.ToolDescriptor, error) {
	return []backend.ToolDescriptor{{Name: testCountedTool, Description: "counts its calls"}}, nil
}

func (b *countingBackend) Healthy(context.Context) error { return nil }

// newProtocolTestServer returns a server whose tool calls reach a
// countingBackend, with the metrics registry it records to.
func newProtocolTestServer(t *testing.T, cfg *config.Config) (*http.ServeMux, *countingBackend, *metrics.Registry) {
	t.Helper()
	logger := newQuietMCPLogger()
	cb := &countingBackend{}
	exec := executor.New(nil, nil, cb, nil, nil, 30*time.Second, logger, nil, nil)
	handler := NewHandler(exec, cb, nil, "", nil, logger, false)
	reg := metrics.New(metrics.Options{LabelTool: true})
	srv := NewServer(handler, cfg, logger, nil, nil, nil, nil, nil, reg)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)
	return mux, cb, reg
}

// mcpPost sends one JSON-RPC body to the MCP endpoint with the given
// headers. A header value of "" is not set; values separated by "\n" are
// sent as several header lines.
func mcpPost(t *testing.T, mux *http.ServeMux, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	authorize(req)
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		if value == "" {
			continue
		}
		for _, line := range strings.Split(value, "\n") {
			req.Header.Add(name, line)
		}
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// statelessHeaders are the headers a client of revision 2026-07-28 sends
// for a method and, on tools/call, a tool name.
func statelessHeaders(method, name string) map[string]string {
	return map[string]string{
		headerProtocolVersion: protocolVersion20260728,
		headerMethod:          method,
		headerName:            name,
	}
}

// requestSeries returns the series of toolmesh_mcp_requests_total as the
// metrics endpoint prints them, sorted.
func requestSeries(t *testing.T, reg *metrics.Registry) []string {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	var series []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "toolmesh_mcp_requests_total{") {
			series = append(series, line)
		}
	}
	slices.Sort(series)
	return series
}

func decodeRPC(t *testing.T, w *httptest.ResponseRecorder) (result map[string]any, rpcErr map[string]any) {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v (%q)", err, w.Body.String())
	}
	result, _ = resp["result"].(map[string]any)
	rpcErr, _ = resp[outcomeError].(map[string]any)
	return result, rpcErr
}

func TestStateless_Discover(t *testing.T) {
	mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})

	w := mcpPost(t, mux,
		`{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{`+testStatelessMeta+`}}`,
		statelessHeaders(methodDiscover, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	result, _ := decodeRPC(t, w)
	if result == nil {
		t.Fatalf("no result: %s", w.Body.String())
	}
	if result[resultKeyResultType] != resultTypeComplete {
		t.Errorf("resultType = %v, want complete", result[resultKeyResultType])
	}
	versions, _ := result["supportedVersions"].([]any)
	if len(versions) != 2 || versions[0] != protocolVersion20260728 || versions[1] != protocolVersion20251125 {
		t.Errorf("supportedVersions = %v", versions)
	}
	if _, ok := result["capabilities"].(map[string]any)["tools"]; !ok {
		t.Errorf("capabilities lack tools: %v", result["capabilities"])
	}
	if ttl, _ := result[resultKeyTTL].(float64); ttl <= 0 {
		t.Errorf("ttlMs = %v, want > 0", result[resultKeyTTL])
	}
	if result[resultKeyCacheScope] != cacheScopePrivate {
		t.Errorf("cacheScope = %v, want private", result[resultKeyCacheScope])
	}
	info, _ := result[metaKey].(map[string]any)[metaKeyServerInfo].(map[string]any)
	if info[jsonKeyName] != "toolmesh" {
		t.Errorf("serverInfo = %v", info)
	}
}

func TestStateless_ToolsList(t *testing.T) {
	mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})

	w := mcpPost(t, mux,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+testStatelessMeta+`}}`,
		statelessHeaders(methodToolsList, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	result, _ := decodeRPC(t, w)
	if tools, _ := result["tools"].([]any); len(tools) == 0 {
		t.Fatalf("no tools: %s", w.Body.String())
	}
	if result[resultKeyResultType] != resultTypeComplete {
		t.Errorf("resultType = %v", result[resultKeyResultType])
	}
	// The list is filtered by what the caller may use: it must never be
	// offered to a cache that several callers share.
	if result[resultKeyCacheScope] != cacheScopePrivate {
		t.Errorf("cacheScope = %v, want private", result[resultKeyCacheScope])
	}
	if _, ok := result[resultKeyTTL].(float64); !ok {
		t.Errorf("ttlMs missing: %v", result)
	}
}

func TestStateless_ToolsCall(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + testCountedTool + `","arguments":{},` + testStatelessMeta + `}}`

	t.Run("json", func(t *testing.T) {
		mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, body, statelessHeaders(methodToolsCall, testCountedTool))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		result, _ := decodeRPC(t, w)
		if result[resultKeyResultType] != resultTypeComplete {
			t.Errorf("resultType = %v", result[resultKeyResultType])
		}
		if _, ok := result[metaKey].(map[string]any)[metaKeyServerInfo]; !ok {
			t.Errorf("result lacks serverInfo: %v", result)
		}
		if got := cb.calls.Load(); got != 1 {
			t.Errorf("backend calls = %d, want 1", got)
		}
	})

	t.Run("sse", func(t *testing.T) {
		mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		headers := statelessHeaders(methodToolsCall, testCountedTool)
		headers["Accept"] = testAcceptStream
		w := mcpPost(t, mux, body, headers)
		if ct := w.Header().Get("Content-Type"); ct != mimeEventStream {
			t.Fatalf("Content-Type = %q, want an event stream: %s", ct, w.Body.String())
		}
		messages := sseMessages(t, w.Body.String())
		if len(messages) != 1 {
			t.Fatalf("got %d messages, want 1: %s", len(messages), w.Body.String())
		}
		result, _ := messages[0]["result"].(map[string]any)
		if result[resultKeyResultType] != resultTypeComplete {
			t.Errorf("resultType = %v", result[resultKeyResultType])
		}
		if got := cb.calls.Load(); got != 1 {
			t.Errorf("backend calls = %d, want 1", got)
		}
	})

	t.Run("name as base64", func(t *testing.T) {
		mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		// "counted_tool" in Base64 between the sentinel marks.
		w := mcpPost(t, mux, body, statelessHeaders(methodToolsCall, "=?base64?Y291bnRlZF90b29s?="))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d: %s", w.Code, w.Body.String())
		}
		if got := cb.calls.Load(); got != 1 {
			t.Errorf("backend calls = %d, want 1", got)
		}
	})
}

// sseMessages returns the JSON payloads of the message events in an SSE
// body.
func sseMessages(t *testing.T, body string) []map[string]any {
	t.Helper()
	var out []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		data, ok := strings.CutPrefix(scanner.Text(), "data: ")
		if !ok {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			t.Fatalf("SSE data is not JSON: %v (%q)", err, data)
		}
		out = append(out, msg)
	}
	return out
}

// A request whose headers and body do not say the same, or that leaves out
// what the stateless revision requires, is refused before anything of it
// runs. The tools/call cases check that the tool was not called: a proxy
// may have admitted the request by its headers.
func TestStateless_Rejections(t *testing.T) {
	const (
		callBody     = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + testCountedTool + `","arguments":{},` + testStatelessMeta + `}}`
		listBody     = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + testStatelessMeta + `}}`
		noMetaBody   = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + testCountedTool + `","arguments":{}}}`
		futureMeta   = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}`
		noCapsMeta   = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`
		badCapsMeta  = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":"all"}`
		numberedMeta = `"_meta":{"io.modelcontextprotocol/protocolVersion":20260728,"io.modelcontextprotocol/clientCapabilities":{}}`
	)
	call := func(meta string) string {
		return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + testCountedTool + `","arguments":{},` + meta + `}}`
	}

	tests := []struct {
		name       string
		body       string
		headers    map[string]string
		wantStatus int
		wantCode   int
	}{
		{
			name:       "revision in the body, none in the header",
			body:       callBody,
			headers:    map[string]string{headerMethod: methodToolsCall, headerName: testCountedTool},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "revision in the header, none in the body",
			body:       noMetaBody,
			headers:    statelessHeaders(methodToolsCall, testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidParams,
		},
		{
			name: "header and body name different revisions",
			body: callBody,
			headers: map[string]string{
				headerProtocolVersion: protocolVersion20251125, headerMethod: methodToolsCall, headerName: testCountedTool,
			},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name: "revision header sent twice",
			body: callBody,
			headers: map[string]string{
				headerProtocolVersion: protocolVersion20260728 + "\n" + protocolVersion20251125,
				headerMethod:          methodToolsCall, headerName: testCountedTool,
			},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name: "revision the server does not speak",
			body: call(futureMeta),
			headers: map[string]string{
				headerProtocolVersion: "2099-01-01", headerMethod: methodToolsCall, headerName: testCountedTool,
			},
			wantStatus: http.StatusBadRequest, wantCode: codeUnsupportedProtocolVersion,
		},
		{
			name:       "unknown revision in the header only",
			body:       noMetaBody,
			headers:    map[string]string{headerProtocolVersion: "next"},
			wantStatus: http.StatusBadRequest, wantCode: codeUnsupportedProtocolVersion,
		},
		{
			name:       "revision in the body is not a string",
			body:       call(numberedMeta),
			headers:    statelessHeaders(methodToolsCall, testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidParams,
		},
		{
			name:       "no client capabilities",
			body:       call(noCapsMeta),
			headers:    statelessHeaders(methodToolsCall, testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidParams,
		},
		{
			name:       "client capabilities are not an object",
			body:       call(badCapsMeta),
			headers:    statelessHeaders(methodToolsCall, testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeInvalidParams,
		},
		{
			name:       "no Mcp-Method",
			body:       callBody,
			headers:    map[string]string{headerProtocolVersion: protocolVersion20260728, headerName: testCountedTool},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Method names a harmless method, the body calls a tool",
			body:       callBody,
			headers:    statelessHeaders(methodToolsList, testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Method differs in case",
			body:       callBody,
			headers:    statelessHeaders("Tools/Call", testCountedTool),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name: "Mcp-Method sent twice",
			body: callBody,
			headers: map[string]string{
				headerProtocolVersion: protocolVersion20260728,
				headerMethod:          methodToolsCall + "\n" + methodToolsList, headerName: testCountedTool,
			},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "no Mcp-Name on a tool call",
			body:       callBody,
			headers:    statelessHeaders(methodToolsCall, ""),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Name names another tool",
			body:       callBody,
			headers:    statelessHeaders(methodToolsCall, toolDiscoverTools),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name: "Mcp-Name sent twice",
			body: callBody,
			headers: map[string]string{
				headerProtocolVersion: protocolVersion20260728, headerMethod: methodToolsCall,
				headerName: testCountedTool + "\n" + toolDiscoverTools,
			},
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Name with Base64 that does not decode",
			body:       callBody,
			headers:    statelessHeaders(methodToolsCall, "=?base64?***?="),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Name with Base64 of another tool",
			body:       callBody,
			headers:    statelessHeaders(methodToolsCall, "=?base64?ZGlzY292ZXJfdG9vbHM=?="),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "Mcp-Name with a character a header may not carry unencoded",
			body:       callBody,
			headers:    statelessHeaders(methodToolsCall, testCountedTool+"é"),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
		{
			name:       "ping is no method of the stateless revision",
			body:       `{"jsonrpc":"2.0","id":1,"method":"ping","params":{` + testStatelessMeta + `}}`,
			headers:    statelessHeaders(methodPing, ""),
			wantStatus: http.StatusNotFound, wantCode: codeMethodNotFound,
		},
		{
			name:       "initialize is no method of the stateless revision",
			body:       `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{` + testStatelessMeta + `}}`,
			headers:    statelessHeaders(methodInitialize, ""),
			wantStatus: http.StatusNotFound, wantCode: codeMethodNotFound,
		},
		{
			name:       "unknown method",
			body:       `{"jsonrpc":"2.0","id":1,"method":"resources/list","params":{` + testStatelessMeta + `}}`,
			headers:    statelessHeaders("resources/list", ""),
			wantStatus: http.StatusNotFound, wantCode: codeMethodNotFound,
		},
		{
			name:       "tools/list with a wrong Mcp-Method",
			body:       listBody,
			headers:    statelessHeaders(methodDiscover, ""),
			wantStatus: http.StatusBadRequest, wantCode: codeHeaderMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, cb, reg := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
			w := mcpPost(t, mux, tt.body, tt.headers)
			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			_, rpcErr := decodeRPC(t, w)
			if rpcErr == nil {
				t.Fatalf("no JSON-RPC error: %s", w.Body.String())
			}
			if code, _ := rpcErr[oauthCode].(float64); int(code) != tt.wantCode {
				t.Errorf("code = %v, want %d: %s", rpcErr[oauthCode], tt.wantCode, w.Body.String())
			}
			if got := cb.calls.Load(); got != 0 {
				t.Errorf("the tool was called %d times; a refused request must not run", got)
			}
			if tt.wantStatus == http.StatusBadRequest {
				series := requestSeries(t, reg)
				if len(series) != 1 || !strings.Contains(series[0], `protocol="refused"`) {
					t.Errorf("request counter = %v, want the one series of the refused request", series)
				}
			}
		})
	}
}

// The error for a revision the server does not speak names the ones it
// does, so that a client can pick one and send the request again.
func TestStateless_UnsupportedVersionNamesSupported(t *testing.T) {
	mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
	long := strings.Repeat("9", 500)

	w := mcpPost(t, mux,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"`+long+`","io.modelcontextprotocol/clientCapabilities":{}}}}`,
		map[string]string{headerProtocolVersion: long, headerMethod: methodToolsList})
	_, rpcErr := decodeRPC(t, w)
	data, _ := rpcErr["data"].(map[string]any)
	supported, _ := data["supported"].([]any)
	if len(supported) != 2 || supported[0] != protocolVersion20260728 {
		t.Errorf("supported = %v", data["supported"])
	}
	// What the caller sent comes back shortened, not in full.
	if requested, _ := data["requested"].(string); len(requested) > maxEchoedHeaderLen+len("…") {
		t.Errorf("requested is echoed with %d bytes", len(requested))
	}
}

// Requests of the handshake generation are answered as they always were:
// with HTTP 200 for a JSON-RPC error, and without the fields the stateless
// revision adds.
func TestHandshake_Unchanged(t *testing.T) {
	t.Run("initialize", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`, nil)
		result, _ := decodeRPC(t, w)
		if result["protocolVersion"] != protocolVersion20251125 {
			t.Errorf("protocolVersion = %v", result["protocolVersion"])
		}
		if _, ok := result[resultKeyResultType]; ok {
			t.Errorf("a handshake result carries resultType: %v", result)
		}
		if _, ok := result[metaKey]; ok {
			t.Errorf("a handshake result carries _meta: %v", result)
		}
	})

	t.Run("tools/list with the header of an older revision", func(t *testing.T) {
		for _, version := range []string{"", protocolVersion20251125, "2025-06-18", "2025-03-26"} {
			mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
			w := mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{headerProtocolVersion: version})
			result, _ := decodeRPC(t, w)
			if tools, _ := result["tools"].([]any); len(tools) == 0 {
				t.Fatalf("version %q: no tools: %s", version, w.Body.String())
			}
			for _, key := range []string{resultKeyResultType, resultKeyTTL, resultKeyCacheScope, metaKey} {
				if _, ok := result[key]; ok {
					t.Errorf("version %q: a handshake result carries %s", version, key)
				}
			}
		}
	})

	t.Run("tools/call without routing headers", func(t *testing.T) {
		mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+testCountedTool+`","arguments":{}}}`,
			map[string]string{headerProtocolVersion: protocolVersion20251125})
		result, _ := decodeRPC(t, w)
		if result == nil || cb.calls.Load() != 1 {
			t.Fatalf("call did not run: %s", w.Body.String())
		}
		if _, ok := result[resultKeyResultType]; ok {
			t.Errorf("a handshake result carries resultType: %v", result)
		}
	})

	t.Run("an older revision named in header and body", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux,
			`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25"}}}`,
			map[string]string{headerProtocolVersion: protocolVersion20251125})
		result, _ := decodeRPC(t, w)
		if result == nil {
			t.Fatalf("no result: %s", w.Body.String())
		}
		if _, ok := result[resultKeyResultType]; ok {
			t.Errorf("served as stateless: %v", result)
		}
	})

	t.Run("unknown method keeps status 200", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"server/discover"}`, nil)
		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
		_, rpcErr := decodeRPC(t, w)
		if code, _ := rpcErr[oauthCode].(float64); int(code) != codeMethodNotFound {
			t.Errorf("code = %v", rpcErr[oauthCode])
		}
	})

	t.Run("ping", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
		if _, rpcErr := decodeRPC(t, w); rpcErr != nil {
			t.Errorf("ping failed: %v", rpcErr)
		}
	})
}

// A request of the handshake generation carries no routing headers. One
// that carries them anyway, and says something else in its body, is not
// executed: leaving the revision out is no way around the check for a
// request that went through a proxy on the strength of its headers.
func TestHandshake_RoutingHeadersAreHeldToTheBody(t *testing.T) {
	const callBody = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + testCountedTool + `","arguments":{}}}`

	tests := []struct {
		name     string
		headers  map[string]string
		wantRuns int32
	}{
		{"no routing headers", nil, 1},
		{"headers that agree with the body", map[string]string{headerMethod: methodToolsCall, headerName: testCountedTool}, 1},
		{"Mcp-Method names a harmless method", map[string]string{headerMethod: methodToolsList}, 0},
		{"Mcp-Name names another tool", map[string]string{headerName: toolDiscoverTools}, 0},
		{"Mcp-Method sent twice", map[string]string{headerMethod: methodToolsCall + "\n" + methodToolsList}, 0},
		{
			"an older revision in the header and a wrong Mcp-Name",
			map[string]string{headerProtocolVersion: protocolVersion20251125, headerName: toolDiscoverTools}, 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
			w := mcpPost(t, mux, callBody, tt.headers)
			if got := cb.calls.Load(); got != tt.wantRuns {
				t.Errorf("the tool ran %d times, want %d: %s", got, tt.wantRuns, w.Body.String())
			}
			if tt.wantRuns == 0 {
				if w.Code != http.StatusBadRequest {
					t.Errorf("status = %d, want 400", w.Code)
				}
				_, rpcErr := decodeRPC(t, w)
				if code, _ := rpcErr[oauthCode].(float64); int(code) != codeHeaderMismatch {
					t.Errorf("code = %v, want %d", rpcErr[oauthCode], codeHeaderMismatch)
				}
			}
		})
	}
}

func TestNotification_MethodHeader(t *testing.T) {
	mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
	const body = `{"jsonrpc":"2.0","method":"notifications/initialized"}`

	if w := mcpPost(t, mux, body, nil); w.Code != http.StatusAccepted {
		t.Errorf("without the header: status = %d, want 202", w.Code)
	}
	if w := mcpPost(t, mux, body, map[string]string{headerMethod: "notifications/initialized"}); w.Code != http.StatusAccepted {
		t.Errorf("with the matching header: status = %d, want 202", w.Code)
	}
	w := mcpPost(t, mux, body, map[string]string{headerMethod: methodToolsList})
	if w.Code != http.StatusBadRequest {
		t.Errorf("with another method in the header: status = %d, want 400", w.Code)
	}
}

// The credential is checked before the protocol: a caller without one
// learns nothing about what the server would have said to the request.
func TestStateless_UnauthenticatedGets401(t *testing.T) {
	mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+testCountedTool+`","arguments":{},`+testStatelessMeta+`}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerProtocolVersion, "garbage")
	req.Header.Set(headerMethod, methodToolsList)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if cb.calls.Load() != 0 {
		t.Error("the tool was called without a credential")
	}
}

func TestMCP_OriginAllowlist(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	t.Run("an origin outside the allowlist is refused", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey, CORSAllowedOrigins: []string{testOriginClaudeAI}})
		for _, origin := range []string{"https://evil.example.com", "null", "https://claude.ai.evil.example.com"} {
			w := mcpPost(t, mux, body, map[string]string{testHeaderOrigin: origin})
			if w.Code != http.StatusForbidden {
				t.Errorf("origin %q: status = %d, want 403", origin, w.Code)
			}
		}
	})
	t.Run("an origin on the allowlist passes", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey, CORSAllowedOrigins: []string{testOriginClaudeAI}})
		if w := mcpPost(t, mux, body, map[string]string{testHeaderOrigin: testOriginClaudeAI}); w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
	t.Run("a client that sends no origin passes", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey, CORSAllowedOrigins: []string{testOriginClaudeAI}})
		if w := mcpPost(t, mux, body, nil); w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
	t.Run("without an allowlist no origin is refused", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		if w := mcpPost(t, mux, body, map[string]string{testHeaderOrigin: "https://anything.example.com"}); w.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", w.Code)
		}
	})
	t.Run("a refused origin is not told whether its credential is valid", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey, CORSAllowedOrigins: []string{testOriginClaudeAI}})
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(testHeaderOrigin, "https://evil.example.com")
		req.Header.Set("Authorization", "Bearer wrong")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", w.Code)
		}
	})
}

// subscriptions/listen is acknowledged with an empty set of notifications
// and ended at once: the server sends none.
func TestStateless_SubscriptionsListen(t *testing.T) {
	const body = `{"jsonrpc":"2.0","id":42,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},` + testStatelessMeta + `}}`

	t.Run("sse", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		headers := statelessHeaders(methodSubscriptionsListen, "")
		headers["Accept"] = testAcceptStream
		w := mcpPost(t, mux, body, headers)
		messages := sseMessages(t, w.Body.String())
		if len(messages) != 2 {
			t.Fatalf("got %d messages, want acknowledgment and result: %s", len(messages), w.Body.String())
		}
		ack := messages[0]
		if ack["method"] != "notifications/subscriptions/acknowledged" {
			t.Errorf("first message = %v", ack)
		}
		params, _ := ack["params"].(map[string]any)
		if honored, _ := params["notifications"].(map[string]any); len(honored) != 0 {
			t.Errorf("acknowledged notifications = %v, want none", params["notifications"])
		}
		if id := params[metaKey].(map[string]any)[metaKeySubscriptionID]; id != float64(42) {
			t.Errorf("acknowledgment subscriptionId = %v, want 42", id)
		}
		result, _ := messages[1]["result"].(map[string]any)
		if result[resultKeyResultType] != resultTypeComplete {
			t.Errorf("result = %v", result)
		}
		if id := result[metaKey].(map[string]any)[metaKeySubscriptionID]; id != float64(42) {
			t.Errorf("result subscriptionId = %v, want 42", id)
		}
	})

	t.Run("json", func(t *testing.T) {
		mux, _, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
		w := mcpPost(t, mux, body, statelessHeaders(methodSubscriptionsListen, ""))
		result, _ := decodeRPC(t, w)
		if result[resultKeyResultType] != resultTypeComplete {
			t.Errorf("result = %v", result)
		}
	})
}

func TestDecodeHeaderValue(t *testing.T) {
	tests := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"us-west1", "us-west1", true},
		{"", "", true},
		{"with space", "with space", true},
		// The examples of the specification.
		{"=?base64?SGVsbG8sIOS4lueVjA==?=", "Hello, 世界", true},
		{"=?base64?IHBhZGRlZCA=?=", " padded ", true},
		{"=?base64?bGluZTEKbGluZTI=?=", "line1\nline2", true},
		{"=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=", "=?base64?literal?=", true},
		// Not the sentinel: the marks are case-sensitive.
		{"=?BASE64?eA==?=", "=?BASE64?eA==?=", true},
		{"=?base64?not base64?=", "", false},
		{"=?base64?eA?=", "", false}, // padding missing
		{"café", "", false},
		{"bell\x07", "", false},
	}
	for _, tt := range tests {
		got, ok := decodeHeaderValue(tt.in)
		if ok != tt.wantOK || got != tt.want {
			t.Errorf("decodeHeaderValue(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

// The method label of the request counter comes from a closed set: a
// caller cannot create series by inventing method names.
func TestMetrics_RequestLabels(t *testing.T) {
	mux, _, reg := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})

	for i := 0; i < 5; i++ {
		mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"invented/`+strings.Repeat("x", i+1)+`"}`, nil)
	}
	mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, map[string]string{headerProtocolVersion: protocolVersion20251125})
	mcpPost(t, mux, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{`+testStatelessMeta+`}}`, statelessHeaders(methodToolsList, ""))
	mcpPost(t, mux, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil)

	want := []string{
		`toolmesh_mcp_requests_total{method="notification",protocol="unspecified"} 1`,
		`toolmesh_mcp_requests_total{method="other",protocol="unspecified"} 5`,
		`toolmesh_mcp_requests_total{method="tools/list",protocol="2025-11-25"} 1`,
		`toolmesh_mcp_requests_total{method="tools/list",protocol="2026-07-28"} 1`,
	}
	if got := requestSeries(t, reg); !slices.Equal(got, want) {
		t.Errorf("request counter:\n got %v\nwant %v", got, want)
	}
}

// bearerRoundTripper adds the test credential to the requests of an SDK
// client.
type bearerRoundTripper struct{ base http.RoundTripper }

func (b bearerRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+testAPIKey)
	return b.base.RoundTrip(req)
}

// The client of the official Go SDK talks to the endpoint in both
// generations: without a handshake where it asks for the stateless
// revision, with initialize where it asks for the older one.
func TestSDKClient_BothGenerations(t *testing.T) {
	tests := []struct {
		name         string
		opts         *mcpsdk.ClientSessionOptions
		wantRevision string
	}{
		{name: "stateless", opts: nil, wantRevision: protocolVersion20260728},
		{name: "handshake", opts: &mcpsdk.ClientSessionOptions{ProtocolVersion: protocolVersion20251125}, wantRevision: protocolVersion20251125},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux, cb, _ := newProtocolTestServer(t, &config.Config{APIKey: testAPIKey})
			ts := httptest.NewServer(mux)
			defer ts.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "sdk-test", Version: "1"}, &mcpsdk.ClientOptions{Capabilities: &mcpsdk.ClientCapabilities{}})
			session, err := client.Connect(ctx, &mcpsdk.StreamableClientTransport{
				Endpoint:   ts.URL + "/mcp",
				HTTPClient: &http.Client{Transport: bearerRoundTripper{base: http.DefaultTransport}},
			}, tt.opts)
			if err != nil {
				t.Fatalf("connect: %v", err)
			}
			defer func() { _ = session.Close() }()

			if got := session.InitializeResult().ProtocolVersion; got != tt.wantRevision {
				t.Errorf("revision = %q, want %q", got, tt.wantRevision)
			}

			tools, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatalf("list tools: %v", err)
			}
			if len(tools.Tools) == 0 {
				t.Fatal("no tools listed")
			}

			result, err := session.CallTool(ctx, &mcpsdk.CallToolParams{Name: testCountedTool, Arguments: map[string]any{}})
			if err != nil {
				t.Fatalf("call tool: %v", err)
			}
			if result.IsError || len(result.Content) == 0 {
				t.Errorf("unexpected result: %+v", result)
			}
			if got := cb.calls.Load(); got != 1 {
				t.Errorf("backend calls = %d, want 1", got)
			}
		})
	}
}
