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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

func decodeDebugResponse(t *testing.T, w *httptest.ResponseRecorder) (resultText string, isError bool) {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	result, _ := resp["result"].(map[string]any)
	if result == nil {
		t.Fatalf("response missing result: %v", resp)
	}
	isError, _ = result["isError"].(bool)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return "", isError
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text, isError
}

func postToolCall(t *testing.T, mux http.Handler, name, args string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestHandleToolCall_DebugEcho_Disabled(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{}) // DebugTools defaults to false

	w := postToolCall(t, mux, "debug_echo", `{"payload":"hello"}`)
	text, isError := decodeDebugResponse(t, w)
	if !isError {
		t.Fatalf("expected isError=true when debug tools disabled, got: %s", text)
	}
	if !strings.Contains(text, "TOOLMESH_DEBUG_TOOLS") {
		t.Errorf("expected error text to mention TOOLMESH_DEBUG_TOOLS, got: %s", text)
	}
}

func TestHandleToolCall_DebugEcho_StringRoundTrip(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	payload := "hello, world — Umlauts: ä ö ü"
	args, _ := json.Marshal(map[string]any{"payload": payload})
	w := postToolCall(t, mux, "debug_echo", string(args))
	text, isError := decodeDebugResponse(t, w)
	if isError {
		t.Fatalf("unexpected error: %s", text)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode echo result: %v (text=%s)", err, text)
	}

	if got["type"] != "string" {
		t.Errorf("expected type=string, got %v", got["type"])
	}
	wantSum := sha256.Sum256([]byte(payload))
	if got["sha256"] != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 mismatch: got %v want %s", got["sha256"], hex.EncodeToString(wantSum[:]))
	}
	if int(got["received_bytes"].(float64)) != len(payload) {
		t.Errorf("received_bytes: got %v want %d", got["received_bytes"], len(payload))
	}
}

func TestHandleToolCall_DebugEcho_Object(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_echo", `{"payload":{"a":1,"b":[1,2,3]}}`)
	text, isError := decodeDebugResponse(t, w)
	if isError {
		t.Fatalf("unexpected error: %s", text)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["type"] != "object" {
		t.Errorf("expected type=object, got %v", got["type"])
	}
	if _, hasChars := got["received_chars"]; hasChars {
		t.Errorf("received_chars should only appear for string payloads, got: %v", got)
	}
}

func TestHandleToolCall_DebugEcho_MissingPayload(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_echo", `{}`)
	text, isError := decodeDebugResponse(t, w)
	if !isError {
		t.Fatalf("expected isError=true when payload missing, got: %s", text)
	}
	if !strings.Contains(text, "payload") {
		t.Errorf("expected error to mention payload, got: %s", text)
	}
}

func TestHandleToolCall_DebugGenerate_Disabled(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{}) // disabled

	w := postToolCall(t, mux, "debug_generate", `{"size_bytes":100}`)
	text, isError := decodeDebugResponse(t, w)
	if !isError {
		t.Fatalf("expected isError=true when disabled, got: %s", text)
	}
	if !strings.Contains(text, "TOOLMESH_DEBUG_TOOLS") {
		t.Errorf("expected error text to mention TOOLMESH_DEBUG_TOOLS, got: %s", text)
	}
}

func TestHandleToolCall_DebugGenerate_Ascii(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_generate", `{"size_bytes":1000}`)
	text, isError := decodeDebugResponse(t, w)
	if isError {
		t.Fatalf("unexpected error: %s", text)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(text), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if int(got["returned_bytes"].(float64)) != 1000 {
		t.Errorf("returned_bytes: got %v want 1000", got["returned_bytes"])
	}
	body := got["text"].(string)
	if len(body) != 1000 {
		t.Errorf("text length: got %d want 1000", len(body))
	}
	wantSum := sha256.Sum256([]byte(body))
	if got["sha256"] != hex.EncodeToString(wantSum[:]) {
		t.Errorf("sha256 mismatch")
	}
}

func TestHandleToolCall_DebugGenerate_Random(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_generate", `{"size_bytes":256,"pattern":"random"}`)
	text, isError := decodeDebugResponse(t, w)
	if isError {
		t.Fatalf("unexpected error: %s", text)
	}

	var got map[string]any
	_ = json.Unmarshal([]byte(text), &got)
	body := got["text"].(string)
	if len(body) != 256 {
		t.Errorf("text length: got %d want 256", len(body))
	}
	// Random output should not be all the same byte.
	if strings.Count(body, string(body[0])) == 256 {
		t.Errorf("random pattern produced all-same byte sequence: %q", body)
	}
}

func TestHandleToolCall_DebugGenerate_TooLarge(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_generate", `{"size_bytes":99999999999}`)
	text, isError := decodeDebugResponse(t, w)
	if !isError {
		t.Fatalf("expected isError=true for oversized request, got: %s", text)
	}
	if !strings.Contains(text, "exceeds maximum") {
		t.Errorf("expected error to mention 'exceeds maximum', got: %s", text)
	}
}

func TestHandleToolCall_DebugGenerate_BadPattern(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{DebugTools: true})

	w := postToolCall(t, mux, "debug_generate", `{"size_bytes":10,"pattern":"banana"}`)
	text, isError := decodeDebugResponse(t, w)
	if !isError {
		t.Fatalf("expected isError=true for unknown pattern, got: %s", text)
	}
	if !strings.Contains(text, "unknown pattern") {
		t.Errorf("expected error to mention unknown pattern, got: %s", text)
	}
}

func TestBuildToolList_DebugToolsAdvertisedWhenEnabled(t *testing.T) {
	mb := &mockTestBackend{}
	hOff := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), false)
	hOn := NewHandler(nil, mb, nil, "", nil, newQuietMCPLogger(), true)

	listOff, err := hOff.BuildToolList(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	listOn, err := hOn.BuildToolList(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	hasDebug := func(list []ToolDefinition) bool {
		for _, td := range list {
			if td.Name == "debug_echo" || td.Name == "debug_generate" {
				return true
			}
		}
		return false
	}
	if hasDebug(listOff) {
		t.Errorf("debug tools listed when disabled: %+v", listOff)
	}
	if !hasDebug(listOn) {
		t.Errorf("debug tools missing when enabled: %+v", listOn)
	}
}
