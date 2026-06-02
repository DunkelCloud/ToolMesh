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

package unit

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

const (
	testSubName  = "svc"
	testTextKind = "text"
)

// stubBackend is a minimal ToolBackend used by sandbox tests. It records how
// often each tool was called and lets the test inject the response.
type stubBackend struct {
	tools    []backend.ToolDescriptor
	respond  func(tool string, params map[string]any) (*backend.ToolResult, error)
	callsTot int64
}

func (s *stubBackend) Execute(_ context.Context, tool string, params map[string]any) (*backend.ToolResult, error) {
	atomic.AddInt64(&s.callsTot, 1)
	if s.respond != nil {
		return s.respond(tool, params)
	}
	return &backend.ToolResult{Content: []any{}}, nil
}
func (s *stubBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return append([]backend.ToolDescriptor(nil), s.tools...), nil
}
func (s *stubBackend) Healthy(_ context.Context) error { return nil }

func makeStub(toolNames ...string) *stubBackend {
	tools := make([]backend.ToolDescriptor, len(toolNames))
	for i, n := range toolNames {
		tools[i] = backend.ToolDescriptor{Name: n}
	}
	return &stubBackend{tools: tools}
}

func TestDescribe_HappyPath(t *testing.T) {
	src := `
function describe() {
    return {
        tools: [
            { name: "do_it", description: "doer", params: { x: { type: "integer", required: true } } }
        ]
    };
}
`
	descs, err := callDescribe(context.Background(), "u", src, "u.js", nil)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if len(descs) != 1 || descs[0].Name != "do_it" {
		t.Fatalf("got %+v", descs)
	}
	schema := descs[0].InputSchema
	if schema["type"] != "object" {
		t.Fatalf("schema type: %v", schema)
	}
	props, _ := schema["properties"].(map[string]any)
	if _, ok := props["x"]; !ok {
		t.Fatalf("missing property x in %v", props)
	}
	req, _ := schema["required"].([]any)
	if len(req) != 1 || req[0] != "x" {
		t.Fatalf("required: %v", req)
	}
}

func TestDescribe_InvalidName(t *testing.T) {
	src := `function describe() { return { tools: [{ name: "1bad" }] }; }`
	if _, err := callDescribe(context.Background(), "u", src, "u.js", nil); err == nil {
		t.Fatalf("expected error for invalid name, got nil")
	}
}

func TestDescribe_ToolNameCollidesWithSubBackend(t *testing.T) {
	src := `function describe() { return { tools: [{ name: "randombit" }] }; }`
	_, err := callDescribe(context.Background(), "u", src, "u.js", []string{"randombit"})
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("expected collision error, got %v", err)
	}
}

func TestDescribe_MissingFunction(t *testing.T) {
	src := `var x = 42;`
	_, err := callDescribe(context.Background(), "u", src, "u.js", nil)
	if err == nil || !strings.Contains(err.Error(), "describe()") {
		t.Fatalf("expected describe() error, got %v", err)
	}
}

func TestExecute_ReachesSubBackend(t *testing.T) {
	stub := makeStub("ping")
	stub.respond = func(tool string, _ map[string]any) (*backend.ToolResult, error) {
		return &backend.ToolResult{Content: []any{map[string]any{
			"type": testTextKind, testTextKind: "pong from " + tool,
		}}}, nil
	}
	subs := map[string]backend.ToolBackend{testSubName: stub}

	src := `
function describe() {
    return { tools: [{ name: "run", description: "run" }] };
}
async function run() {
    const r = await api.svc.ping({ msg: "hi" });
    return r;
}
`
	descs, err := callDescribe(context.Background(), "u", src, "u.js", []string{testSubName})
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if descs[0].Name != "run" {
		t.Fatalf("unexpected descs: %+v", descs)
	}

	v, err := callExportedFunction(context.Background(), "u", src, "u.js", "run", nil, subs, DefaultMaxCallDepth, DefaultMaxAPICalls)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if stub.callsTot != 1 {
		t.Fatalf("expected exactly 1 sub-backend call, got %d", stub.callsTot)
	}
	res := toolResultFromJS(v)
	if len(res.Content) == 0 {
		t.Fatalf("empty content")
	}
	block, _ := res.Content[0].(map[string]any)
	if block[testTextKind] != "pong from ping" {
		t.Fatalf("unexpected content: %v", block)
	}
}

func TestExecute_MaxAPICallsTripsOnRunawayLoop(t *testing.T) {
	// A flat for-loop never grows the depth counter (each api.* call
	// returns before the next starts), so the runaway-loop safeguard is
	// the cumulative call-count cap. Setting it to 5 with a 100-iteration
	// loop must trip exactly once on the 6th call.
	stub := makeStub("step")
	subs := map[string]backend.ToolBackend{testSubName: stub}

	src := `
function describe() { return { tools: [{ name: "loop" }] }; }
async function loop() {
    for (let i = 0; i < 100; i++) {
        await api.svc.step({});
    }
}
`
	_, err := callExportedFunction(context.Background(), "u", src, "u.js", "loop", nil, subs, DefaultMaxCallDepth, 5)
	if err == nil {
		t.Fatalf("expected api-call cap exceeded, got nil")
	}
	if !strings.Contains(err.Error(), "api.* calls per invocation") {
		t.Fatalf("expected api-call cap error, got %v", err)
	}
}

// TestExecute_MaxCallDepthNotExercisedYet documents that the depth counter
// cannot be tripped until unit-in-unit dependencies are wired. With a single
// goja runtime per Execute, every api.* closure increments depth then
// decrements before returning to JS; a flat or recursive JS pattern never
// accumulates concurrent in-flight calls. Keep this test as a guard so the
// invariant is visible when nesting lands.
func TestExecute_MaxCallDepthNotExercisedYet(t *testing.T) {
	stub := makeStub("step")
	subs := map[string]backend.ToolBackend{testSubName: stub}
	src := `
function describe() { return { tools: [{ name: "loop" }] }; }
async function loop() {
    for (let i = 0; i < 32; i++) { await api.svc.step({}); }
}
`
	// maxCallDepth=1 — would trip immediately if depth grew via flat JS calls.
	_, err := callExportedFunction(context.Background(), "u", src, "u.js", "loop", nil, subs, 1, DefaultMaxAPICalls)
	if err != nil {
		t.Fatalf("flat JS calls must not exceed depth=1: %v", err)
	}
}

func TestExecute_UnknownTool(t *testing.T) {
	src := `function describe() { return { tools: [] }; }`
	_, err := callExportedFunction(context.Background(), "u", src, "u.js", "ghost", nil, nil, DefaultMaxCallDepth, DefaultMaxAPICalls)
	if err == nil || !strings.Contains(err.Error(), "ghost") {
		t.Fatalf("expected unknown tool error, got %v", err)
	}
}

func TestExecute_RejectsInvalidToolName(t *testing.T) {
	_, err := callExportedFunction(context.Background(), "u", `function describe(){return{tools:[]}}`, "u.js", "1bad", nil, nil, DefaultMaxCallDepth, DefaultMaxAPICalls)
	if err == nil || !strings.Contains(err.Error(), "invalid tool name") {
		t.Fatalf("expected invalid-name error, got %v", err)
	}
}

func TestToolResultFromJS_ContentShape(t *testing.T) {
	r := toolResultFromJS(map[string]any{
		"content": []any{map[string]any{"type": testTextKind, testTextKind: "hi"}},
		"_meta":   map[string]any{"k": "v"},
	})
	if len(r.Content) != 1 {
		t.Fatalf("content len: %d", len(r.Content))
	}
	if r.Metadata["k"] != "v" {
		t.Fatalf("meta missing: %v", r.Metadata)
	}
}

func TestToolResultFromJS_ScalarFallback(t *testing.T) {
	r := toolResultFromJS(42)
	if len(r.Content) != 1 {
		t.Fatalf("content len: %d", len(r.Content))
	}
	block, _ := r.Content[0].(map[string]any)
	if block[testTextKind] != "42" {
		t.Fatalf("unexpected text: %v", block)
	}
}
