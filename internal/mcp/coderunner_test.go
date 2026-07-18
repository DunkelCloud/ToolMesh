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
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	testToolFoo = "test:foo"
	testToolBar = "test:bar"
)

// codeRunnerTestBackend captures calls and returns configurable results.
type codeRunnerTestBackend struct {
	calls   []capturedCall
	handler func(toolName string, params map[string]any) (*backend.ToolResult, error)
}

type capturedCall struct {
	ToolName string
	Params   map[string]any
}

func (b *codeRunnerTestBackend) Execute(_ context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	b.calls = append(b.calls, capturedCall{ToolName: toolName, Params: params})
	if b.handler != nil {
		return b.handler(toolName, params)
	}
	return &backend.ToolResult{
		Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}},
	}, nil
}

func (b *codeRunnerTestBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return []backend.ToolDescriptor{
		{Name: testToolFoo, Description: "A test tool"},
		{Name: testToolBar, Description: "Another test tool"},
	}, nil
}

func (b *codeRunnerTestBackend) Healthy(_ context.Context) error { return nil }

func newTestCodeRunner(t *testing.T, mb *codeRunnerTestBackend) *CodeRunner {
	t.Helper()
	logger := handlerTestLogger()
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	nameMap := map[string]string{
		"test_foo": testToolFoo,
		"test_bar": testToolBar,
	}
	tools, err := mb.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	return NewCodeRunner(nameMap, tools, exec, nil, logger)
}

func testCtx() context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "test-user",
		Authenticated: true,
	})
}

func TestCodeRunner_SimpleInlineCall(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `await toolmesh.test_foo({ key: "value" })`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(mb.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mb.calls))
	}
	if mb.calls[0].ToolName != testToolFoo {
		t.Errorf("tool = %q, want \"test:foo\"", mb.calls[0].ToolName)
	}
	if mb.calls[0].Params["key"] != "value" {
		t.Errorf("params[key] = %v, want \"value\"", mb.calls[0].Params["key"])
	}
}

func TestCodeRunner_SetTimeout_InterruptsLongRun(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(toolName string, _ map[string]any) (*backend.ToolResult, error) {
			// A backend slower than the configured code timeout. The Go sleep
			// itself is not interruptible, but the runner's per-call context
			// check trips before the next toolmesh.* call.
			time.Sleep(250 * time.Millisecond)
			return &backend.ToolResult{
				Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: toolName}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)
	runner.SetTimeout(40 * time.Millisecond)

	// First call returns after the deadline; the second must not run.
	code := `
		await toolmesh.test_foo();
		await toolmesh.test_bar();
		return "done";
	`
	result, err := runner.Execute(testCtx(), code)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "deadline") {
		t.Errorf("error = %q, want it to mention the deadline", err)
	}
	if len(mb.calls) != 1 {
		t.Fatalf("expected the run to stop after 1 call, got %d", len(mb.calls))
	}
	// The partial result from the first call is preserved, not discarded.
	if result == nil {
		t.Fatal("expected a partial result, got nil")
	}
}

func TestCodeRunner_SetTimeout_ZeroRestoresDefault(t *testing.T) {
	runner := newTestCodeRunner(t, &codeRunnerTestBackend{})
	runner.SetTimeout(5 * time.Second)
	runner.SetTimeout(0)
	if runner.timeout != 0 {
		t.Errorf("timeout = %v, want 0 (default restored)", runner.timeout)
	}
}

func TestCodeRunner_VariableReference(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := `
		const x = "hello";
		await toolmesh.test_foo({ key: x });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if mb.calls[0].Params["key"] != "hello" {
		t.Errorf("params[key] = %v, want \"hello\"", mb.calls[0].Params["key"])
	}
}

func TestCodeRunner_StringConcatenation(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := `
		const x = "a" + "b";
		await toolmesh.test_foo({ key: x });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if mb.calls[0].Params["key"] != "ab" {
		t.Errorf("params[key] = %v, want \"ab\"", mb.calls[0].Params["key"])
	}
}

func TestCodeRunner_TemplateLiteral(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := "const x = `hello ${1+1}`; await toolmesh.test_foo({ key: x });"
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if mb.calls[0].Params["key"] != "hello 2" {
		t.Errorf("params[key] = %v, want \"hello 2\"", mb.calls[0].Params["key"])
	}
}

func TestCodeRunner_LoopBuildingData(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := `
		let s = "";
		for (let i = 0; i < 3; i++) s += "x";
		await toolmesh.test_foo({ key: s });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if mb.calls[0].Params["key"] != "xxx" {
		t.Errorf("params[key] = %v, want \"xxx\"", mb.calls[0].Params["key"])
	}
}

func TestCodeRunner_SequentialCallsWithDataFlow(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(toolName string, _ map[string]any) (*backend.ToolResult, error) {
			// Return a JSON result — extractJSValue will parse it for JS
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: `{"source": "` + toolName + `", "id": 42}`,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// JS code accesses parsed JSON fields directly (e.g. r1.source, r1.id)
	code := `
		const r1 = await toolmesh.test_foo({ key: "first" });
		await toolmesh.test_bar({ key: "second", prev: r1.source });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(mb.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(mb.calls))
	}
	if mb.calls[1].Params["prev"] != "test:foo" {
		t.Errorf("params[prev] = %v, want \"test:foo\"", mb.calls[1].Params["prev"])
	}
}

func TestCodeRunner_SequentialCallsWithDataFlow_PlainText(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(toolName string, _ map[string]any) (*backend.ToolResult, error) {
			// Return a non-JSON result — extractJSValue returns raw string
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: "result from " + toolName,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// When content is plain text, the return value is the string itself
	code := `
		const r1 = await toolmesh.test_foo({ key: "first" });
		await toolmesh.test_bar({ key: "second", prev: r1 });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(mb.calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(mb.calls))
	}
	if mb.calls[1].Params["prev"] != "result from test:foo" {
		t.Errorf("params[prev] = %v, want \"result from test:foo\"", mb.calls[1].Params["prev"])
	}
}

func TestCodeRunner_ReturnValue(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: `{"id": 123, "name": "test"}`,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// extractJSValue parses the JSON, so r.id works directly
	code := `
		const r = await toolmesh.test_foo({ key: "val" });
		return r.id;
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	// Should have tool call result + return value
	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	// 1 tool call result + 1 return value entry
	if len(results) != 2 {
		t.Fatalf("expected 2 result entries, got %d: %s", len(results), text)
	}
	if results[0]["tool"] != testToolFoo {
		t.Errorf("tool = %v, want \"test:foo\"", results[0]["tool"])
	}
	// The return value entry should have "return" key with value 123
	retVal, ok := results[1]["return"]
	if !ok {
		t.Fatalf("expected 'return' key in last result entry, got: %v", results[1])
	}
	// JSON numbers unmarshal as float64
	if retVal != 123.0 {
		t.Errorf("return value = %v (%T), want 123", retVal, retVal)
	}
}

func TestCodeRunner_NoToolCalls(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `const x = 42;`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Error("expected error result when no tool calls found")
	}
}

func TestCodeRunner_NoToolCallsWithReturn(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `return 42;`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Code returned a value but made no tool calls — should still return the value
	if result.IsError {
		t.Fatalf("expected non-error result for code with return value")
	}
	text := extractText(t, result)
	if text != "42" {
		t.Errorf("return value = %q, want \"42\"", text)
	}
}

func TestCodeRunner_ToolError(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return nil, &testError{msg: "backend failure"}
		},
	}
	runner := newTestCodeRunner(t, mb)

	// Tool errors are returned to JS as error objects instead of panicking.
	// The execute_code call itself succeeds; the error is in the results.
	result, err := runner.Execute(testCtx(), `await toolmesh.test_foo({ key: "val" })`)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected IsError on result: %v", result.Content)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result entry, got %d", len(results))
	}
	errMsg, ok := results[0]["error"].(string)
	if !ok {
		t.Fatalf("expected error string in result, got: %v", results[0])
	}
	if !strings.Contains(errMsg, "backend failure") {
		t.Errorf("error = %q, want to contain \"backend failure\"", errMsg)
	}
}

type testError struct {
	msg string
}

func (e *testError) Error() string { return e.msg }

func TestCodeRunner_Timeout(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	// Use a short-lived context to trigger timeout
	ctx, cancel := context.WithTimeout(testCtx(), 100*time.Millisecond)
	defer cancel()

	// Infinite loop should be interrupted
	_, err := runner.Execute(ctx, `while(true) {}`)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error = %q, want to contain \"interrupted\"", err.Error())
	}
}

func TestCodeRunner_CallLimitExceeded(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	// Build code that makes >50 calls
	code := `for (let i = 0; i < 51; i++) { await toolmesh.test_foo({ i: i }); }`
	_, err := runner.Execute(testCtx(), code)
	if err == nil {
		t.Fatal("expected error for exceeding call limit")
	}
	if !strings.Contains(err.Error(), "exceeded maximum") {
		t.Errorf("error = %q, want to contain \"exceeded maximum\"", err.Error())
	}
}

func TestCodeRunner_SandboxViolation_Eval(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `eval("1+1")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for eval() usage")
	}
	text := extractText(t, result)
	if !strings.Contains(text, "forbidden") {
		t.Errorf("result text = %q, want to contain \"forbidden\"", text)
	}
}

func TestCodeRunner_SandboxViolation_Require(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `const fs = require("fs")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for require() usage")
	}
}

func TestCodeRunner_SandboxViolation_Fetch(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `await fetch("https://example.com")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true for fetch() usage")
	}
}

func TestCodeRunner_MultipleCallsResultFormat(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := `
		await toolmesh.test_foo({ key: "first" });
		await toolmesh.test_bar({ key: "second" });
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 result entries, got %d", len(results))
	}
	if results[0]["tool"] != testToolFoo {
		t.Errorf("first tool = %v, want \"test:foo\"", results[0]["tool"])
	}
	if results[1]["tool"] != testToolBar {
		t.Errorf("second tool = %v, want \"test:bar\"", results[1]["tool"])
	}
}

func TestCodeRunner_ToolIsError_Catchable(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			// Tool returns a result with IsError=true but no Go error.
			// This represents a tool-level error (e.g. 404, validation failure).
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: `{"error": "page not found"}`,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// JS code should be able to inspect the error result without panic
	code := `
		const r = await toolmesh.test_foo({ page: "nonexistent" });
		return { caught: false, errorMsg: r.error };
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	// Last entry should be the return value
	last := results[len(results)-1]
	retVal, ok := last["return"].(map[string]any)
	if !ok {
		t.Fatalf("expected return map, got: %v", last)
	}
	if retVal["errorMsg"] != "page not found" {
		t.Errorf("errorMsg = %v, want \"page not found\"", retVal["errorMsg"])
	}
}

func TestCodeRunner_ReturnValueFromJSON(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: `{"items": [{"name": "a"}, {"name": "b"}], "total": 2}`,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// Verify JS can traverse parsed JSON deeply
	code := `
		const r = await toolmesh.test_foo({});
		return r.items[1].name;
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	last := results[len(results)-1]
	if last["return"] != "b" {
		t.Errorf("return = %v, want \"b\"", last["return"])
	}
}

func TestCodeRunner_EmptyParams(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	result, err := runner.Execute(testCtx(), `await toolmesh.test_foo()`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if len(mb.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(mb.calls))
	}
	if len(mb.calls[0].Params) != 0 {
		t.Errorf("expected empty params, got %v", mb.calls[0].Params)
	}
}

func TestCodeRunner_LoopWithFailingCalls(t *testing.T) {
	callNum := 0
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			callNum++
			if callNum == 2 {
				return nil, &testError{msg: "transient failure"}
			}
			return &backend.ToolResult{
				Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: `{"ok": true}`}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	// 3 iterations: call 1 succeeds, call 2 fails, call 3 succeeds.
	// All 3 should execute — the failing call must not stop the loop.
	code := `
		for (let i = 0; i < 3; i++) {
			await toolmesh.test_foo({ i: i });
		}
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected IsError: %v", result.Content)
	}
	if len(mb.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(mb.calls))
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 result entries, got %d: %s", len(results), text)
	}
	// Second entry should be the error
	if _, ok := results[1]["error"]; !ok {
		t.Errorf("expected error in second result, got: %v", results[1])
	}
}

func TestCodeRunner_ErrorReturnedToJS(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return nil, &testError{msg: "something broke"}
		},
	}
	runner := newTestCodeRunner(t, mb)

	// JS code can inspect the error object returned by a failed call.
	code := `
		const r = await toolmesh.test_foo({});
		if (r.error) return { wasError: true, msg: r.error };
		return { wasError: false };
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected Go error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected IsError: %v", result.Content)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	last := results[len(results)-1]
	retVal, ok := last["return"].(map[string]any)
	if !ok {
		t.Fatalf("expected return map, got: %v", last)
	}
	if retVal["wasError"] != true {
		t.Errorf("wasError = %v, want true", retVal["wasError"])
	}
	if msg, _ := retVal["msg"].(string); !strings.Contains(msg, "something broke") {
		t.Errorf("msg = %q, want to contain \"something broke\"", msg)
	}
}

// TestCodeRunner_DiscoverToolsGuard verifies the JS sandbox installs an
// explicit guard for toolmesh.discover_tools and toolmesh.execute_code so a
// caller using them inline gets a clear "this is a separate MCP tool" message
// instead of the generic goja TypeError "Object has no member 'discover_tools'".
func TestCodeRunner_DiscoverToolsGuard(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	cases := []struct {
		name string
		code string
	}{
		{name: toolDiscoverTools, code: `await toolmesh.discover_tools({pattern: ".*"});`},
		{name: toolExecuteCode, code: `await toolmesh.execute_code({code: "1"});`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := runner.Execute(testCtx(), tc.code)
			if err == nil {
				t.Fatalf("expected guard error, got nil (result=%v)", result)
			}
			msg := err.Error()
			if !strings.Contains(msg, "toolmesh."+tc.name+" is not a backend tool") {
				t.Errorf("expected guard to name toolmesh.%s, got: %s", tc.name, msg)
			}
			if !strings.Contains(msg, "separate MCP tool") {
				t.Errorf("expected guard to point at separate MCP tool semantics, got: %s", msg)
			}
			// No partial result expected — the call short-circuits before any
			// real tool runs, so handler.go falls through to the "no partial
			// result" branch and emits only the real error.
			if result != nil {
				t.Errorf("expected nil result on pure guard error (no preceding tool calls), got: %v", result)
			}
			if len(mb.calls) != 0 {
				t.Errorf("expected no backend calls, got %d", len(mb.calls))
			}
		})
	}
}

// TestCodeRunner_DiscoverToolsGuard_NotShadowedByRealTool verifies that the
// guard does NOT overwrite a real backend tool that happens to share the
// reserved name. If a backend ever exposes a tool named "discover_tools", the
// real tool wins — the guard only installs into otherwise empty slots.
func TestCodeRunner_DiscoverToolsGuard_NotShadowedByRealTool(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	logger := handlerTestLogger()
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	const realDiscoverTool = "test:discover_tools"
	nameMap := map[string]string{
		"discover_tools": realDiscoverTool,
	}
	tools := []backend.ToolDescriptor{{Name: realDiscoverTool, Description: "real tool"}}
	runner := NewCodeRunner(nameMap, tools, exec, nil, logger)

	result, err := runner.Execute(testCtx(), `await toolmesh.discover_tools({foo: "bar"});`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected IsError: %v", result.Content)
	}
	if len(mb.calls) != 1 || mb.calls[0].ToolName != realDiscoverTool {
		t.Errorf("expected 1 call to test:discover_tools, got %d calls: %v", len(mb.calls), mb.calls)
	}
}

// TestCodeRunner_NoToolCalls_NoDuplicatePlaceholderOnError verifies that a
// runtime error in code with no preceding tool calls returns nil result +
// the real error. handler.go then emits only the real error message instead
// of also surfacing the misleading "no tool calls found in code" placeholder.
func TestCodeRunner_NoToolCalls_NoDuplicatePlaceholderOnError(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	// Reference an undefined member so goja raises a TypeError, mirroring the
	// real-world "toolmesh.discover_tools" mistake before the guard would have
	// fired (e.g. if a typo lands on a totally unknown name).
	result, err := runner.Execute(testCtx(), `await toolmesh.totally_not_a_tool({});`)
	if err == nil {
		t.Fatalf("expected runtime error, got nil")
	}
	if result != nil {
		t.Errorf("expected nil result on pure runtime error (no preceding tool calls), got: %v", result)
	}
}

const compactTestPayload = `{"id": 123, "bulk_padding": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`

func compactTestRunner(t *testing.T) *CodeRunner {
	t.Helper()
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: compactTestPayload,
				}},
			}, nil
		},
	}
	return newTestCodeRunner(t, mb)
}

// TestCodeRunner_ReturnValue_CompactsCallEntries verifies that a script with
// an explicit return value gets compact {tool, status, resultBytes} call
// entries instead of the full result echo — the return value is the script's
// projection of the data, so the full echo would ship the payload twice.
func TestCodeRunner_ReturnValue_CompactsCallEntries(t *testing.T) {
	runner := compactTestRunner(t)

	code := `
		const r = await toolmesh.test_foo({});
		return r.id;
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if strings.Contains(text, "bulk_padding") {
		t.Errorf("full tool result leaked into compacted response: %s", text)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entries (compact call + return), got %d: %s", len(results), text)
	}
	entry := results[0]
	if entry[logKeyTool] != testToolFoo {
		t.Errorf("tool = %v, want %q", entry[logKeyTool], testToolFoo)
	}
	if _, hasFull := entry[resultKeyResult]; hasFull {
		t.Errorf("expected compact entry without %q key, got: %v", resultKeyResult, entry)
	}
	if entry[resultKeyStatus] != resultStatusOK {
		t.Errorf("status = %v, want %q", entry[resultKeyStatus], resultStatusOK)
	}
	if entry[resultKeyBytes] != float64(len(compactTestPayload)) {
		t.Errorf("resultBytes = %v, want %d", entry[resultKeyBytes], len(compactTestPayload))
	}
	if results[1][resultKeyReturn] != 123.0 {
		t.Errorf("return = %v, want 123", results[1][resultKeyReturn])
	}
}

// TestCodeRunner_IncludeResults_KeepsFullEcho verifies that the include_results
// escape hatch restores the pre-compaction behavior: full per-call results
// alongside the return value.
func TestCodeRunner_IncludeResults_KeepsFullEcho(t *testing.T) {
	runner := compactTestRunner(t)

	code := `
		const r = await toolmesh.test_foo({});
		return r.id;
	`
	result, err := runner.ExecuteWithOptions(testCtx(), code, ExecuteOptions{IncludeResults: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "bulk_padding") {
		t.Errorf("expected full tool result with include_results, got: %s", text)
	}

	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if _, hasFull := results[0][resultKeyResult]; !hasFull {
		t.Errorf("expected full %q entry, got: %v", resultKeyResult, results[0])
	}
	if results[1][resultKeyReturn] != 123.0 {
		t.Errorf("return = %v, want 123", results[1][resultKeyReturn])
	}
}

// TestCodeRunner_NoReturn_KeepsFullResults pins the preserved behavior: when
// the script does not return a value, the full per-call results ARE the
// response and must not be compacted.
func TestCodeRunner_NoReturn_KeepsFullResults(t *testing.T) {
	runner := compactTestRunner(t)

	result, err := runner.Execute(testCtx(), `await toolmesh.test_foo({});`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "bulk_padding") {
		t.Errorf("expected full tool result without return value, got: %s", text)
	}
}

// TestCodeRunner_Compact_KeepsToolLevelErrors verifies that compaction keeps
// entries whose result carries IsError in full: the error content is the
// diagnostic the caller needs, and re-running the call to recover it could
// repeat side effects.
func TestCodeRunner_Compact_KeepsToolLevelErrors(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: `{"error": "quota exceeded for project 42"}`,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	code := `
		const r = await toolmesh.test_foo({});
		return { sawError: true };
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "quota exceeded for project 42") {
		t.Errorf("tool-level error content must survive compaction, got: %s", text)
	}
}

// TestCodeRunner_Compact_KeepsDispatchErrors verifies that compaction leaves
// {tool, error} entries from failed dispatches untouched.
func TestCodeRunner_Compact_KeepsDispatchErrors(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return nil, &testError{msg: "backend unreachable"}
		},
	}
	runner := newTestCodeRunner(t, mb)

	code := `
		const r = await toolmesh.test_foo({});
		return { failed: !!r.error };
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "backend unreachable") {
		t.Errorf("dispatch error must survive compaction, got: %s", text)
	}
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if _, hasErr := results[0][outcomeError]; !hasErr {
		t.Errorf("expected %q key on dispatch-error entry, got: %v", outcomeError, results[0])
	}
}
