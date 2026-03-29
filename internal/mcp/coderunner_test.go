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
		Content: []any{map[string]any{"type": "text", "text": "ok"}},
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
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger)
	nameMap := map[string]string{
		"test_foo": testToolFoo,
		"test_bar": testToolBar,
	}
	return NewCodeRunner(nameMap, exec, nil, logger)
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
			// Return a result with an "id" field that can be used in subsequent calls
			return &backend.ToolResult{
				Content: []any{map[string]any{
					"type": "text",
					"text": "result from " + toolName,
				}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	code := `
		const r1 = await toolmesh.test_foo({ key: "first" });
		await toolmesh.test_bar({ key: "second", prev: r1.Content[0].text });
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
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	code := `
		const r = await toolmesh.test_foo({ key: "val" });
		return r.Content[0].text;
	`
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	// Should have tool call results (the primary output)
	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("failed to unmarshal results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result entry, got %d", len(results))
	}
	if results[0]["tool"] != testToolFoo {
		t.Errorf("tool = %v, want \"test:foo\"", results[0]["tool"])
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

	_, err := runner.Execute(testCtx(), `await toolmesh.test_foo({ key: "val" })`)
	if err == nil {
		t.Fatal("expected error from failed tool call")
	}
	if !strings.Contains(err.Error(), "backend failure") {
		t.Errorf("error = %q, want to contain \"backend failure\"", err.Error())
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

	_, err := runner.Execute(testCtx(), `eval("1+1")`)
	if err == nil {
		t.Fatal("expected error for eval() usage")
	}
	if !strings.Contains(err.Error(), "eval is not allowed") {
		t.Errorf("error = %q, want to contain \"eval is not allowed\"", err.Error())
	}
}

func TestCodeRunner_SandboxViolation_Require(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	_, err := runner.Execute(testCtx(), `const fs = require("fs")`)
	if err == nil {
		t.Fatal("expected error for require() usage")
	}
}

func TestCodeRunner_SandboxViolation_Fetch(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	_, err := runner.Execute(testCtx(), `await fetch("https://example.com")`)
	if err == nil {
		t.Fatal("expected error for fetch() usage")
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
