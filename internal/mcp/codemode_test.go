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
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

func TestCodeModeParser_ParseCode_SimpleCall(t *testing.T) {
	parser := &CodeModeParser{}

	calls, err := parser.ParseCode(`const result = await toolmesh.webSearch("query")`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	if calls[0].ToolName != "webSearch" {
		t.Errorf("ToolName = %q, want \"webSearch\"", calls[0].ToolName)
	}
	if calls[0].Params["arg0"] != "query" {
		t.Errorf("arg0 = %v, want \"query\"", calls[0].Params["arg0"])
	}
}

func TestCodeModeParser_ParseCode_WithJSONArg(t *testing.T) {
	parser := &CodeModeParser{}

	calls, err := parser.ParseCode(`await toolmesh.search({"query": "hello", "limit": 5})`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	if calls[0].ToolName != "search" {
		t.Errorf("ToolName = %q, want \"search\"", calls[0].ToolName)
	}
	if calls[0].Params["query"] != "hello" {
		t.Errorf("query = %v, want \"hello\"", calls[0].Params["query"])
	}
}

func TestCodeModeParser_ParseCode_MultipleCalls(t *testing.T) {
	parser := &CodeModeParser{}

	code := `
		const a = await toolmesh.search("test")
		const b = toolmesh.fetch("data")
	`
	calls, err := parser.ParseCode(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}

	if calls[0].ToolName != "search" {
		t.Errorf("first call ToolName = %q, want \"search\"", calls[0].ToolName)
	}
	if calls[1].ToolName != "fetch" {
		t.Errorf("second call ToolName = %q, want \"fetch\"", calls[1].ToolName)
	}
}

func TestCodeModeParser_ParseCode_NoArgs(t *testing.T) {
	parser := &CodeModeParser{}

	calls, err := parser.ParseCode(`toolmesh.listAll()`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	if calls[0].ToolName != "listAll" {
		t.Errorf("ToolName = %q, want \"listAll\"", calls[0].ToolName)
	}
	if len(calls[0].Params) != 0 {
		t.Errorf("expected 0 params, got %d", len(calls[0].Params))
	}
}

func TestCodeModeParser_ParseCode_NoToolCalls(t *testing.T) {
	parser := &CodeModeParser{}

	_, err := parser.ParseCode(`const x = 42; console.log(x);`)
	if err == nil {
		t.Fatal("expected error for code with no tool calls, got nil")
	}
}

func TestGenerateToolDefinitions(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{
			Name:        "search",
			Description: "Search for things",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer"},
				},
				"required": []any{"query"},
			},
		},
		{
			Name:        "memorizer:store",
			Description: "Store data",
		},
	}

	result := GenerateToolDefinitions(tools)

	if !strings.Contains(result, "declare namespace toolmesh") {
		t.Error("expected namespace declaration")
	}
	if !strings.Contains(result, "function search") {
		t.Error("expected search function")
	}
	if !strings.Contains(result, "function memorizer_store") {
		t.Error("expected sanitized memorizer_store function")
	}
	if !strings.Contains(result, "Search for things") {
		t.Error("expected description in JSDoc comment")
	}
	if !strings.Contains(result, "Promise<any>") {
		t.Error("expected Promise<any> return type")
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"camelCase", "camelCase"},
		{"with:colon", "with_colon"},
		{"with-dash", "with_dash"},
		{"with.dot", "with_dot"},
		{"under_score", "under_score"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty", "", 0},
		{"single string", `"hello"`, 1},
		{"two args", `"a", "b"`, 2},
		{"nested braces", `"a", {"key": "val"}`, 2},
		{"nested quotes in object", `{"key": "val, with comma"}`, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitArgs(tt.input)
			if len(got) != tt.want {
				t.Errorf("splitArgs(%q) returned %d args, want %d: %v", tt.input, len(got), tt.want, got)
			}
		})
	}
}

func TestExtractBalancedArgs(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		startAt int
		want    string
		wantOK  bool
	}{
		{
			name:    "simple",
			code:    `("hello")`,
			startAt: 0,
			want:    `"hello"`,
			wantOK:  true,
		},
		{
			name:    "object arg",
			code:    `({"key": "val"})`,
			startAt: 0,
			want:    `{"key": "val"}`,
			wantOK:  true,
		},
		{
			name:    "parens in string value",
			code:    `({content: "text (with parens) here"})`,
			startAt: 0,
			want:    `{content: "text (with parens) here"}`,
			wantOK:  true,
		},
		{
			name:    "parens in single-quoted string",
			code:    `({content: 'text (with parens) here'})`,
			startAt: 0,
			want:    `{content: 'text (with parens) here'}`,
			wantOK:  true,
		},
		{
			name:    "empty args",
			code:    `()`,
			startAt: 0,
			want:    ``,
			wantOK:  true,
		},
		{
			name:    "unbalanced",
			code:    `(unclosed`,
			startAt: 0,
			want:    ``,
			wantOK:  false,
		},
		{
			name:    "escaped quote in string",
			code:    `({content: "say \"hello\" world"})`,
			startAt: 0,
			want:    `{content: "say \"hello\" world"}`,
			wantOK:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := extractBalancedArgs(tt.code, tt.startAt)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestParseCode_JSObjectLiteral verifies that JS object literals with unquoted
// keys are parsed correctly (not wrapped in arg0).
func TestParseCode_JSObjectLiteral(t *testing.T) {
	parser := &CodeModeParser{}

	calls, err := parser.ParseCode(`await toolmesh.memorizer_memorize({content: "hello", title: "world"})`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	if _, hasArg0 := calls[0].Params["arg0"]; hasArg0 {
		t.Errorf("params should NOT contain arg0, got: %v", calls[0].Params)
	}
	if calls[0].Params["content"] != "hello" {
		t.Errorf("content = %v, want \"hello\"", calls[0].Params["content"])
	}
	if calls[0].Params["title"] != "world" {
		t.Errorf("title = %v, want \"world\"", calls[0].Params["title"])
	}
}

// TestParseCode_ParensInStringValue verifies that parentheses inside string
// values do not break argument extraction (the original arg0 bug).
func TestParseCode_ParensInStringValue(t *testing.T) {
	parser := &CodeModeParser{}

	calls, err := parser.ParseCode(`await toolmesh.memorizer_memorize({content: "text (with parens) and more", title: "test"})`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	if _, hasArg0 := calls[0].Params["arg0"]; hasArg0 {
		t.Errorf("params should NOT contain arg0, got: %v", calls[0].Params)
	}
	if calls[0].Params["content"] != "text (with parens) and more" {
		t.Errorf("content = %v, want \"text (with parens) and more\"", calls[0].Params["content"])
	}
	if calls[0].Params["title"] != "test" {
		t.Errorf("title = %v, want \"test\"", calls[0].Params["title"])
	}
}

// TestParseCode_ExecuteCodeFlatParams is an end-to-end test that simulates
// the exact code pattern Claude.ai sends via execute_code, ensuring parameters
// are passed flat to the backend (no arg0 wrapping).
func TestParseCode_ExecuteCodeFlatParams(t *testing.T) {
	parser := NewCodeModeParser([]backend.ToolDescriptor{
		{Name: "memorizer:memorize", Description: "Store knowledge"},
	})

	code := `const result = await toolmesh.memorizer_memorize({content: "Test content", title: "Test title"});
return result;`

	calls, err := parser.ParseCode(code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	// Verify canonical name resolution
	if calls[0].ToolName != "memorizer:memorize" {
		t.Errorf("ToolName = %q, want \"memorizer:memorize\"", calls[0].ToolName)
	}

	// Verify flat params — no arg0 wrapping
	if _, hasArg0 := calls[0].Params["arg0"]; hasArg0 {
		t.Errorf("params must NOT contain arg0; got: %v", calls[0].Params)
	}
	if calls[0].Params["content"] != "Test content" {
		t.Errorf("content = %v, want \"Test content\"", calls[0].Params["content"])
	}
	if calls[0].Params["title"] != "Test title" {
		t.Errorf("title = %v, want \"Test title\"", calls[0].Params["title"])
	}
}
