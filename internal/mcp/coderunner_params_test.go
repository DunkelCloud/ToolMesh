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
	"encoding/json"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// runEntries runs code and returns the decoded result listing.
func runEntries(t *testing.T, runner *CodeRunner, code string) []map[string]any {
	t.Helper()
	result, err := runner.Execute(testCtx(), code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var entries []map[string]any
	if err := json.Unmarshal([]byte(extractText(t, result)), &entries); err != nil {
		t.Fatalf("decode results: %v", err)
	}
	return entries
}

// TestCodeRunner_FailedCallEntryCarriesParams is the field case: several
// calls in one script, one of them fails, and the listing must say which
// arguments that one was made with.
func TestCodeRunner_FailedCallEntryCarriesParams(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(toolName string, _ map[string]any) (*backend.ToolResult, error) {
			if toolName == testToolBar {
				return nil, &testError{msg: "backend unreachable"}
			}
			return &backend.ToolResult{
				Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	entries := runEntries(t, runner, `
		await toolmesh.test_foo({id: 1});
		await toolmesh.test_bar({id: 42, scope: "all"});
		return "done";
	`)
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(entries), entries)
	}
	if _, has := entries[0][resultKeyParams]; has {
		t.Errorf("successful entry must not carry params: %v", entries[0])
	}
	params, ok := entries[1][resultKeyParams].(map[string]any)
	if !ok {
		t.Fatalf("failed entry lacks params: %v", entries[1])
	}
	if params["id"] != float64(42) || params["scope"] != "all" {
		t.Errorf("params = %v, want the sent arguments", params)
	}
	if !strings.Contains(entries[1][outcomeError].(string), "backend unreachable") {
		t.Errorf("failed entry lost its error: %v", entries[1])
	}
}

// TestCodeRunner_ToolErrorEntryCarriesParams covers the other failure
// shape: the backend answered, with isError.
func TestCodeRunner_ToolErrorEntryCarriesParams(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "Error: not found"}},
			}, nil
		},
	}
	runner := newTestCodeRunner(t, mb)

	entries := runEntries(t, runner, `await toolmesh.test_foo({id: 7});`)
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(entries), entries)
	}
	params, ok := entries[0][resultKeyParams].(map[string]any)
	if !ok {
		t.Fatalf("tool-error entry lacks params: %v", entries[0])
	}
	if params["id"] != float64(7) {
		t.Errorf("params = %v, want {id: 7}", params)
	}
}

// TestCodeRunner_FailedCallParamsRedactSecrets keeps a password the script
// passed out of the listing while the other arguments stay readable.
func TestCodeRunner_FailedCallParamsRedactSecrets(t *testing.T) {
	mb := &codeRunnerTestBackend{
		handler: func(_ string, _ map[string]any) (*backend.ToolResult, error) {
			return nil, &testError{msg: "login failed"}
		},
	}
	runner := newTestCodeRunner(t, mb)

	entries := runEntries(t, runner, `await toolmesh.test_foo({user: "ad", password: "hunter2", api_key: "k"});`)
	params, ok := entries[0][resultKeyParams].(map[string]any)
	if !ok {
		t.Fatalf("failed entry lacks params: %v", entries[0])
	}
	if params["user"] != "ad" {
		t.Errorf("user = %v, want ad", params["user"])
	}
	for _, key := range []string{"password", "api_key"} {
		if params[key] != "[REDACTED]" {
			t.Errorf("%s = %v, want [REDACTED]", key, params[key])
		}
	}
	if strings.Contains(extractTextFromEntries(t, entries), "hunter2") {
		t.Error("the password leaked into the listing")
	}
}

// extractTextFromEntries re-encodes the listing so a test can search it.
func extractTextFromEntries(t *testing.T, entries []map[string]any) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return string(b)
}

// TestCodeRunner_SuccessfulEntriesCarryNoParams makes sure the full echo
// (no return value) stays as it was for calls that worked.
func TestCodeRunner_SuccessfulEntriesCarryNoParams(t *testing.T) {
	runner := newTestCodeRunner(t, &codeRunnerTestBackend{})
	entries := runEntries(t, runner, `await toolmesh.test_foo({id: 1});`)
	if _, has := entries[0][resultKeyParams]; has {
		t.Errorf("successful entry must not carry params: %v", entries[0])
	}
}

// TestCodeRunner_TextCodecsAvailable checks the standard codecs reach the
// execute_code sandbox: a base64 payload decodes to UTF-8 text in one line.
func TestCodeRunner_TextCodecsAvailable(t *testing.T) {
	runner := newTestCodeRunner(t, &codeRunnerTestBackend{})
	result, err := runner.Execute(testCtx(), `
		const text = new TextDecoder().decode(Uint8Array.from(atob("Z3LDvMOfIEdvdHQ="), c => c.charCodeAt(0)));
		return {text, back: btoa("hello")};
	`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(extractText(t, result)), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["text"] != "grüß Gott" || got["back"] != "aGVsbG8=" {
		t.Errorf("got %v", got)
	}
}
