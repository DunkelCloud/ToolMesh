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
	testHintBackend = "hintful"
	testHintText    = "read the wiki_rules page before writing"
)

// hintfulBackend is a ToolBackend that also reports per-backend hints and can
// resolve a tool to its owning backend — the two capabilities the notifier
// needs to do anything.
type hintfulBackend struct {
	codeRunnerTestBackend
	infos   []backend.BackendInfo
	ownedBy map[string]string // tool name → backend name
}

func (b *hintfulBackend) BackendSummaries() []backend.BackendInfo { return b.infos }

func (b *hintfulBackend) ResolveBackendName(toolName string) (string, bool) {
	name, ok := b.ownedBy[toolName]
	return name, ok
}

func newHintfulBackend(hint string) *hintfulBackend {
	return &hintfulBackend{
		infos:   []backend.BackendInfo{{Name: testHintBackend, Hint: hint}},
		ownedBy: map[string]string{testToolFoo: testHintBackend, testToolBar: testHintBackend},
	}
}

func ctxForUser(userID string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        userID,
		Authenticated: true,
	})
}

func TestHintNotifier_DeliversOncePerPrincipal(t *testing.T) {
	n := newHintNotifier(newHintfulBackend(testHintText))
	if n == nil {
		t.Fatal("expected a notifier for a resolver+summarizer backend")
	}

	first := n.noticeFor(ctxForUser("alice"), testToolFoo)
	if !strings.Contains(first, testHintText) {
		t.Errorf("first call notice = %q, want it to carry the hint", first)
	}
	if !strings.Contains(first, testHintBackend) {
		t.Errorf("first call notice = %q, want it to name the backend", first)
	}

	// Same principal, and a second tool of the same backend: the hint is
	// about the backend, so it is not repeated per tool.
	if again := n.noticeFor(ctxForUser("alice"), testToolBar); again != "" {
		t.Errorf("second call notice = %q, want empty", again)
	}

	// A different principal has not seen it yet.
	if other := n.noticeFor(ctxForUser("bob"), testToolFoo); other == "" {
		t.Error("expected a notice for a principal that has not seen the hint")
	}
}

func TestHintNotifier_SilentWithoutHintOrOwner(t *testing.T) {
	tests := []struct {
		name    string
		backend *hintfulBackend
		tool    string
	}{
		{
			name:    "backend has no hint configured",
			backend: newHintfulBackend(""),
			tool:    testToolFoo,
		},
		{
			name:    "hint is only whitespace",
			backend: newHintfulBackend("   \n "),
			tool:    testToolFoo,
		},
		{
			name:    "no backend owns the tool",
			backend: newHintfulBackend(testHintText),
			tool:    "unowned:tool",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			n := newHintNotifier(tc.backend)
			if notice := n.noticeFor(ctxForUser("alice"), tc.tool); notice != "" {
				t.Errorf("notice = %q, want empty", notice)
			}
		})
	}
}

// A backend that implements neither capability yields no notifier at all, and
// the resulting nil must stay safe to call.
func TestHintNotifier_NilForPlainBackend(t *testing.T) {
	n := newHintNotifier(&codeRunnerTestBackend{})
	if n != nil {
		t.Fatalf("expected nil notifier for a plain backend, got %+v", n)
	}
	if notice := n.noticeFor(ctxForUser("alice"), testToolFoo); notice != "" {
		t.Errorf("nil notifier returned %q, want empty", notice)
	}
}

// Overflow drops the ledger wholesale, so a principal may be told a second
// time. That is the documented trade-off — what must not happen is unbounded
// growth.
func TestHintNotifier_LedgerIsBounded(t *testing.T) {
	n := newHintNotifier(newHintfulBackend(testHintText))

	if !n.markFirstUse("first-key") {
		t.Fatal("expected the first key to be new")
	}
	for i := range maxTrackedHintPrincipals {
		n.markFirstUse(string(rune(i)) + "-filler")
	}

	n.mu.Lock()
	size := len(n.seen)
	n.mu.Unlock()
	if size > maxTrackedHintPrincipals {
		t.Errorf("ledger holds %d entries, want at most %d", size, maxTrackedHintPrincipals)
	}
	if !n.markFirstUse("first-key") {
		t.Error("expected the dropped ledger to treat a known key as new again")
	}
}

// Unauthenticated callers share one bucket rather than each getting a notice.
func TestHintNotifier_UnauthenticatedShareOneBucket(t *testing.T) {
	n := newHintNotifier(newHintfulBackend(testHintText))

	if notice := n.noticeFor(context.Background(), testToolFoo); notice == "" {
		t.Fatal("expected a notice for the first anonymous call")
	}
	if notice := n.noticeFor(context.Background(), testToolFoo); notice != "" {
		t.Errorf("second anonymous notice = %q, want empty", notice)
	}
}

func TestHandleToolCall_HintPrecedesPayload(t *testing.T) {
	hb := newHintfulBackend(testHintText)
	exec := executor.New(nil, nil, hb, nil, nil, 5*time.Second, newQuietMCPLogger(), nil, nil)
	h := NewHandler(exec, hb, nil, "", nil, newQuietMCPLogger(), false)
	ctx := ctxForUser("alice")

	result, err := h.HandleToolCall(ctx, testToolFoo, map[string]any{})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if len(result.Content) != 2 {
		t.Fatalf("content blocks = %d, want 2 (notice + payload): %+v", len(result.Content), result.Content)
	}

	notice, _ := result.Content[0].(map[string]any)
	if text, _ := notice[contentKeyText].(string); !strings.Contains(text, testHintText) {
		t.Errorf("first block = %q, want the hint notice", text)
	}
	// The payload must arrive untouched behind the notice.
	payload, _ := result.Content[1].(map[string]any)
	if text, _ := payload[contentKeyText].(string); text != "ok" {
		t.Errorf("payload block = %q, want the backend response \"ok\"", text)
	}

	// Second call: payload only.
	second, err := h.HandleToolCall(ctx, testToolFoo, map[string]any{})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if len(second.Content) != 1 {
		t.Errorf("second call content blocks = %d, want 1: %+v", len(second.Content), second.Content)
	}
}

// The sandbox hands the tool result straight to the script, so the notice has
// to travel beside it. Folding it into the content would make the script parse
// the note instead of its data.
func TestCodeRunner_HintTravelsBesideResult(t *testing.T) {
	hb := newHintfulBackend(testHintText)
	exec := executor.New(nil, nil, hb, nil, nil, 5*time.Second, newQuietMCPLogger(), nil, nil)
	h := NewHandler(exec, hb, nil, "", nil, newQuietMCPLogger(), false)

	result, err := h.codeRunner.Execute(ctxForUser("alice"), `await toolmesh.test_foo({})`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	entries := decodeCallLog(t, result)
	if len(entries) != 1 {
		t.Fatalf("call log entries = %d, want 1: %+v", len(entries), entries)
	}

	notice, _ := entries[0][resultKeyNotice].(string)
	if !strings.Contains(notice, testHintText) {
		t.Errorf("entry notice = %q, want the hint", notice)
	}

	// The result the script consumed must be exactly what the backend
	// returned — one content block, no notice mixed in.
	callResult, _ := entries[0][resultKeyResult].(map[string]any)
	content, _ := callResult["content"].([]any)
	if len(content) != 1 {
		t.Fatalf("result content blocks = %d, want 1 (notice must stay outside): %+v", len(content), content)
	}
	block, _ := content[0].(map[string]any)
	if text, _ := block[contentKeyText].(string); text != "ok" {
		t.Errorf("result content = %q, want the untouched backend response", text)
	}
}

// Compaction rewrites successful entries; the notice is the one field the
// caller cannot recover from the returned data, so it has to survive.
func TestCompactCallResults_PreservesNotice(t *testing.T) {
	results := []any{map[string]any{
		logKeyTool:      testToolFoo,
		resultKeyNotice: "note",
		resultKeyResult: &backend.ToolResult{
			Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "payload"}},
		},
	}}

	compacted, _ := compactCallResults(results)[0].(map[string]any)
	if compacted[resultKeyStatus] != resultStatusOK {
		t.Errorf("status = %v, want %q", compacted[resultKeyStatus], resultStatusOK)
	}
	if compacted[resultKeyNotice] != "note" {
		t.Errorf("notice = %v, want it preserved through compaction", compacted[resultKeyNotice])
	}
	if _, echoed := compacted[resultKeyResult]; echoed {
		t.Error("compacted entry still carries the full result")
	}
}

// decodeCallLog unwraps the execute_code wire format: a single text block
// holding the JSON array of per-call entries.
func decodeCallLog(t *testing.T, result *backend.ToolResult) []map[string]any {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatal("empty result")
	}
	block, _ := result.Content[0].(map[string]any)
	text, _ := block[contentKeyText].(string)

	var entries []map[string]any
	if err := json.Unmarshal([]byte(text), &entries); err != nil {
		t.Fatalf("decode call log %q: %v", text, err)
	}
	return entries
}
