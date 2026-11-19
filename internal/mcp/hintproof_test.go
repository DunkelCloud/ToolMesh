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
	"bytes"
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

const (
	proofTestHint = "Page names follow the naming rules; read them before creating a page."
	// proofTestWrite writes with the tool named in the script, so the
	// check before the run sees it.
	proofTestWrite = `await toolmesh.test_foo({title: "New page"}); return "done";`
	// proofTestComputedWrite reaches the same tool under a name the check
	// before the run cannot see.
	proofTestComputedWrite = `await toolmesh["test_" + "foo"]({title: "New page"});`
	proofTestNoneRan       = "none of the script's calls has run"
	proofTestBadShape      = "must be a list of strings"
)

// proofBackend is a hintful backend whose tools carry access classes:
// test:foo writes, test:bar reads.
type proofBackend struct {
	hintfulBackend
}

func (b *proofBackend) LookupTool(toolName string) (backend.ToolDescriptor, bool) {
	switch toolName {
	case testToolFoo:
		return backend.ToolDescriptor{Name: toolName, Access: ecAccessWrite}, true
	case testToolBar:
		return backend.ToolDescriptor{Name: toolName, Access: testAccessRead}, true
	}
	return backend.ToolDescriptor{}, false
}

// newProofBackend returns a backend whose write tool needs a hint proof, an
// executor over it with the clock fixed at day, and the backend's tools.
func newProofBackend(t *testing.T, day time.Time) (*proofBackend, *executor.Executor, []backend.ToolDescriptor) {
	t.Helper()
	b := &proofBackend{hintfulBackend: *newHintfulBackend(proofTestHint)}
	b.infos[0].HintRequiredFor = []string{ecAccessWrite}

	exec := executor.New(nil, nil, b, nil, nil, 120*time.Second, handlerTestLogger(), nil, nil)
	exec.SetClock(func() time.Time { return day })
	tools, err := b.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	// The runner's descriptors carry the access classes, as a backend set
	// that passes them through its tool list does.
	for i := range tools {
		if d, ok := b.LookupTool(tools[i].Name); ok {
			tools[i].Access = d.Access
		}
	}
	return b, exec, tools
}

// newProofRunner returns a code runner over a backend whose write tool needs
// a hint proof, with the clock fixed at day.
func newProofRunner(t *testing.T, day time.Time) (*CodeRunner, *proofBackend) {
	t.Helper()
	b, exec, tools := newProofBackend(t, day)
	nameMap := map[string]string{sanitizeName(testToolFoo): testToolFoo, sanitizeName(testToolBar): testToolBar}
	return NewCodeRunner(nameMap, tools, exec, nil, handlerTestLogger()), b
}

func calledTools(b *proofBackend) []string {
	names := make([]string, 0, len(b.calls))
	for _, c := range b.calls {
		names = append(names, c.ToolName)
	}
	return names
}

// proofsArg is the argument a refusal prints for one proof.
func proofsArg(proof string) string {
	return `"proofs": ["` + proof + `"]`
}

// A script that names a tool whose hint the caller has yet to receive is
// refused before it runs: the read before the write does not run either,
// and the refusal carries the hint and the argument for the next run.
func TestCodeRunner_HintRefusalBeforeTheRun(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)

	result, err := runner.Execute(ctxForUser("alice"), `
		await toolmesh.test_bar({});
		await toolmesh.test_foo({title: "New page"});
		return "done";
	`)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("result = %+v, want a refusal", result)
	}
	if got := calledTools(b); len(got) != 0 {
		t.Errorf("backend calls = %v, want none", got)
	}
	text := resultText(t, result)
	for _, want := range []string{
		"[ToolMesh note: " + testHintBackend + "] " + proofTestHint,
		proofTestNoneRan,
		"The script calls " + testToolFoo + ", which needs proof",
		proofsArg(backend.HintProof(testHintBackend, proofTestHint, day)),
	} {
		if !strings.Contains(text, want) {
			t.Errorf("refusal lacks %q:\n%s", want, text)
		}
	}
}

func TestCodeRunner_Proofs(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(testHintBackend, proofTestHint, day)
	stale := backend.HintProof(testHintBackend, proofTestHint, day.AddDate(0, 0, -1))
	const read = `await toolmesh.test_bar({}); return "done";`

	cases := []struct {
		name      string
		code      string
		proofs    []string
		wantCalls int
		want      []string // substrings of the refusal; nil means the script completes
	}{
		{"the day's proof", proofTestWrite, []string{current}, 1, nil},
		{"no proof", proofTestWrite, nil, 0, []string{proofTestNoneRan, proofsArg(current)}},
		{"stale proof", proofTestWrite, []string{stale}, 0, []string{"no longer valid", proofTestHint, proofsArg(current)}},
		{"stale proof on a script that only reads", read, []string{stale}, 0, []string{"no longer valid", proofsArg(current)}},
		{"not a proof", proofTestWrite, []string{"0123456789abcdef"}, 0, []string{"is not a proof"}},
		{"a script that only reads needs none", read, nil, 1, nil},
		{"name in brackets", `await toolmesh["test_foo"]({}); return "done";`, nil, 0, []string{proofTestNoneRan}},
		{"name in brackets with single quotes", `await toolmesh['test_foo']({}); return "done";`, nil, 0, []string{proofTestNoneRan}},
		{"optional chaining", `await toolmesh?.test_foo({}); return "done";`, nil, 0, []string{proofTestNoneRan}},
		{"name on the next line", "await toolmesh\n\t.test_foo({}); return 1;", nil, 0, []string{proofTestNoneRan}},
		{"a name in a comment counts", "// later: toolmesh.test_foo\n" + read, nil, 0, []string{proofTestNoneRan}},
		{"another object's member of that name", `const o = {test_foo: 1}; await toolmesh.test_bar({}); return o.test_foo;`, nil, 1, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, b := newProofRunner(t, day)
			result, err := runner.ExecuteWithOptions(ctxForUser("alice"), tc.code, ExecuteOptions{Proofs: tc.proofs})
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if got := len(b.calls); got != tc.wantCalls {
				t.Errorf("backend calls = %d, want %d", got, tc.wantCalls)
			}
			if tc.want == nil {
				if result.IsError {
					t.Fatalf("script was refused:\n%s", resultText(t, result))
				}
				return
			}
			if !result.IsError {
				t.Fatal("script ran, want a refusal")
			}
			text := resultText(t, result)
			for _, want := range tc.want {
				if !strings.Contains(text, want) {
					t.Errorf("refusal lacks %q:\n%s", want, text)
				}
			}
		})
	}
}

// A tool reached under a name the script computes is refused at the call.
// The script stops there even when it catches errors: the calls after it do
// not run, and the refusal reaches the caller.
func TestCodeRunner_HintRefusalAtTheCall(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)

	result, err := runner.Execute(ctxForUser("alice"), `
		await toolmesh.test_bar({});
		try {
			`+proofTestComputedWrite+`
		} catch (e) {
			// carry on
		}
		await toolmesh.test_bar({});
		return "done";
	`)
	if err == nil {
		t.Fatal("script ran to completion, want it to stop at the write")
	}
	if got := calledTools(b); len(got) != 1 || got[0] != testToolBar {
		t.Errorf("backend calls = %v, want only the read before the write", got)
	}
	if result == nil {
		t.Error("no partial result, want the call before the refusal listed")
	}
	for _, want := range []string{
		"[ToolMesh note: " + testHintBackend + "] " + proofTestHint,
		proofsArg(backend.HintProof(testHintBackend, proofTestHint, day)),
		"The script stopped at this call. The 1 call(s) before it were executed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "interrupted") {
		t.Errorf("error reads like a timeout:\n%v", err)
	}
}

// With the proof passed, a computed name runs as any other.
func TestCodeRunner_ComputedNameWithProof(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)
	current := backend.HintProof(testHintBackend, proofTestHint, day)

	if _, err := runner.ExecuteWithOptions(ctxForUser("alice"), proofTestComputedWrite+` return "done";`, ExecuteOptions{Proofs: []string{current}}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := calledTools(b); len(got) != 1 || got[0] != testToolFoo {
		t.Errorf("backend calls = %v, want the write", got)
	}
}

// Proofs belong to the run they were passed with. The next script starts
// without any, as the next conversation does.
func TestCodeRunner_ProofsDoNotOutliveTheRun(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)
	current := backend.HintProof(testHintBackend, proofTestHint, day)

	first, err := runner.ExecuteWithOptions(ctxForUser("alice"), proofTestWrite, ExecuteOptions{Proofs: []string{current}})
	if err != nil || first.IsError {
		t.Fatalf("run with proof = %+v, %v", first, err)
	}
	second, err := runner.Execute(ctxForUser("alice"), proofTestWrite)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !second.IsError {
		t.Fatal("second run wrote without a proof")
	}
	if got := len(b.calls); got != 1 {
		t.Errorf("backend calls = %d, want 1", got)
	}
}

// A script has no way to present a proof: the proofs are an argument of the
// run. So a script cannot take the proof out of a refusal and carry on by
// itself; whoever started it has to run it again.
func TestCodeRunner_ScriptCannotPresentProofs(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)
	current := backend.HintProof(testHintBackend, proofTestHint, day)

	_, err := runner.Execute(ctxForUser("alice"), `toolmesh.assert_proofs(["`+current+`"]); `+proofTestComputedWrite)
	if err == nil {
		t.Fatal("script ran to completion")
	}
	if got := len(b.calls); got != 0 {
		t.Errorf("backend calls = %d, want none", got)
	}
}

// The proofs reach a run as an argument of execute_code.
func TestHandleExecuteCode_Proofs(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(testHintBackend, proofTestHint, day)

	cases := []struct {
		name      string
		proofs    any
		wantCalls int
		want      string // substring of the error result; "" means the script completes
	}{
		{"left out", nil, 0, proofsArg(current)},
		{"list", []any{current}, 1, ""},
		{"single string", current, 1, ""},
		{"list as a string", `["` + current + `"]`, 1, ""},
		{"empty string", "", 0, proofsArg(current)},
		{"not a list of strings", []any{42}, 0, proofTestBadShape},
		{"a number", 42, 0, proofTestBadShape},
		{"a broken list", `["` + current, 0, proofTestBadShape},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, exec, _ := newProofBackend(t, day)
			h := NewHandler(exec, b, nil, "", nil, handlerTestLogger(), false)

			params := map[string]any{argNameCode: proofTestWrite}
			if tc.proofs != nil {
				params[argNameProofs] = tc.proofs
			}
			result := h.handleExecuteCode(ctxForUser("alice"), params)
			if got := len(b.calls); got != tc.wantCalls {
				t.Errorf("backend calls = %d, want %d", got, tc.wantCalls)
			}
			if tc.want == "" {
				if result.IsError {
					t.Fatalf("script was refused:\n%s", resultText(t, result))
				}
				return
			}
			if !result.IsError || !strings.Contains(resultText(t, result), tc.want) {
				t.Errorf("result lacks %q:\n%s", tc.want, resultText(t, result))
			}
		})
	}
}

// The tool list tells a client that execute_code takes proofs.
func TestBuildToolList_ExecuteCodeTakesProofs(t *testing.T) {
	b, exec, _ := newProofBackend(t, time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC))
	h := NewHandler(exec, b, nil, "", nil, handlerTestLogger(), false)

	tools, err := h.BuildToolList(ctxForUser("alice"))
	if err != nil {
		t.Fatalf("BuildToolList: %v", err)
	}
	for _, tool := range tools {
		if tool.Name != toolExecuteCode {
			continue
		}
		props, _ := tool.InputSchema[schemaKeyProperties].(map[string]any)
		proofs, _ := props[argNameProofs].(map[string]any)
		if proofs[contentKeyType] != jsonTypeArray {
			t.Errorf("proofs property = %v, want an array", proofs)
		}
		if required, _ := tool.InputSchema[schemaKeyRequired].([]string); !reflect.DeepEqual(required, []string{argNameCode}) {
			t.Errorf("required = %v, want only %s", required, argNameCode)
		}
		return
	}
	t.Fatalf("no %s in the tool list", toolExecuteCode)
}

// A hint that is a precondition reaches the caller with the refusal. The
// first-use notice, which a second conversation of the same user never
// gets, stays out of it.
func TestHintNotifier_SilentForRequiredHint(t *testing.T) {
	b := newHintfulBackend(testHintText)
	b.infos[0].HintRequiredFor = []string{ecAccessWrite}

	n := newHintNotifier(b)
	if notice := n.noticeFor(ctxForUser("alice"), testToolBar); notice != "" {
		t.Errorf("notice = %q, want none for a backend with hint_required_for", notice)
	}
}

// An entry that covers no tool of its backend refuses nothing. The log says
// so when the tool list is built, and stays quiet about a backend that has
// no tools yet.
func TestWarnUnmatchedHintEntries(t *testing.T) {
	b, _, tools := newProofBackend(t, time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC))
	b.infos[0].HintRequiredFor = []string{ecAccessWrite, "creat_page"}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	warnUnmatchedHintEntries(b, tools, logger)
	out := buf.String()
	if !strings.Contains(out, "entry=creat_page") || !strings.Contains(out, "backend="+testHintBackend) {
		t.Errorf("log does not name the entry that covers no tool:\n%s", out)
	}
	if strings.Contains(out, "entry="+ecAccessWrite) {
		t.Errorf("log reports an entry that covers a tool:\n%s", out)
	}

	buf.Reset()
	warnUnmatchedHintEntries(b, nil, logger)
	if buf.Len() != 0 {
		t.Errorf("log reports entries of a backend without tools:\n%s", buf.String())
	}
}
