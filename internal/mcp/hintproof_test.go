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
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

const proofTestHint = "Page names follow the naming rules; read them before creating a page."

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

// newProofRunner returns a code runner over a backend whose write tool needs
// a hint proof, with the clock fixed at day.
func newProofRunner(t *testing.T, day time.Time) (*CodeRunner, *proofBackend) {
	t.Helper()
	b := &proofBackend{hintfulBackend: *newHintfulBackend(proofTestHint)}
	b.infos[0].HintRequiredFor = []string{ecAccessWrite}

	logger := handlerTestLogger()
	exec := executor.New(nil, nil, b, nil, nil, 120*time.Second, logger, nil, nil)
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
	nameMap := map[string]string{sanitizeName(testToolFoo): testToolFoo, sanitizeName(testToolBar): testToolBar}
	return NewCodeRunner(nameMap, tools, exec, nil, logger), b
}

func calledTools(b *proofBackend) []string {
	names := make([]string, 0, len(b.calls))
	for _, c := range b.calls {
		names = append(names, c.ToolName)
	}
	return names
}

// A script that writes without a proof stops at the write. The error carries
// the hint and the line to start the next run with, and says which calls
// already ran.
func TestCodeRunner_HintRefusalStopsScript(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)

	result, err := runner.Execute(ctxForUser("alice"), `
		await toolmesh.test_bar({});
		await toolmesh.test_foo({title: "New page"});
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
	proof := backend.HintProof(testHintBackend, proofTestHint, day)
	for _, want := range []string{
		"[ToolMesh note: " + testHintBackend + "] " + proofTestHint,
		`toolmesh.assert_proofs(["` + proof + `"]);`,
		"The 1 call(s) before it were executed",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestCodeRunner_AssertProofs(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(testHintBackend, proofTestHint, day)
	stale := backend.HintProof(testHintBackend, proofTestHint, day.AddDate(0, 0, -1))
	const write = `await toolmesh.test_foo({title: "New page"}); return "done";`

	cases := []struct {
		name      string
		code      string
		wantCalls int
		wantErr   []string // substrings of the error; nil means the script completes
	}{
		{"array with the day's proof", `toolmesh.assert_proofs(["` + current + `"]); ` + write, 1, nil},
		{"single string", `toolmesh.assert_proofs("` + current + `"); ` + write, 1, nil},
		{"awaited", `await toolmesh.assert_proofs(["` + current + `"]); ` + write, 1, nil},
		{"stale proof fails before any call", `toolmesh.assert_proofs(["` + stale + `"]); ` + write, 0,
			[]string{"no longer valid", proofTestHint, `toolmesh.assert_proofs(["` + current + `"]);`}},
		{"not an array of strings", `toolmesh.assert_proofs(42); ` + write, 0, []string{"array of strings"}},
		{"nothing asserted", write, 0, []string{"None of its calls was executed"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, b := newProofRunner(t, day)
			_, err := runner.Execute(ctxForUser("alice"), tc.code)
			if got := len(b.calls); got != tc.wantCalls {
				t.Errorf("backend calls = %d, want %d", got, tc.wantCalls)
			}
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Execute: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("script ran to completion")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q:\n%v", want, err)
				}
			}
		})
	}
}

// Proofs belong to the run that asserted them. The next script starts
// without any, as the next conversation does.
func TestCodeRunner_ProofsDoNotOutliveTheRun(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	runner, b := newProofRunner(t, day)
	current := backend.HintProof(testHintBackend, proofTestHint, day)
	const write = `await toolmesh.test_foo({title: "New page"}); return "done";`

	if _, err := runner.Execute(ctxForUser("alice"), `toolmesh.assert_proofs(["`+current+`"]); `+write); err != nil {
		t.Fatalf("run with proof: %v", err)
	}
	if _, err := runner.Execute(ctxForUser("alice"), write); err == nil {
		t.Fatal("second run wrote without asserting a proof")
	}
	if got := len(b.calls); got != 1 {
		t.Errorf("backend calls = %d, want 1", got)
	}
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
