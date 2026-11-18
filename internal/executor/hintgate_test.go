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

package executor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	hintGateBackendName = "wiki"
	hintGateText        = "Page names follow the naming rules; read them before creating a page."
	hintGateRead        = "wiki_read_page"
	hintGateWrite       = "wiki_create_page"
	// hintGateWriteBare is hintGateWrite as the backend calls it.
	hintGateWriteBare = "create_page"
	hintGateEdit      = "wiki_edit_page"
	hintGatePlain     = "wiki_ping"
	// hintGateOtherProof is a proof for a backend the gateway does not know.
	hintGateOtherProof = "tickets:0123456789abcdef"
)

// hintGateBackend is a backend whose tools carry access classes and whose
// summary carries a hint, the two things the hint precondition reads.
type hintGateBackend struct {
	mockBackend
	infos    []backend.BackendInfo
	executed []string
}

func newHintGateBackend(requiredFor ...string) *hintGateBackend {
	b := &hintGateBackend{
		infos: []backend.BackendInfo{{
			Name:            hintGateBackendName,
			Hint:            hintGateText,
			HintRequiredFor: requiredFor,
		}},
	}
	b.executeFunc = func(_ context.Context, toolName string, _ map[string]any) (*backend.ToolResult, error) {
		b.executed = append(b.executed, toolName)
		return &backend.ToolResult{
			Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}},
		}, nil
	}
	return b
}

func (b *hintGateBackend) LookupTool(toolName string) (backend.ToolDescriptor, bool) {
	switch toolName {
	case hintGateRead:
		return backend.ToolDescriptor{Name: toolName, Access: testAccessRead}, true
	case hintGateWrite, hintGateEdit:
		return backend.ToolDescriptor{Name: toolName, Access: testAccessWrite}, true
	case hintGatePlain:
		return backend.ToolDescriptor{Name: toolName}, true
	}
	return backend.ToolDescriptor{}, false
}

func (b *hintGateBackend) BackendSummaries() []backend.BackendInfo { return b.infos }

func (b *hintGateBackend) ResolveBackendName(toolName string) (string, bool) {
	if strings.HasPrefix(toolName, hintGateBackendName+"_") {
		return hintGateBackendName, true
	}
	return "", false
}

// denyAll is an authorizer that allows nothing.
type denyAll struct{}

func (denyAll) Check(context.Context, authz.Request) (bool, error) { return false, nil }
func (denyAll) Healthy(context.Context) error                      { return nil }
func (denyAll) Close() error                                       { return nil }

func hintGateCtx() context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})
}

// proofsArg is the argument a refusal prints for the given proofs.
func proofsArg(proofs ...string) string {
	return proofsArgument(proofs)
}

func TestExecuteTool_HintPrecondition(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(hintGateBackendName, hintGateText, day)

	cases := []struct {
		name        string
		requiredFor []string
		tool        string
		proofs      []string
		wantRefused bool
	}{
		{"write without proof", []string{testAccessWrite}, hintGateWrite, nil, true},
		{"write with the day's proof", []string{testAccessWrite}, hintGateWrite, []string{current}, false},
		{"write with yesterday's proof", []string{testAccessWrite}, hintGateWrite,
			[]string{backend.HintProof(hintGateBackendName, hintGateText, day.AddDate(0, 0, -1))}, true},
		{"write with the proof of another hint", []string{testAccessWrite}, hintGateWrite,
			[]string{backend.HintProof(hintGateBackendName, "another wording", day)}, true},
		{"read is not listed", []string{testAccessWrite}, hintGateRead, nil, false},
		{"unclassified tool is not matched by a class", []string{testAccessWrite}, hintGatePlain, nil, false},
		{"all covers an unclassified tool", []string{backend.HintAccessAll}, hintGatePlain, nil, true},
		{"tool listed by name", []string{hintGateWriteBare}, hintGateWrite, nil, true},
		{"another tool of the class of a listed tool", []string{hintGateWriteBare}, hintGateEdit, nil, false},
		{"hint as advice only", nil, hintGateWrite, nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newHintGateBackend(tc.requiredFor...)
			rec := &recordingAudit{}
			exec := New(nil, nil, be, nil, rec, 30*time.Second, newTestLogger(), nil, nil)
			exec.SetClock(func() time.Time { return day })

			result, err := exec.ExecuteTool(hintGateCtx(), ExecuteToolRequest{
				ToolName:   tc.tool,
				HintProofs: tc.proofs,
			})
			if err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}

			if !tc.wantRefused {
				if result.IsError {
					t.Fatalf("call was refused: %s", resultText(result))
				}
				if len(be.executed) != 1 {
					t.Errorf("backend executed %v, want one call", be.executed)
				}
				return
			}

			if !result.IsError {
				t.Fatal("call was executed, want a refusal")
			}
			if len(be.executed) != 0 {
				t.Errorf("backend executed %v, want no call", be.executed)
			}
			text := resultText(result)
			for _, want := range []string{
				"[ToolMesh note: " + hintGateBackendName + "] " + hintGateText,
				proofsArg(current),
			} {
				if !strings.Contains(text, want) {
					t.Errorf("refusal lacks %q:\n%s", want, text)
				}
			}
			if got := result.Metadata[backend.MetadataKeyHintRequired]; got != hintGateBackendName {
				t.Errorf("result metadata %s = %v, want %q", backend.MetadataKeyHintRequired, got, hintGateBackendName)
			}
			if rec.last.Status != statusDenied || rec.last.Error != errHintProofMissing {
				t.Errorf("audit status = %q, error = %q, want %q, %q", rec.last.Status, rec.last.Error, statusDenied, errHintProofMissing)
			}
			if got := rec.last.Metadata[metaHintRequired]; got != hintGateBackendName {
				t.Errorf("audit metadata %s = %q, want %q", metaHintRequired, got, hintGateBackendName)
			}
		})
	}
}

// A proof handed out late in the evening stops working at midnight UTC: the
// call is refused again and the refusal carries the new day's proof.
func TestExecuteTool_HintProofExpiresWithTheDay(t *testing.T) {
	be := newHintGateBackend(testAccessWrite)
	exec := New(nil, nil, be, nil, nil, 30*time.Second, newTestLogger(), nil, nil)

	now := time.Date(2026, 3, 14, 23, 59, 0, 0, time.UTC)
	exec.SetClock(func() time.Time { return now })
	evening := backend.HintProof(hintGateBackendName, hintGateText, now)

	call := func() *backend.ToolResult {
		t.Helper()
		result, err := exec.ExecuteTool(hintGateCtx(), ExecuteToolRequest{
			ToolName:   hintGateWrite,
			HintProofs: []string{evening},
		})
		if err != nil {
			t.Fatalf("ExecuteTool: %v", err)
		}
		return result
	}

	if result := call(); result.IsError {
		t.Fatalf("refused on the day of the proof: %s", resultText(result))
	}

	now = now.Add(2 * time.Minute)
	result := call()
	if !result.IsError {
		t.Fatal("executed with the proof of the day before")
	}
	next := backend.HintProof(hintGateBackendName, hintGateText, now)
	text := resultText(result)
	if next == evening || !strings.Contains(text, proofsArg(next)) {
		t.Errorf("refusal does not print the new day's proof alone, %s:\n%s", proofsArg(next), text)
	}
}

// A caller that may not call the tool is told so and nothing more: the hint
// is operator text and goes only to callers that may act on it.
func TestExecuteTool_HintComesAfterAuthorization(t *testing.T) {
	be := newHintGateBackend(testAccessWrite)
	exec := New(denyAll{}, nil, be, nil, nil, 30*time.Second, newTestLogger(), nil, nil)

	result, err := exec.ExecuteTool(hintGateCtx(), ExecuteToolRequest{ToolName: hintGateWrite})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("call was executed, want a denial")
	}
	if text := resultText(result); strings.Contains(text, hintGateText) {
		t.Errorf("denial carries the hint:\n%s", text)
	}
}

// The check before a script runs: what the proofs passed with it and the
// tools it names add up to.
func TestHintPreflight(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(hintGateBackendName, hintGateText, day)
	stale := backend.HintProof(hintGateBackendName, hintGateText, day.AddDate(0, 0, -1))
	older := backend.HintProof(hintGateBackendName, hintGateText, day.AddDate(0, 0, -2))
	note := "[ToolMesh note: " + hintGateBackendName + "] " + hintGateText
	const noneRan = "none of the script's calls has run"

	cases := []struct {
		name        string
		requiredFor []string
		tools       []string
		proofs      []string
		want        []string // substrings of the refusal; nil means the script may run
		wantAudited string   // tool of the audit entry, "" for none
	}{
		{"names a tool that needs a proof", []string{testAccessWrite}, []string{hintGateRead, hintGateWrite}, nil,
			[]string{note, noneRan, "The script calls " + hintGateWrite + ", which needs proof", proofsArg(current)}, hintGateWrite},
		{"names two such tools", []string{testAccessWrite}, []string{hintGateWrite, hintGateEdit, hintGateWrite}, nil,
			[]string{"The script calls " + hintGateWrite + ", " + hintGateEdit + ", which need proof", proofsArg(current)}, hintGateEdit},
		{"carries the day's proof", []string{testAccessWrite}, []string{hintGateWrite}, []string{current}, nil, ""},
		{"names only tools that are not listed", []string{testAccessWrite}, []string{hintGateRead, hintGatePlain}, nil, nil, ""},
		{"names a tool listed by name", []string{hintGateWriteBare}, []string{hintGateWrite}, nil,
			[]string{note, proofsArg(current)}, hintGateWrite},
		{"names another tool of that class", []string{hintGateWriteBare}, []string{hintGateEdit}, nil, nil, ""},
		{"stale proof and the tool", []string{testAccessWrite}, []string{hintGateWrite}, []string{stale},
			[]string{note, noneRan, "which needs proof", "The proof passed for " + hintGateBackendName + " is no longer valid", proofsArg(current)}, hintGateWrite},
		{"stale proof, no such tool named", []string{testAccessWrite}, []string{hintGateRead}, []string{stale},
			[]string{note, "is no longer valid", proofsArg(current)}, ""},
		{"two stale proofs become one current", []string{testAccessWrite}, nil, []string{older, stale},
			[]string{proofsArg(current)}, ""},
		{"a stale proof next to the current one", []string{testAccessWrite}, []string{hintGateWrite}, []string{stale, current}, nil, ""},
		{"proofs of other backends stay in the argument", []string{testAccessWrite}, []string{hintGateWrite}, []string{hintGateOtherProof},
			[]string{proofsArg(hintGateOtherProof, current)}, hintGateWrite},
		{"not a proof", []string{testAccessWrite}, nil, []string{"0123456789abcdef"}, []string{"is not a proof"}, ""},
		{"stale proof for a backend that requires none", nil, []string{hintGateWrite}, []string{stale}, nil, ""},
		{"proof for an unknown backend", []string{testAccessWrite}, []string{hintGateRead}, []string{hintGateOtherProof}, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := newHintGateBackend(tc.requiredFor...)
			rec := &recordingAudit{}
			exec := New(nil, nil, be, nil, rec, 30*time.Second, newTestLogger(), nil, nil)
			exec.SetClock(func() time.Time { return day })

			refusal := exec.HintPreflight(hintGateCtx(), tc.tools, tc.proofs)
			if tc.want == nil && refusal != "" {
				t.Fatalf("script refused:\n%s", refusal)
			}
			if tc.want != nil && refusal == "" {
				t.Fatal("script may run, want a refusal")
			}
			for _, want := range tc.want {
				if !strings.Contains(refusal, want) {
					t.Errorf("refusal lacks %q:\n%s", want, refusal)
				}
			}
			if strings.Count(refusal, note) > 1 {
				t.Errorf("refusal carries the note more than once:\n%s", refusal)
			}
			if len(be.executed) != 0 {
				t.Errorf("backend executed %v, want no call", be.executed)
			}

			if tc.wantAudited == "" {
				if rec.last.Tool != "" {
					t.Errorf("audit entry for %q, want none", rec.last.Tool)
				}
				return
			}
			if rec.last.Tool != tc.wantAudited || rec.last.Status != statusDenied || rec.last.Error != errHintProofMissing {
				t.Errorf("audit entry = %q, %q, %q, want %q, %q, %q",
					rec.last.Tool, rec.last.Status, rec.last.Error, tc.wantAudited, statusDenied, errHintProofMissing)
			}
			if got := rec.last.Metadata[metaHintRequired]; got != hintGateBackendName {
				t.Errorf("audit metadata %s = %q, want %q", metaHintRequired, got, hintGateBackendName)
			}
		})
	}
}

// A caller that may not call the tool is not refused here: the script runs
// into the denial at the call, and the hint stays with callers that may act
// on it.
func TestHintPreflight_ComesAfterAuthorization(t *testing.T) {
	be := newHintGateBackend(testAccessWrite)
	rec := &recordingAudit{}
	exec := New(denyAll{}, nil, be, nil, rec, 30*time.Second, newTestLogger(), nil, nil)

	if refusal := exec.HintPreflight(hintGateCtx(), []string{hintGateWrite}, nil); refusal != "" {
		t.Errorf("script refused with the hint:\n%s", refusal)
	}
	if rec.last.Tool != "" {
		t.Errorf("audit entry for %q, want none", rec.last.Tool)
	}
}

// A backend set that cannot name the backend of a tool or report hints has
// no hint precondition; calls and scripts run as before.
func TestExecuteTool_NoHintPreconditionWithoutSummaries(t *testing.T) {
	exec := New(nil, nil, &mockBackend{}, nil, nil, 30*time.Second, newTestLogger(), nil, nil)
	result, err := exec.ExecuteTool(hintGateCtx(), ExecuteToolRequest{ToolName: hintGateWrite})
	if err != nil || result.IsError {
		t.Fatalf("ExecuteTool = %v, %v, want an executed call", result, err)
	}
	if refusal := exec.HintPreflight(hintGateCtx(), []string{hintGateWrite}, []string{hintGateOtherProof}); refusal != "" {
		t.Errorf("HintPreflight refused:\n%s", refusal)
	}
	if refusal := exec.HintPreflight(hintGateCtx(), nil, []string{"nonsense"}); !strings.Contains(refusal, "is not a proof") {
		t.Errorf("HintPreflight accepted a malformed proof: %q", refusal)
	}
}
