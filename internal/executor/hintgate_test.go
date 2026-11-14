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
	"errors"
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
	hintGatePlain       = "wiki_ping"
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
	case hintGateWrite:
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
				`toolmesh.assert_proofs(["` + current + `"]);`,
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
	if next == evening || !strings.Contains(resultText(result), next) {
		t.Errorf("refusal does not carry the new day's proof %q:\n%s", next, resultText(result))
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

func TestCheckHintProofs(t *testing.T) {
	day := time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC)
	current := backend.HintProof(hintGateBackendName, hintGateText, day)
	stale := backend.HintProof(hintGateBackendName, hintGateText, day.AddDate(0, 0, -1))

	cases := []struct {
		name        string
		requiredFor []string
		proofs      []string
		wantErr     []string // substrings of the error; nil means no error
	}{
		{"current proof", []string{testAccessWrite}, []string{current}, nil},
		{"no proofs", []string{testAccessWrite}, nil, nil},
		{"stale proof names the note and the new line", []string{testAccessWrite}, []string{stale},
			[]string{"no longer valid", hintGateText, `toolmesh.assert_proofs(["` + current + `"]);`}},
		{"not a proof", []string{testAccessWrite}, []string{"0123456789abcdef"}, []string{"is not a proof"}},
		{"backend that requires none", nil, []string{stale}, nil},
		{"unknown backend", []string{testAccessWrite}, []string{"tickets:0123456789abcdef"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := New(nil, nil, newHintGateBackend(tc.requiredFor...), nil, nil, 30*time.Second, newTestLogger(), nil, nil)
			exec.SetClock(func() time.Time { return day })

			err := exec.CheckHintProofs(tc.proofs)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckHintProofs: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("CheckHintProofs accepted the proofs")
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lacks %q:\n%v", want, err)
				}
			}
		})
	}
}

// A backend set that cannot name the backend of a tool or report hints has
// no hint precondition; calls run as before.
func TestExecuteTool_NoHintPreconditionWithoutSummaries(t *testing.T) {
	exec := New(nil, nil, &mockBackend{}, nil, nil, 30*time.Second, newTestLogger(), nil, nil)
	result, err := exec.ExecuteTool(hintGateCtx(), ExecuteToolRequest{ToolName: hintGateWrite})
	if err != nil || result.IsError {
		t.Fatalf("ExecuteTool = %v, %v, want an executed call", result, err)
	}
	if err := exec.CheckHintProofs([]string{"wiki:0123456789abcdef"}); err != nil {
		t.Errorf("CheckHintProofs: %v", err)
	}
	if err := exec.CheckHintProofs([]string{"nonsense"}); err == nil || errors.Is(err, context.Canceled) {
		t.Errorf("CheckHintProofs accepted a malformed proof: %v", err)
	}
}
