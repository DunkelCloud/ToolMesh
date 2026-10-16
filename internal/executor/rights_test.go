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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names shared by the kit tests.
const (
	testKitNetDiag    = "net-diag-read"
	testGraylogSearch = "graylog_search"
	testGraylogDelete = "graylog_delete_stream"
	testUnifiClients  = "unifi_list_clients"
	testUserBob       = "bob"
	testUserCarol     = "carol"
	testUserOwner     = "owner"
)

// classifiedBackend owns tools by their bare names with a DADL access
// classification each.
type classifiedBackend struct {
	access map[string]string
}

func (b *classifiedBackend) Execute(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}}}, nil
}

func (b *classifiedBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	out := make([]backend.ToolDescriptor, 0, len(b.access))
	for name, access := range b.access {
		out = append(out, backend.ToolDescriptor{Name: name, Access: access})
	}
	return out, nil
}

func (b *classifiedBackend) LookupTool(name string) (backend.ToolDescriptor, bool) {
	access, ok := b.access[name]
	return backend.ToolDescriptor{Name: name, Access: access}, ok
}

func (b *classifiedBackend) Healthy(_ context.Context) error { return nil }

// newKitExecutor builds an executor on the embedded engine with the owner
// granted everything, carol denied graylog_search, and one kit covering the
// read tools of graylog and unifi.
func newKitExecutor(t *testing.T) (*Executor, *recordingAudit) {
	t.Helper()
	engine, err := authz.OpenEmbedded(context.Background(), authz.EmbeddedOptions{Path: filepath.Join(t.TempDir(), authz.DBFileName)})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.ApplyPolicy(context.Background(), authz.Policy{
		Grants: []authz.Grant{{User: testUserOwner, AllTools: true}},
		Denies: []authz.Grant{{User: testUserCarol, Tools: []string{testGraylogSearch}}},
		Kits: []authz.Kit{{
			Name:        testKitNetDiag,
			Description: "Network diagnosis (read-only)",
			Grants:      []string{"graylog:read", "unifi:read"},
			TTLDefault:  4 * time.Hour,
		}},
	}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		"graylog": &classifiedBackend{access: map[string]string{"search": "read", "delete_stream": "write"}},
		"unifi":   &classifiedBackend{access: map[string]string{"list_clients": "read"}},
	})
	rec := &recordingAudit{}
	return New(engine, nil, composite, nil, rec, time.Second, newTestLogger(), nil, nil), rec
}

func descriptors(names ...string) []backend.ToolDescriptor {
	out := make([]backend.ToolDescriptor, len(names))
	for i, n := range names {
		out[i] = backend.ToolDescriptor{Name: n}
	}
	return out
}

func TestAssessTools(t *testing.T) {
	exec, _ := newKitExecutor(t)
	tools := descriptors(testGraylogSearch, testGraylogDelete, testUnifiClients)

	tests := []struct {
		name    string
		user    string
		verify  bool
		verdict []string
		kits    [][]string
		blocked []bool
	}{
		{
			name:    "owner may call everything",
			user:    testUserOwner,
			verify:  true,
			verdict: []string{VerdictAllowed, VerdictAllowed, VerdictAllowed},
			kits:    [][]string{nil, nil, nil},
			blocked: []bool{false, false, false},
		},
		{
			name:    "kit covers the read tools only",
			user:    testUserBob,
			verify:  true,
			verdict: []string{VerdictEscalatable, VerdictDenied, VerdictEscalatable},
			kits:    [][]string{{testKitNetDiag}, nil, {testKitNetDiag}},
			blocked: []bool{false, false, false},
		},
		{
			name:    "a deny is not lifted by the kit",
			user:    testUserCarol,
			verify:  true,
			verdict: []string{VerdictDenied, VerdictDenied, VerdictEscalatable},
			kits:    [][]string{nil, nil, {testKitNetDiag}},
			blocked: []bool{true, false, false},
		},
		{
			name:    "without verification the definition counts",
			user:    testUserCarol,
			verify:  false,
			verdict: []string{VerdictEscalatable, VerdictDenied, VerdictEscalatable},
			kits:    [][]string{{testKitNetDiag}, nil, {testKitNetDiag}},
			blocked: []bool{false, false, false},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := exec.AssessTools(context.Background(), &userctx.UserContext{UserID: tc.user}, tools, tc.verify)
			for i, r := range got {
				if r.Verdict != tc.verdict[i] || !slices.Equal(r.Kits, tc.kits[i]) || r.Blocked != tc.blocked[i] {
					t.Errorf("%s: verdict=%s kits=%v blocked=%v, want %s %v %v",
						r.Tool, r.Verdict, r.Kits, r.Blocked, tc.verdict[i], tc.kits[i], tc.blocked[i])
				}
			}
			if got[0].Backend != "graylog" || got[2].Backend != "unifi" {
				t.Errorf("backends = %q, %q, want graylog, unifi", got[0].Backend, got[2].Backend)
			}
		})
	}
}

func TestAssessTools_AuthorizationDisabled(t *testing.T) {
	exec := New(nil, nil, &mockBackend{}, nil, nil, time.Second, newTestLogger(), nil, nil)
	got := exec.AssessTools(context.Background(), &userctx.UserContext{UserID: "u"}, descriptors("a_b"), true)
	if got[0].Verdict != VerdictAllowed {
		t.Errorf("verdict = %s with authorization disabled, want allowed", got[0].Verdict)
	}
	if exec.Authorizes() || exec.Kits() != nil {
		t.Error("an executor without authorizer reports authorization or kits")
	}
}

func TestExecuteTool_DenialNamesKit(t *testing.T) {
	exec, rec := newKitExecutor(t)

	res, err := exec.ExecuteTool(callerCtx(&userctx.UserContext{UserID: testUserBob}), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	text := resultText(res)
	for _, want := range []string{"not authorized to execute tool " + testGraylogSearch, `"` + testKitNetDiag + `" (Network diagnosis (read-only))`, RightsToolName} {
		if !res.IsError || !strings.Contains(text, want) {
			t.Errorf("denial %q does not contain %q", text, want)
		}
	}
	if rec.last.Status != statusDenied || rec.last.Metadata["remedy_kits"] != testKitNetDiag {
		t.Errorf("audit = %s %v, want denied with remedy_kits=%s", rec.last.Status, rec.last.Metadata, testKitNetDiag)
	}

	// No kit covers the write tool: the plain denial, nothing to point to.
	res, err = exec.ExecuteTool(callerCtx(&userctx.UserContext{UserID: testUserBob}), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if text := resultText(res); strings.Contains(text, "kit") || strings.Contains(text, RightsToolName) {
		t.Errorf("denial without a covering kit mentions one: %q", text)
	}
	if rec.last.Metadata != nil {
		t.Errorf("audit metadata = %v, want none", rec.last.Metadata)
	}

	// Carol's deny is not lifted by the kit, so the kit is not offered.
	res, err = exec.ExecuteTool(callerCtx(&userctx.UserContext{UserID: testUserCarol}), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if text := resultText(res); strings.Contains(text, testKitNetDiag) {
		t.Errorf("denial offers a kit that a deny overrides: %q", text)
	}
}

func TestAuditRightsQuery(t *testing.T) {
	exec, rec := newKitExecutor(t)
	ctx := callerCtx(&userctx.UserContext{UserID: testUserBob, CallerID: "agent-1"})

	exec.AuditRightsQuery(ctx, map[string]any{"tools": []any{testGraylogSearch}, "token": "secret"}, time.Now(), "")
	if rec.last.Tool != RightsToolName || rec.last.UserID != testUserBob || rec.last.CallerID != "agent-1" || rec.last.Status != statusSuccess {
		t.Errorf("audit entry = %+v", rec.last)
	}
	if rec.last.Params["token"] != "[REDACTED]" {
		t.Errorf("audit params = %v, want the token redacted", rec.last.Params)
	}

	exec.AuditRightsQuery(ctx, nil, time.Now(), "bad arguments")
	if rec.last.Status != statusError || rec.last.Error != "bad arguments" {
		t.Errorf("audit entry of a failed query = %s %q", rec.last.Status, rec.last.Error)
	}
}

func resultText(res *backend.ToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if m, ok := c.(map[string]any); ok {
			if s, ok := m[contentKeyText].(string); ok {
				sb.WriteString(s)
			}
		}
	}
	return sb.String()
}

// fixedKits is a KitHolder that grants the same kits to one user as one
// caller.
type fixedKits struct {
	user, caller string
	kits         []string
}

func (f fixedKits) HeldKits(_ context.Context, userID, callerID string) []string {
	if userID == f.user && callerID == f.caller {
		return f.kits
	}
	return nil
}

func TestKitHolder(t *testing.T) {
	const agent = "agent-1"
	exec, rec := newKitExecutor(t)
	exec.SetKitHolder(fixedKits{user: testUserBob, caller: agent, kits: []string{testKitNetDiag}})
	bob := &userctx.UserContext{UserID: testUserBob, CallerID: agent, Authenticated: true}

	rights := exec.AssessTools(context.Background(), bob, descriptors(testGraylogSearch, testGraylogDelete), true)
	if rights[0].Verdict != VerdictAllowed || rights[1].Verdict != VerdictDenied {
		t.Errorf("rights = %+v, want the kit's read tool allowed and the write tool denied", rights)
	}

	res, err := exec.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil || res.IsError {
		t.Fatalf("ExecuteTool with the kit = %v, %v", resultText(res), err)
	}
	if rec.last.Status != statusSuccess || rec.last.Metadata["held_kits"] != testKitNetDiag {
		t.Errorf("audit = %s %v, want success with held_kits", rec.last.Status, rec.last.Metadata)
	}
	if err := exec.CheckChild(callerCtx(bob), testUnifiClients, nil); err != nil {
		t.Errorf("CheckChild with the kit: %v", err)
	}

	// A denial now points to request_grant.
	res, _ = exec.ExecuteTool(callerCtx(&userctx.UserContext{UserID: testUserBob, CallerID: "agent-2", Authenticated: true}), ExecuteToolRequest{ToolName: testGraylogSearch})
	if !res.IsError || !strings.Contains(resultText(res), RequestGrantToolName) {
		t.Errorf("denial for another caller = %q, want it to point to %s", resultText(res), RequestGrantToolName)
	}

	// Only an authenticated caller holds kits.
	anon := &userctx.UserContext{UserID: testUserBob, CallerID: agent}
	if err := exec.CheckChild(callerCtx(anon), testUnifiClients, nil); err == nil {
		t.Error("an unauthenticated caller was granted the kit")
	}
}
