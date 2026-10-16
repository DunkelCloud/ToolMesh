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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names shared by the kit tests.
const (
	testKitNetDiag      = "net-diag-read"
	testGraylogSearch   = "graylog_search"
	testGraylogDelete   = "graylog_delete_stream"
	testUnifiClients    = "unifi_list_clients"
	testVaultFetch      = "vault_fetch"
	testBackendVault    = "vault"
	testAccessRead      = "read"
	testKitWide         = "wide"
	testBackendGraylog  = "graylog"
	testKitUserBob      = "bob"
	testKitUserOwner    = "owner"
	testUnknownToolName = "nope_tool"
)

// kitTestBackend owns tools by their bare names with a DADL access
// classification each.
type kitTestBackend struct {
	access map[string]string
}

func (b *kitTestBackend) Execute(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "{}"}}}, nil
}

func (b *kitTestBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	out := make([]backend.ToolDescriptor, 0, len(b.access))
	for name, access := range b.access {
		out = append(out, backend.ToolDescriptor{Name: name, Description: "Tool " + name + ".", Access: access})
	}
	slices.SortFunc(out, func(a, b backend.ToolDescriptor) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (b *kitTestBackend) LookupTool(name string) (backend.ToolDescriptor, bool) {
	access, ok := b.access[name]
	return backend.ToolDescriptor{Name: name, Access: access}, ok
}

func (b *kitTestBackend) Healthy(_ context.Context) error { return nil }

// rightsAudit keeps every recorded entry.
type rightsAudit struct {
	entries []audit.AuditEntry
}

func (a *rightsAudit) Record(_ context.Context, e audit.AuditEntry) error {
	a.entries = append(a.entries, e)
	return nil
}

func (a *rightsAudit) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, audit.ErrQueryNotSupported
}

func (a *rightsAudit) Healthy(_ context.Context) error { return nil }

// newKitHandler builds a handler on the embedded engine: the owner may call
// everything, and the kit net-diag-read covers the read tools of graylog and
// unifi. The backend "vault" is covered by nothing.
func newKitHandler(t *testing.T) (*Handler, *rightsAudit) {
	t.Helper()
	engine, err := authz.OpenEmbedded(context.Background(), authz.EmbeddedOptions{Path: filepath.Join(t.TempDir(), authz.DBFileName)})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.ApplyPolicy(context.Background(), authz.Policy{
		Grants: []authz.Grant{{User: testKitUserOwner, AllTools: true}},
		Kits: []authz.Kit{{
			Name:        testKitNetDiag,
			Description: "Network diagnosis (read-only)",
			Warning:     "Production systems.",
			Grants:      []string{"graylog:read", "unifi:read"},
			TTLDefault:  4 * time.Hour,
			TTLMax:      90 * time.Minute * 16,
		}},
	}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		testBackendGraylog: &kitTestBackend{access: map[string]string{"search": testAccessRead, "delete_stream": "write"}},
		"unifi":            &kitTestBackend{access: map[string]string{"list_clients": testAccessRead}},
		testBackendVault:   &kitTestBackend{access: map[string]string{"fetch": testAccessRead}},
	})
	rec := &rightsAudit{}
	exec := executor.New(engine, nil, composite, nil, rec, 5*time.Second, newQuietMCPLogger(), nil, nil)
	return NewHandler(exec, composite, nil, "", nil, newQuietMCPLogger(), false), rec
}

func kitCaller(user string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: user, Authenticated: true})
}

func askRights(t *testing.T, h *Handler, user string, params map[string]any) rightsAnswer {
	t.Helper()
	res, err := h.HandleToolCall(kitCaller(user), toolTellMeMyRights, params)
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if res.IsError {
		t.Fatalf("tell_me_my_rights failed: %s", resultText(t, res))
	}
	var a rightsAnswer
	if err := json.Unmarshal([]byte(resultText(t, res)), &a); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, resultText(t, res))
	}
	return a
}

func TestTellMeMyRights_Preflight(t *testing.T) {
	h, rec := newKitHandler(t)
	a := askRights(t, h, testKitUserBob, map[string]any{
		argNameTools: []any{testGraylogSearch, testGraylogDelete, testUnifiClients, testVaultFetch, testUnknownToolName},
	})

	want := map[string]rightsTool{
		testGraylogSearch:   {Tool: testGraylogSearch, Verdict: executor.VerdictEscalatable, Kits: []string{testKitNetDiag}},
		testUnifiClients:    {Tool: testUnifiClients, Verdict: executor.VerdictEscalatable, Kits: []string{testKitNetDiag}},
		testGraylogDelete:   {Tool: testGraylogDelete, Verdict: executor.VerdictDenied, Reason: reasonUnavailable},
		testVaultFetch:      {Tool: testVaultFetch, Verdict: executor.VerdictDenied, Reason: reasonUnavailable},
		testUnknownToolName: {Tool: testUnknownToolName, Verdict: executor.VerdictDenied, Reason: reasonUnavailable},
	}
	if len(a.Tools) != len(want) {
		t.Fatalf("tools = %+v, want %d entries", a.Tools, len(want))
	}
	for _, got := range a.Tools {
		w := want[got.Tool]
		if got.Verdict != w.Verdict || !slices.Equal(got.Kits, w.Kits) || got.Reason != w.Reason {
			t.Errorf("%s = %+v, want %+v", got.Tool, got, w)
		}
	}
	if a.Bundle == nil || !slices.Equal(a.Bundle.Kits, []string{testKitNetDiag}) ||
		!slices.Equal(a.Bundle.Covers, []string{testGraylogSearch, testUnifiClients}) {
		t.Errorf("bundle = %+v", a.Bundle)
	}
	if len(a.Kits) != 1 || a.Kits[0].TTLDefault != "4h" || a.Kits[0].TTLMax != "24h" || a.Kits[0].Warning == "" {
		t.Errorf("kits = %+v", a.Kits)
	}
	if a.Caller != testKitUserBob || a.Note == "" {
		t.Errorf("caller/note = %q / %q", a.Caller, a.Note)
	}

	if len(rec.entries) != 1 || rec.entries[0].Tool != toolTellMeMyRights || rec.entries[0].UserID != testKitUserBob {
		t.Errorf("audit entries = %+v, want one for the query", rec.entries)
	}
}

func TestTellMeMyRights_PreflightAllowed(t *testing.T) {
	h, _ := newKitHandler(t)
	a := askRights(t, h, testKitUserOwner, map[string]any{argNameTools: []any{testGraylogDelete}})
	if len(a.Tools) != 1 || a.Tools[0].Verdict != executor.VerdictAllowed || a.Bundle != nil || len(a.Kits) != 0 {
		t.Errorf("answer = %+v, want one allowed tool, no bundle, no kits", a)
	}
}

func TestTellMeMyRights_Overview(t *testing.T) {
	h, _ := newKitHandler(t)
	a := askRights(t, h, testKitUserBob, map[string]any{})
	want := []rightsBackend{
		{Backend: testBackendGraylog, Escalatable: 1, Kits: []string{testKitNetDiag}},
		{Backend: "unifi", Escalatable: 1, Kits: []string{testKitNetDiag}},
	}
	if len(a.Backends) != len(want) {
		t.Fatalf("backends = %+v, want %+v", a.Backends, want)
	}
	for i, b := range a.Backends {
		if b.Backend != want[i].Backend || b.Allowed != want[i].Allowed || b.Escalatable != want[i].Escalatable || !slices.Equal(b.Kits, want[i].Kits) {
			t.Errorf("backend %d = %+v, want %+v", i, b, want[i])
		}
	}

	owner := askRights(t, h, testKitUserOwner, nil)
	if len(owner.Backends) != 3 || owner.Backends[0].Allowed != 2 || len(owner.Kits) != 0 {
		t.Errorf("owner overview = %+v, want 3 backends, graylog with 2 allowed, no kits", owner.Backends)
	}
}

func TestTellMeMyRights_Backend(t *testing.T) {
	h, _ := newKitHandler(t)
	a := askRights(t, h, testKitUserBob, map[string]any{argNameBackend: testBackendGraylog})
	if a.Backend != testBackendGraylog || len(a.Tools) != 1 || a.Tools[0].Tool != testGraylogSearch || a.Tools[0].Verdict != executor.VerdictEscalatable {
		t.Errorf("answer = %+v, want only %s, escalatable", a, testGraylogSearch)
	}
	// A backend without anything for the caller looks like one that does not
	// exist.
	if s := askRights(t, h, testKitUserBob, map[string]any{argNameBackend: testBackendVault}); len(s.Tools) != 0 {
		t.Errorf("backend vault = %+v, want no tools", s.Tools)
	}
}

func TestTellMeMyRights_InvalidArguments(t *testing.T) {
	h, rec := newKitHandler(t)
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"both modes", map[string]any{argNameTools: []any{"a"}, argNameBackend: "b"}, "either tools or backend"},
		{"not a list", map[string]any{argNameTools: 7}, "list of tool names"},
		{"not strings", map[string]any{argNameTools: []any{1}}, "list of tool names"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := h.HandleToolCall(kitCaller(testKitUserBob), toolTellMeMyRights, tc.params)
			if err != nil {
				t.Fatalf("HandleToolCall: %v", err)
			}
			if !res.IsError || !strings.Contains(resultText(t, res), tc.want) {
				t.Errorf("result = %q, want an error mentioning %q", resultText(t, res), tc.want)
			}
		})
	}
	if len(rec.entries) != len(tests) || rec.entries[0].Status != "error" {
		t.Errorf("audit entries = %d, want %d failed queries recorded", len(rec.entries), len(tests))
	}
}

func TestDiscoverTools_MarksKitTools(t *testing.T) {
	h, _ := newKitHandler(t)
	for _, detail := range []string{detailFull, detailSummary, detailNames} {
		res, err := h.HandleToolCall(kitCaller(testKitUserBob), toolDiscoverTools, map[string]any{argNameDetail: detail})
		if err != nil {
			t.Fatalf("discover_tools: %v", err)
		}
		text := resultText(t, res)
		for _, want := range []string{testGraylogSearch, testUnifiClients, "grant_required: kit " + testKitNetDiag, "2 of them are marked grant_required", toolTellMeMyRights} {
			if !strings.Contains(text, want) {
				t.Errorf("detail %s: output lacks %q:\n%s", detail, want, text)
			}
		}
		for _, hidden := range []string{testGraylogDelete, testVaultFetch} {
			if strings.Contains(text, hidden) {
				t.Errorf("detail %s: output shows %s, which the caller may neither call nor get a kit for", detail, hidden)
			}
		}
	}

	res, err := h.HandleToolCall(kitCaller(testKitUserBob), toolDiscoverTools, map[string]any{argNameDetail: detailOverview})
	if err != nil {
		t.Fatalf("discover_tools: %v", err)
	}
	// The test backends leave the descriptor's backend label empty, so the
	// overview has one group.
	if text := resultText(t, res); !strings.Contains(text, "2 tools (2 grant_required)") {
		t.Errorf("overview lacks the grant_required count:\n%s", text)
	}

	// The owner may call everything: nothing is marked.
	res, err = h.HandleToolCall(kitCaller(testKitUserOwner), toolDiscoverTools, map[string]any{})
	if err != nil {
		t.Fatalf("discover_tools: %v", err)
	}
	if text := resultText(t, res); strings.Contains(text, "grant_required") || !strings.Contains(text, testVaultFetch) {
		t.Errorf("owner output marks tools or misses one:\n%s", text)
	}
}

func TestSandboxDiscovery_MarksKitTools(t *testing.T) {
	h, _ := newKitHandler(t)
	run := func(code string) *backend.ToolResult {
		t.Helper()
		res, err := h.HandleToolCall(kitCaller(testKitUserBob), toolExecuteCode, map[string]any{argNameCode: code})
		if err != nil {
			t.Fatalf("execute_code: %v", err)
		}
		return res
	}

	res := run(`return toolmesh.discover("graylog search")`)
	if text := resultText(t, res); !strings.Contains(text, `"grant_required"`) || !strings.Contains(text, testKitNetDiag) || strings.Contains(text, testGraylogDelete) {
		t.Errorf("toolmesh.discover = %s", text)
	}

	res = run(`return toolmesh.describe("` + testGraylogSearch + `")`)
	if text := resultText(t, res); res.IsError || !strings.Contains(text, testKitNetDiag) {
		t.Errorf("toolmesh.describe of a kit tool = %s", text)
	}

	res = run(`return toolmesh.describe("` + testGraylogDelete + `")`)
	if !res.IsError || !strings.Contains(fullText(res), "unknown tool") {
		t.Errorf("toolmesh.describe of a hidden tool = %s, want unknown tool", fullText(res))
	}
}

func TestDenial_PointsToRightsTool(t *testing.T) {
	h, _ := newKitHandler(t)
	res, err := h.HandleToolCall(kitCaller(testKitUserBob), testGraylogSearch, map[string]any{})
	if err != nil {
		t.Fatalf("HandleToolCall: %v", err)
	}
	if text := resultText(t, res); !res.IsError || !strings.Contains(text, testKitNetDiag) || !strings.Contains(text, toolTellMeMyRights) {
		t.Errorf("denial = %q", text)
	}
}

func TestDiscoveryFooter_GrantRequired(t *testing.T) {
	tests := []struct {
		n    int
		want string
		not  string
	}{
		{0, "", "grant_required"},
		{1, "1 of them is marked grant_required: you cannot call it yet; the named kit covers it, though a deny can still block a tool for you.", "are marked"},
		{3, "3 of them are marked grant_required: you cannot call them yet; the named kit covers them, though a deny", "is marked"},
	}
	for _, tc := range tests {
		got := discoveryFooter(5, 10, 5, detailNames, false, "", tc.n)
		if !strings.Contains(got, tc.want) || strings.Contains(got, tc.not) {
			t.Errorf("footer with %d grant_required = %q, want %q and not %q", tc.n, got, tc.want, tc.not)
		}
		if tc.n > 0 && !strings.Contains(got, toolTellMeMyRights) {
			t.Errorf("footer with %d grant_required does not point to %s", tc.n, toolTellMeMyRights)
		}
	}
}

func TestSmallestBundle(t *testing.T) {
	b := smallestBundle(map[string][]string{
		"t1": {testKitWide, "a"},
		"t2": {testKitWide, "b"},
		"t3": {testKitWide},
		"t4": {"c"},
	})
	if !slices.Equal(b.Kits, []string{testKitWide, "c"}) || !slices.Equal(b.Covers, []string{"t1", "t2", "t3", "t4"}) {
		t.Errorf("bundle = %+v, want kits [wide c] covering t1..t4", b)
	}
	tie := smallestBundle(map[string][]string{"t": {"zulu", "bravo"}})
	if !slices.Equal(tie.Kits, []string{"bravo"}) {
		t.Errorf("tie bundle = %v, want the first kit by name", tie.Kits)
	}
}

func TestStringList(t *testing.T) {
	tests := []struct {
		in   any
		want []string
		err  bool
	}{
		{nil, nil, false},
		{[]any{" a ", "b", "a", ""}, []string{"a", "b"}, false},
		{[]string{"x"}, []string{"x"}, false},
		{`["a","b"]`, []string{"a", "b"}, false},
		{"single", []string{"single"}, false},
		{"[broken", nil, true},
		{[]any{"a", 2}, nil, true},
		{3.5, nil, true},
	}
	for _, tc := range tests {
		got, err := stringList(tc.in)
		if (err != nil) != tc.err || (!tc.err && !slices.Equal(got, tc.want)) {
			t.Errorf("stringList(%v) = %v, %v; want %v, error %v", tc.in, got, err, tc.want, tc.err)
		}
	}
}

func TestFormatTTL(t *testing.T) {
	tests := map[time.Duration]string{
		0:                       "",
		4 * time.Hour:           "4h",
		90 * time.Minute:        "90m",
		90*time.Second + 500000: "1m30.0005s",
	}
	for d, want := range tests {
		if got := formatTTL(d); got != want {
			t.Errorf("formatTTL(%s) = %q, want %q", d, got, want)
		}
	}
}

// fullText joins every text block of a result.
func fullText(r *backend.ToolResult) string {
	var sb strings.Builder
	for _, c := range r.Content {
		if m, ok := c.(map[string]any); ok {
			s, _ := m[contentKeyText].(string)
			sb.WriteString(s)
		}
	}
	return sb.String()
}
