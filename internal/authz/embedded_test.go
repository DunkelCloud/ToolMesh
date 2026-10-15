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

package authz

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTestEngine(t *testing.T, path string, upgrade bool) *Embedded {
	t.Helper()
	e, err := OpenEmbedded(context.Background(), EmbeddedOptions{Path: path, Upgrade: upgrade})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	return e
}

func applyPreset(t *testing.T, e *Embedded, preset string) {
	t.Helper()
	grants, err := PresetGrants(preset, testOwner)
	if err != nil {
		t.Fatalf("PresetGrants: %v", err)
	}
	if _, err := e.Apply(context.Background(), grants, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

func mustCheck(t *testing.T, e *Embedded, req Request) bool {
	t.Helper()
	ok, err := e.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check(%+v): %v", req, err)
	}
	return ok
}

func TestEmbedded_Presets(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)

	owner := Request{UserID: testOwner, Plan: PlanPro, Roles: []string{RoleAdmin}}
	admin := Request{UserID: "alice", Roles: []string{RoleAdmin}}
	pro := Request{UserID: testBob, Plan: PlanPro, Roles: []string{"tool-executor"}}
	free := Request{UserID: testCarol, Plan: PlanFree}
	nobody := Request{UserID: "dave"}

	readTool := Request{Tool: testGitHubListRepos, Backend: testGitHub, Access: AccessRead}
	writeTool := Request{Tool: testGitHubCreateIssue, Backend: testGitHub, Access: testWrite}

	call := func(who, what Request) Request {
		who.Tool, who.Backend, who.Access = what.Tool, what.Backend, what.Access
		return who
	}

	tests := []struct {
		preset string
		who    Request
		what   Request
		want   bool
	}{
		{PresetSingleUser, owner, writeTool, true},
		{PresetSingleUser, Request{UserID: testOwner}, writeTool, true}, // the owner, whatever roles
		{PresetSingleUser, admin, writeTool, true},
		{PresetSingleUser, pro, readTool, false},
		{PresetSingleUser, nobody, readTool, false},

		{PresetTeam, owner, writeTool, true},
		{PresetTeam, admin, writeTool, true},
		{PresetTeam, pro, writeTool, true},
		{PresetTeam, free, readTool, true},
		{PresetTeam, free, writeTool, false},
		{PresetTeam, free, Request{Tool: "mcp_unclassified", Backend: "mcp"}, false},
		{PresetTeam, nobody, readTool, false},

		{PresetOpen, nobody, writeTool, true},
		{PresetOpen, free, Request{Tool: "unknown_tool"}, true},
	}
	for _, tc := range tests {
		applyPreset(t, e, tc.preset)
		req := call(tc.who, tc.what)
		if got := mustCheck(t, e, req); got != tc.want {
			t.Errorf("preset %s: user=%s plan=%s roles=%v tool=%s: allowed=%v, want %v",
				tc.preset, req.UserID, req.Plan, req.Roles, req.Tool, got, tc.want)
		}
	}
}

func TestEmbedded_FileGrants(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)

	f, err := ParseFile([]byte(`
grants:
  - plan: pro
    backends: [github]
  - company: acme
    tools: ["deepl_translate"]
  - user: "erin@example.com"
    access: [read]
  - everyone: true
    tools: [echo_echo]
`))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if _, err := e.Apply(context.Background(), f.Grants, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	tests := []struct {
		name string
		req  Request
		want bool
	}{
		{"backend grant covers its tool", Request{UserID: testBob, Plan: PlanPro, Tool: testGitHubCreateIssue, Backend: testGitHub}, true},
		{"backend grant needs the routed backend", Request{UserID: testBob, Plan: PlanPro, Tool: testGitHubCreateIssue}, false},
		{"backend grant does not cover a longer-named backend", Request{UserID: testBob, Plan: PlanPro, Tool: "github_enterprise_x", Backend: "github_enterprise"}, false},
		{"company grant", Request{UserID: "x", CompanyID: testAcme, Tool: testDeepLTranslate, Backend: testDeepL}, true},
		{"company grant is per tool", Request{UserID: "x", CompanyID: testAcme, Tool: "deepl_usage", Backend: testDeepL}, false},
		{"user grant by access class", Request{UserID: "erin@example.com", Tool: "netbox_list", Backend: testNetbox, Access: AccessRead}, true},
		{"user grant by access class, other class", Request{UserID: "erin@example.com", Tool: "netbox_delete", Backend: testNetbox, Access: testDangerous}, false},
		{"everyone grant", Request{UserID: "anyone", Tool: testEchoEcho, Backend: testEcho}, true},
		{"nothing granted", Request{UserID: "anyone", Tool: "echo_add", Backend: testEcho}, false},
		{"no user", Request{Tool: testEchoEcho, Backend: testEcho}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustCheck(t, e, tc.req); got != tc.want {
				t.Errorf("allowed=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestEmbedded_ApplyReconciles(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()

	res, err := e.Apply(ctx, []Grant{{Plan: PlanPro, AllTools: true}, {Role: testRoleOps, Backends: []string{"a", "b"}}}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Written != 3 || res.Deleted != 0 || res.Tuples != 3 {
		t.Errorf("first Apply = %+v, want 3 written", res)
	}

	res, err = e.Apply(ctx, []Grant{{Role: testRoleOps, Backends: []string{"b", "c"}}}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Written != 1 || res.Deleted != 2 || res.Tuples != 2 {
		t.Errorf("second Apply = %+v, want 1 written, 2 deleted", res)
	}

	if mustCheck(t, e, Request{UserID: "u", Plan: PlanPro, Tool: "a_x", Backend: "a"}) {
		t.Error("revoked plan grant still allows")
	}
	if !mustCheck(t, e, Request{UserID: "u", Roles: []string{testRoleOps}, Tool: "c_x", Backend: "c"}) {
		t.Error("new role grant does not allow")
	}

	res, err = e.Apply(ctx, []Grant{{Role: testRoleOps, Backends: []string{"b", "c"}}}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Written != 0 || res.Deleted != 0 {
		t.Errorf("unchanged Apply = %+v, want no changes", res)
	}
}

func TestEmbedded_ManyGrantsChunked(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()

	tools := make([]string, 250)
	for i := range tools {
		tools[i] = "t_" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	res, err := e.Apply(ctx, []Grant{{User: "u", Tools: tools}}, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Written != 250 {
		t.Errorf("Written = %d, want 250", res.Written)
	}
	res, err = e.Apply(ctx, nil, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Deleted != 250 {
		t.Errorf("Deleted = %d, want 250", res.Deleted)
	}
}

func TestEmbedded_ReopenKeepsStoreModelAndGrants(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFileName)
	ctx := context.Background()

	first, err := OpenEmbedded(ctx, EmbeddedOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	if _, err := first.Apply(ctx, []Grant{{User: "u", AllTools: true}}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	storeID, modelID := first.StoreID(), first.ModelID()
	_ = first.Close()

	second := openTestEngine(t, path, true) // upgrade is decided on the first start only
	if second.StoreID() != storeID || second.ModelID() != modelID {
		t.Errorf("reopen: store/model = %s/%s, want %s/%s", second.StoreID(), second.ModelID(), storeID, modelID)
	}
	if second.UpgradePreset() != "" {
		t.Errorf("UpgradePreset = %q after reopen of a fresh install, want empty", second.UpgradePreset())
	}
	if !mustCheck(t, second, Request{UserID: "u", Tool: testToolXY}) {
		t.Error("grant lost across reopen")
	}
}

func TestEmbedded_UpgradeRecordsOpenPreset(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFileName)
	first, err := OpenEmbedded(context.Background(), EmbeddedOptions{Path: path, Upgrade: true})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	if first.UpgradePreset() != PresetOpen {
		t.Errorf("UpgradePreset = %q, want %q", first.UpgradePreset(), PresetOpen)
	}
	_ = first.Close()

	second := openTestEngine(t, path, false)
	if second.UpgradePreset() != PresetOpen {
		t.Errorf("UpgradePreset after reopen = %q, want %q", second.UpgradePreset(), PresetOpen)
	}
}

func TestEmbedded_ModelChangeWritesNewModel(t *testing.T) {
	path := filepath.Join(t.TempDir(), DBFileName)
	ctx := context.Background()

	first, err := OpenEmbedded(ctx, EmbeddedOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	if _, err := first.Apply(ctx, []Grant{{Role: RoleAdmin, AllTools: true}}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	oldModel := first.ModelID()
	// Simulate a store written by a ToolMesh with a different model.
	if err := first.writeState(ctx, map[string]string{stateModelHash: "older"}); err != nil {
		t.Fatalf("writeState: %v", err)
	}
	_ = first.Close()

	second := openTestEngine(t, path, false)
	if second.ModelID() == oldModel {
		t.Error("model was not written again although the recorded hash differs")
	}
	if !mustCheck(t, second, Request{UserID: "a", Roles: []string{RoleAdmin}, Tool: testToolXY}) {
		t.Error("grant not honored under the new model")
	}
}

func TestHasPriorState(t *testing.T) {
	dir := t.TempDir()
	if HasPriorState(dir) {
		t.Error("empty dir reported as prior state")
	}
	if HasPriorState(filepath.Join(dir, "missing")) {
		t.Error("missing dir reported as prior state")
	}
	for _, name := range []string{DBFileName, DBFileName + "-wal", DBFileName + "-shm"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if HasPriorState(dir) {
		t.Error("authz database files reported as prior state")
	}
	if err := os.Mkdir(filepath.Join(dir, "blobs"), 0o750); err != nil {
		t.Fatal(err)
	}
	if !HasPriorState(dir) {
		t.Error("blobs dir not reported as prior state")
	}
}

func TestEscapeID(t *testing.T) {
	tests := map[string]string{
		"github_list":     "github_list",
		"a:b":             "a%3Ab",
		"a#b":             "a%23b",
		"*":               "%2A",
		"50%":             "50%25",
		"two words":       "two%20words",
		"erin@example.de": "erin@example.de",
	}
	for in, want := range tests {
		if got := escapeID(in); got != want {
			t.Errorf("escapeID(%q) = %q, want %q", in, got, want)
		}
	}
	if escapeID("a:b") == escapeID("a%3Ab") {
		t.Error("escapeID collides on an already-escaped name")
	}
}

func TestEmbedded_WildcardUserIsNotEveryone(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	if _, err := e.Apply(context.Background(), []Grant{{User: "*", AllTools: true}}, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if mustCheck(t, e, Request{UserID: "someone", Tool: testToolXY}) {
		t.Error(`a grant to the user named "*" acts as a grant to everyone`)
	}
	if !mustCheck(t, e, Request{UserID: "*", Tool: testToolXY}) {
		t.Error(`a grant to the user named "*" does not cover that user`)
	}
}

// TestEmbedded_CheckBatchMatchesCheck compares CheckBatch with one Check per
// request over every combination of callers, tools and grants in the table,
// including grants on single tools, which CheckBatch must not generalize.
func TestEmbedded_CheckBatchMatchesCheck(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()

	grants := []Grant{
		{Plan: PlanPro, Backends: []string{testGitHub}},
		{Plan: PlanFree, Access: []string{AccessRead}},
		{Role: testRoleOps, Tools: []string{testNetboxDeleteDevice, testGitHubDeleteRepo}},
		{User: "erin", Tools: []string{testDeepLTranslate}},
		{Company: testAcme, Backends: []string{testNetbox}},
	}
	if _, err := e.Apply(ctx, grants, nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	callers := []Request{
		{UserID: testBob, Plan: PlanPro},
		{UserID: testCarol, Plan: PlanFree},
		{UserID: "dan", Roles: []string{testRoleOps, testRoleOps}},
		{UserID: "erin"},
		{UserID: "frank", CompanyID: testAcme, Plan: PlanFree},
		{UserID: ""},
	}
	tools := []Request{
		{Tool: testGitHubListRepos, Backend: testGitHub, Access: AccessRead},
		{Tool: testGitHubDeleteRepo, Backend: testGitHub, Access: testDangerous},
		{Tool: testGitHubCreateIssue, Backend: testGitHub, Access: testWrite},
		{Tool: testNetboxDeleteDevice, Backend: testNetbox, Access: testDangerous},
		{Tool: "netbox_list_devices", Backend: testNetbox, Access: AccessRead},
		{Tool: testDeepLTranslate, Backend: testDeepL, Access: testWrite},
		{Tool: "deepl_usage", Backend: testDeepL, Access: testWrite},
		{Tool: "mcp_thing", Backend: "mcp"},
		{Tool: ""},
	}

	reqs := make([]Request, 0, len(callers)*len(tools))
	for _, c := range callers {
		for _, tl := range tools {
			r := c
			r.Tool, r.Backend, r.Access = tl.Tool, tl.Backend, tl.Access
			reqs = append(reqs, r)
		}
	}
	got, err := e.CheckBatch(ctx, reqs)
	if err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	for i, r := range reqs {
		if want := mustCheck(t, e, r); got[i] != want {
			t.Errorf("user=%s plan=%s roles=%v company=%s tool=%s: CheckBatch=%v, Check=%v",
				r.UserID, r.Plan, r.Roles, r.CompanyID, r.Tool, got[i], want)
		}
	}

	// Revoking a tool-level grant must reach CheckBatch as well.
	if _, err := e.Apply(ctx, grants[:2], nil); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err = e.CheckBatch(ctx, []Request{{UserID: "dan", Roles: []string{testRoleOps}, Tool: testNetboxDeleteDevice, Backend: testNetbox, Access: testDangerous}})
	if err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	if got[0] {
		t.Error("revoked tool grant still allowed by CheckBatch")
	}
}

func TestEquivalenceKeyIgnoresRoleOrderAndDuplicates(t *testing.T) {
	a := equivalenceKey(Request{UserID: "u", Roles: []string{"b", "a", "a"}})
	b := equivalenceKey(Request{UserID: "u", Roles: []string{"a", "b"}})
	if a != b {
		t.Errorf("keys differ: %q vs %q", a, b)
	}
	if equivalenceKey(Request{UserID: "ab", Plan: "c"}) == equivalenceKey(Request{UserID: "a", Plan: "bc"}) {
		t.Error("key is ambiguous across field boundaries")
	}
}

// Deleting authz.db must not turn an existing data directory into an
// "upgrade" that opens every tool: the marker keeps the first decision.
func TestEmbedded_MarkerSurvivesDatabaseLoss(t *testing.T) {
	for _, tc := range []struct {
		name          string
		firstUpgrade  bool
		wantAfterLoss string
	}{
		{"fresh install stays closed", false, ""},
		{"upgraded install stays open", true, PresetOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, DBFileName)
			first, err := OpenEmbedded(context.Background(), EmbeddedOptions{Path: path, Upgrade: tc.firstUpgrade})
			if err != nil {
				t.Fatalf("OpenEmbedded: %v", err)
			}
			_ = first.Close()
			for _, suffix := range []string{"", "-wal", "-shm"} {
				if err := os.Remove(path + suffix); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}

			// The data directory now has state (the marker), as any
			// installation would: main passes Upgrade=true for it.
			second := openTestEngine(t, path, true)
			if second.UpgradePreset() != tc.wantAfterLoss {
				t.Errorf("UpgradePreset after losing the database = %q, want %q", second.UpgradePreset(), tc.wantAfterLoss)
			}
		})
	}
}

func TestEmbedded_InvalidMarkerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, MarkerFileName), []byte(`{"upgrade_preset":"everyone"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenEmbedded(context.Background(), EmbeddedOptions{Path: filepath.Join(dir, DBFileName), Upgrade: true}); err == nil {
		t.Error("OpenEmbedded accepted a marker with an unknown preset")
	}
}

// The connection settings must hold on every pooled connection: WAL so that
// checks read while a reload writes, the busy timeout, and temporary storage
// in memory because the container image has no writable temp directory.
func TestEmbedded_ConnectionPragmas(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	for _, tc := range []struct{ pragma, want string }{
		{"journal_mode", "wal"},
		{"busy_timeout", "5000"},
		{"temp_store", "2"}, // MEMORY
	} {
		var got string
		if err := e.db.QueryRowContext(ctx, "PRAGMA "+tc.pragma).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", tc.pragma, err)
		}
		if got != tc.want {
			t.Errorf("PRAGMA %s = %q, want %q", tc.pragma, got, tc.want)
		}
	}
}

// Denies win over every grant, at every level a deny can name.
func TestEmbedded_DeniesWinOverGrants(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	grants, err := PresetGrants(PresetTeam, testOwner)
	if err != nil {
		t.Fatal(err)
	}
	denies := []Grant{
		{User: "ad", Tools: []string{testEchoTime}},
		{Role: testRoleContractor, Backends: []string{"stripe"}},
		{Role: testRoleIntern, Access: []string{testDangerous}},
		{Company: testAcme, AllTools: true},
		{Everyone: true, Tools: []string{testNetboxDeleteDevice}},
	}
	if _, err := e.Apply(context.Background(), grants, denies); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	ad := Request{UserID: "ad", Plan: PlanPro, Roles: []string{RoleAdmin}}
	tests := []struct {
		name string
		who  Request
		tool Request
		want bool
	}{
		{"deny on a single tool", ad, Request{Tool: testEchoTime, Backend: testEcho}, false},
		{"other tool of the same backend", ad, Request{Tool: testEchoEcho, Backend: testEcho}, true},
		{"deny is per user", Request{UserID: testBob, Plan: PlanPro}, Request{Tool: testEchoTime, Backend: testEcho}, true},
		{"deny on a backend", Request{UserID: "c", Plan: PlanPro, Roles: []string{testRoleContractor}}, Request{Tool: "stripe_list_charges", Backend: "stripe", Access: AccessRead}, false},
		{"backend deny leaves other backends", Request{UserID: "c", Plan: PlanPro, Roles: []string{testRoleContractor}}, Request{Tool: "github_x", Backend: testGitHub, Access: AccessRead}, true},
		{"deny on an access class", Request{UserID: "i", Plan: PlanPro, Roles: []string{testRoleIntern}}, Request{Tool: "netbox_delete_x", Backend: testNetbox, Access: testDangerous}, false},
		{"access deny leaves other classes", Request{UserID: "i", Plan: PlanPro, Roles: []string{testRoleIntern}}, Request{Tool: "netbox_create_x", Backend: testNetbox, Access: testWrite}, true},
		{"deny of all tools for a company", Request{UserID: "m", CompanyID: testAcme, Plan: PlanPro, Roles: []string{RoleAdmin}}, Request{Tool: testEchoEcho, Backend: testEcho}, false},
		{"deny for everyone beats admin", ad, Request{Tool: testNetboxDeleteDevice, Backend: testNetbox, Access: testDangerous}, false},
		{"deny for everyone beats owner", Request{UserID: testOwner}, Request{Tool: testNetboxDeleteDevice, Backend: testNetbox, Access: testDangerous}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.who
			r.Tool, r.Backend, r.Access = tc.tool.Tool, tc.tool.Backend, tc.tool.Access
			if got := mustCheck(t, e, r); got != tc.want {
				t.Errorf("allowed=%v, want %v", got, tc.want)
			}
			batch, err := e.CheckBatch(context.Background(), []Request{r})
			if err != nil {
				t.Fatalf("CheckBatch: %v", err)
			}
			if batch[0] != tc.want {
				t.Errorf("CheckBatch allowed=%v, want %v", batch[0], tc.want)
			}
		})
	}
}

// A tool listing with denies on single tools and on backends must give the
// same answers in a batch as one check per tool.
func TestEmbedded_CheckBatchMatchesCheckWithDenies(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	if _, err := e.Apply(ctx,
		[]Grant{{Plan: PlanPro, AllTools: true}, {Plan: PlanFree, Access: []string{AccessRead}}},
		[]Grant{{Plan: PlanPro, Tools: []string{testGitHubDeleteRepo}}, {Plan: PlanFree, Backends: []string{testNetbox}}},
	); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	reqs := make([]Request, 0, 10)
	for _, who := range []Request{{UserID: "p", Plan: PlanPro}, {UserID: "f", Plan: PlanFree}} {
		for _, tl := range []Request{
			{Tool: testGitHubDeleteRepo, Backend: testGitHub, Access: testDangerous},
			{Tool: "github_delete_branch", Backend: testGitHub, Access: testDangerous},
			{Tool: testGitHubListRepos, Backend: testGitHub, Access: AccessRead},
			{Tool: "netbox_list_devices", Backend: testNetbox, Access: AccessRead},
			{Tool: "netbox_list_sites", Backend: testNetbox, Access: AccessRead},
		} {
			r := who
			r.Tool, r.Backend, r.Access = tl.Tool, tl.Backend, tl.Access
			reqs = append(reqs, r)
		}
	}
	got, err := e.CheckBatch(ctx, reqs)
	if err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	for i, r := range reqs {
		if want := mustCheck(t, e, r); got[i] != want {
			t.Errorf("plan=%s tool=%s: CheckBatch=%v, Check=%v", r.Plan, r.Tool, got[i], want)
		}
	}
	if got[0] || !got[1] || got[8] {
		t.Errorf("unexpected decisions %v", got)
	}
}

func TestEmbedded_LiftingADenyRestoresAccess(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	grants := []Grant{{User: "ad", AllTools: true}}
	req := Request{UserID: "ad", Tool: testEchoTime, Backend: testEcho}

	res, err := e.Apply(ctx, grants, []Grant{{User: "ad", Tools: []string{testEchoTime}}})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Written != 2 || res.Tuples != 2 {
		t.Errorf("Apply with deny = %+v, want 2 tuples written", res)
	}
	if mustCheck(t, e, req) {
		t.Fatal("denied tool allowed")
	}
	res, err = e.Apply(ctx, grants, nil)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Deleted != 1 || res.Written != 0 {
		t.Errorf("Apply without deny = %+v, want 1 deleted", res)
	}
	if !mustCheck(t, e, req) {
		t.Error("tool still denied after the deny was lifted")
	}
	if _, err := e.Apply(ctx, grants, []Grant{{User: "ad"}}); err == nil || !strings.Contains(err.Error(), "deny 1") {
		t.Errorf("invalid deny: err = %v", err)
	}
}
