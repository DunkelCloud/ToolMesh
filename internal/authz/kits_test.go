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
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Names shared by the kit tests.
const (
	testKitNetDiag     = "net-diag-read"
	testKitUnifiWrite  = "unifi-write"
	testGraylog        = "graylog"
	testUnifi          = "unifi"
	testGraylogSearch  = "graylog_search"
	testGraylogDelete  = "graylog_delete_stream"
	testUnifiClients   = "unifi_list_clients"
	testUnifiBlock     = "unifi_block_client"
	testNetboxGet      = "netbox_get_device"
	testKitDescription = "Network diagnosis (read-only)"
	testKitAllAdmin    = "all-admin"
	testScopeGraylogRd = "graylog:read"
)

const testKitsFile = `
grants:
  - user: owner
    all_tools: true
kits:
  net-diag-read:
    description: "Network diagnosis (read-only)"
    warning: "Production systems."
    grants: [graylog:read, "unifi:read"]
    tools: [netbox_get_device]
    ttl_default: 4h
    ttl_max: 24h
  admin-10min:
    description: "Everything"
    grants: ["*"]
    ttl_default: 10m
`

func TestParseFile_Kits(t *testing.T) {
	f, err := ParseFile([]byte(testKitsFile))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	p, err := ResolvePolicy(PolicyInput{File: f})
	if err != nil {
		t.Fatalf("ResolvePolicy: %v", err)
	}
	if len(p.Kits) != 2 || p.Kits[0].Name != "admin-10min" || p.Kits[1].Name != testKitNetDiag {
		t.Fatalf("Kits = %+v, want admin-10min and %s sorted by name", p.Kits, testKitNetDiag)
	}
	k := p.Kits[1]
	if k.Description != testKitDescription || k.Warning != "Production systems." {
		t.Errorf("kit texts = %q / %q", k.Description, k.Warning)
	}
	if k.TTLDefault != 4*time.Hour || k.TTLMax != 24*time.Hour {
		t.Errorf("kit TTLs = %s / %s, want 4h / 24h", k.TTLDefault, k.TTLMax)
	}
	if len(k.Grants) != 2 || k.Grants[0] != testScopeGraylogRd || len(k.Tools) != 1 {
		t.Errorf("kit targets = %v / %v", k.Grants, k.Tools)
	}

	// Presets define no kits.
	p, err = ResolvePolicy(PolicyInput{DefaultPreset: PresetSingleUser, Owner: testOwner})
	if err != nil {
		t.Fatalf("ResolvePolicy: %v", err)
	}
	if len(p.Kits) != 0 {
		t.Errorf("preset policy has kits: %+v", p.Kits)
	}
}

func TestParseFile_InvalidKits(t *testing.T) {
	tests := []struct {
		name string
		kits string
		want string
	}{
		{"no description", "k:\n    grants: [a]", "description is required"},
		{"no targets", "k:\n    description: d", "at least one of grants or tools"},
		{"bad name", "\"bad name\":\n    description: d\n    grants: [a]", "kit name"},
		{"empty backend", "k:\n    description: d\n    grants: [\":read\"]", "names no backend"},
		{"empty access", "k:\n    description: d\n    grants: [\"a:\"]", "no access classification"},
		{"two colons", "k:\n    description: d\n    grants: [\"a:b:c\"]", "more than one colon"},
		{"empty tool", "k:\n    description: d\n    tools: [\"\"]", "empty names"},
		{"default above max", "k:\n    description: d\n    grants: [a]\n    ttl_default: 2h\n    ttl_max: 1h", "exceeds ttl_max"},
		{"long default without max", "k:\n    description: d\n    grants: [a]\n    ttl_default: 48h", "set ttl_max"},
		{"number as ttl", "k:\n    description: d\n    grants: [a]\n    ttl_max: 3600", "time.Duration"},
		{"unknown field", "k:\n    description: d\n    grants: [a]\n    approvals: 2", "approvals"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile([]byte("grants: []\nkits:\n  " + tc.kits + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseFile error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestKit_Covers(t *testing.T) {
	k := Kit{Name: "k", Description: "d", Grants: []string{testScopeGraylogRd, "netbox", "*:admin"}, Tools: []string{testUnifiBlock}}
	tests := []struct {
		tool, backend, access string
		want                  bool
	}{
		{testGraylogSearch, testGraylog, AccessRead, true},
		{testGraylogDelete, testGraylog, testWrite, false},
		{testGraylogSearch, testGraylog, "", false}, // unclassified is not "read"
		{testGraylogSearch, "", AccessRead, false},  // unrouted is not graylog
		{testNetboxGet, testNetbox, testDangerous, true},
		{"github_admin_x", testGitHub, "admin", true},
		{testUnifiBlock, testUnifi, testWrite, true},
		{testUnifiClients, testUnifi, AccessRead, false},
	}
	for _, tc := range tests {
		if got := k.Covers(tc.tool, tc.backend, tc.access); got != tc.want {
			t.Errorf("Covers(%s, %s, %s) = %v, want %v", tc.tool, tc.backend, tc.access, got, tc.want)
		}
	}
	all := Kit{Grants: []string{"*"}}
	if !all.Covers("anything", "", "") {
		t.Error(`kit "*" does not cover an unrouted, unclassified tool`)
	}
}

func TestBackendAccessID_Injective(t *testing.T) {
	if backendAccessID("a:b", "c") == backendAccessID("a", "b:c") {
		t.Error("backendAccessID collides when a colon moves between the names")
	}
	if strings.ContainsAny(backendAccessID("a:b", "c#d"), ":#*") {
		t.Errorf("backendAccessID(%q, %q) = %q holds a character OpenFGA ids must not", "a:b", "c#d", backendAccessID("a:b", "c#d"))
	}
}

func TestEquivalenceKey_KitsAndRolesApart(t *testing.T) {
	base := Request{UserID: "u", Tool: "t"}
	role, kit := base, base
	role.Roles = []string{"x"}
	kit.Kits = []string{"x"}
	if equivalenceKey(role) == equivalenceKey(kit) {
		t.Error("a role and a kit of the same name share an equivalence key")
	}
	a, b := base, base
	a.Kits = []string{"k1", "k2", "k1"}
	b.Kits = []string{"k2", "k1"}
	if equivalenceKey(a) != equivalenceKey(b) {
		t.Error("the same kits in another order or repeated give another equivalence key")
	}
}

func TestEmbedded_Kits(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	kits := []Kit{
		{Name: testKitNetDiag, Description: testKitDescription, Grants: []string{testScopeGraylogRd, "unifi:read"}, Tools: []string{testNetboxGet}},
		{Name: testKitUnifiWrite, Description: "UniFi changes", Grants: []string{"unifi:write"}},
		{Name: testKitAllAdmin, Description: "Admin tools", Grants: []string{"*:admin"}},
	}
	policy := Policy{
		Grants: []Grant{{User: testOwner, AllTools: true}},
		Denies: []Grant{{User: testCarol, Tools: []string{testGraylogSearch}}},
		Kits:   kits,
	}
	if _, err := e.ApplyPolicy(ctx, policy); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	if got := e.Kits(); len(got) != 3 || got[0].Name != testKitAllAdmin {
		t.Errorf("Kits() = %+v, want 3 kits sorted by name", got)
	}

	tool := func(name, backend, access string) Request {
		return Request{Tool: name, Backend: backend, Access: access}
	}
	graylogRead := tool(testGraylogSearch, testGraylog, AccessRead)
	graylogWrite := tool(testGraylogDelete, testGraylog, testWrite)
	unifiRead := tool(testUnifiClients, testUnifi, AccessRead)
	unifiWrite := tool(testUnifiBlock, testUnifi, testWrite)
	netboxGet := tool(testNetboxGet, testNetbox, testDangerous)
	githubAdmin := tool("github_admin_x", testGitHub, "admin")

	tests := []struct {
		name string
		user string
		kits []string
		tool Request
		want bool
	}{
		{"without the kit", testBob, nil, graylogRead, false},
		{"kit covers backend and class", testBob, []string{testKitNetDiag}, graylogRead, true},
		{"kit covers its other backend", testBob, []string{testKitNetDiag}, unifiRead, true},
		{"kit does not cover another class", testBob, []string{testKitNetDiag}, graylogWrite, false},
		{"kit covers its single tool", testBob, []string{testKitNetDiag}, netboxGet, true},
		{"class across backends", testBob, []string{testKitAllAdmin}, githubAdmin, true},
		{"unknown kit", testBob, []string{"nope"}, graylogRead, false},
		// Two kits must not combine into more than each covers: one names
		// unifi:write, the other graylog:read, neither graylog:write.
		{"two kits do not mix", testBob, []string{testKitNetDiag, testKitUnifiWrite}, graylogWrite, false},
		{"two kits, each its own", testBob, []string{testKitNetDiag, testKitUnifiWrite}, unifiWrite, true},
		{"a deny wins over a kit", testCarol, []string{testKitNetDiag}, graylogRead, false},
		{"the deny leaves the rest of the kit", testCarol, []string{testKitNetDiag}, unifiRead, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.tool
			req.UserID, req.Kits = tc.user, tc.kits
			if got := mustCheck(t, e, req); got != tc.want {
				t.Errorf("allowed=%v, want %v", got, tc.want)
			}
			batch, err := e.CheckBatch(ctx, []Request{req})
			if err != nil || batch[0] != tc.want {
				t.Errorf("CheckBatch = %v, %v, want %v", batch, err, tc.want)
			}
		})
	}

	// A batch mixing callers with and without the kit must not share a
	// decision between them.
	with, without := graylogRead, graylogRead
	with.UserID, with.Kits = testBob, []string{testKitNetDiag}
	without.UserID = testBob
	got, err := e.CheckBatch(ctx, []Request{with, without})
	if err != nil || !got[0] || got[1] {
		t.Errorf("CheckBatch(with kit, without) = %v, %v, want [true false]", got, err)
	}

	// Removing the kits revokes what they covered and clears the catalog.
	if _, err := e.Apply(ctx, policy.Grants, policy.Denies); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(e.Kits()) != 0 {
		t.Errorf("Kits() = %+v after Apply without kits", e.Kits())
	}
	req := graylogRead
	req.UserID, req.Kits = testBob, []string{testKitNetDiag}
	if mustCheck(t, e, req) {
		t.Error("removed kit still allows")
	}
}

func TestEmbedded_ApplyPolicyRejectsInvalidKits(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	twice := []Kit{
		{Name: "k", Description: "d", Grants: []string{"a"}},
		{Name: "k", Description: "d", Grants: []string{"b"}},
	}
	if _, err := e.ApplyPolicy(context.Background(), Policy{Kits: twice}); err == nil || !strings.Contains(err.Error(), "defined twice") {
		t.Errorf("ApplyPolicy error = %v, want a duplicate kit error", err)
	}
}
