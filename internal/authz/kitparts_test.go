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
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// testSigningAddress is a P2WPKH address (BIP 173 test vector).
const testSigningAddress = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

// Scopes of the kit-part tests.
const (
	testScopeUnifiRd  = "unifi:read"
	testScopeAnyAdmin = "*:admin"
)

func TestKit_Part(t *testing.T) {
	k := Kit{Name: testKitNetDiag, Grants: []string{testScopeGraylogRd, testScopeUnifiRd}, Tools: []string{testNetboxGet}}
	p, err := k.Part([]string{testScopeUnifiRd, testScopeGraylogRd, testScopeUnifiRd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Grants, []string{testScopeGraylogRd, testScopeUnifiRd}) || p.Kit != testKitNetDiag || k.IsWhole(p) {
		t.Errorf("Part = %+v, whole %v", p, k.IsWhole(p))
	}
	whole, _ := k.Part(k.Grants, k.Tools)
	if !k.IsWhole(whole) {
		t.Error("a part with every entry is not whole")
	}
	for _, tc := range []struct {
		grants, tools []string
		want          string
	}{
		{nil, nil, "at least one"},
		{[]string{"graylog:write"}, nil, `no grant "graylog:write"`},
		{nil, []string{"netbox_delete"}, `no tool "netbox_delete"`},
	} {
		if _, err := k.Part(tc.grants, tc.tools); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Part(%v, %v) = %v, want %q", tc.grants, tc.tools, err, tc.want)
		}
	}
}

func TestEmbedded_KitParts(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	kit := Kit{Name: testKitNetDiag, Description: testKitDescription, Grants: []string{testScopeGraylogRd, testScopeUnifiRd, testScopeAnyAdmin, testNetbox}, Tools: []string{testUnifiBlock}}
	policy := Policy{
		Grants: []Grant{{User: testOwner, AllTools: true}},
		Denies: []Grant{{User: testCarol, Tools: []string{testGraylogSearch}}},
		Kits:   []Kit{kit},
	}
	if _, err := e.ApplyPolicy(ctx, policy); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	tool := func(name, backend, access string) Request {
		return Request{Tool: name, Backend: backend, Access: access}
	}
	graylogRead := tool(testGraylogSearch, testGraylog, AccessRead)
	unifiRead := tool(testUnifiClients, testUnifi, AccessRead)
	unifiBlock := tool(testUnifiBlock, testUnifi, testWrite)
	githubAdmin := tool("github_admin_x", testGitHub, "admin")
	netboxGet := tool(testNetboxGet, testNetbox, testDangerous)

	part := func(grants, tools []string) []KitPart {
		return []KitPart{{Kit: testKitNetDiag, Grants: grants, Tools: tools}}
	}
	tests := []struct {
		name  string
		user  string
		parts []KitPart
		tool  Request
		want  bool
	}{
		{"granted scope", testBob, part([]string{testScopeGraylogRd}, nil), graylogRead, true},
		{"left-out scope", testBob, part([]string{testScopeGraylogRd}, nil), unifiRead, false},
		{"left-out tool", testBob, part([]string{testScopeGraylogRd}, nil), unifiBlock, false},
		{"granted tool", testBob, part(nil, []string{testUnifiBlock}), unifiBlock, true},
		{"class across backends", testBob, part([]string{testScopeAnyAdmin}, nil), githubAdmin, true},
		{"whole backend", testBob, part([]string{testNetbox}, nil), netboxGet, true},
		{"entry the kit does not list", testBob, part([]string{"unifi:write"}, nil), unifiBlock, false},
		{"unknown kit", testBob, []KitPart{{Kit: "no-such-kit", Grants: []string{testScopeGraylogRd}}}, graylogRead, false},
		{"a deny wins over a part", testCarol, part([]string{testScopeGraylogRd}, nil), graylogRead, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.tool
			req.UserID, req.KitParts = tc.user, tc.parts
			if got := mustCheck(t, e, req); got != tc.want {
				t.Errorf("allowed=%v, want %v", got, tc.want)
			}
		})
	}

	// A batch must not share a decision between a part and the whole kit.
	withPart, withKit := unifiRead, unifiRead
	withPart.UserID, withPart.KitParts = testBob, part([]string{testScopeGraylogRd}, nil)
	withKit.UserID, withKit.Kits = testBob, []string{testKitNetDiag}
	got, err := e.CheckBatch(ctx, []Request{withPart, withKit})
	if err != nil || got[0] || !got[1] {
		t.Errorf("CheckBatch(part, whole kit) = %v, %v, want [false true]", got, err)
	}

	// Entries the kit drops later allow nothing any more.
	kit.Grants = []string{testScopeUnifiRd}
	if _, err := e.ApplyPolicy(ctx, Policy{Grants: policy.Grants, Kits: []Kit{kit}}); err != nil {
		t.Fatal(err)
	}
	req := graylogRead
	req.UserID, req.KitParts = testBob, part([]string{testScopeGraylogRd}, nil)
	if mustCheck(t, e, req) {
		t.Error("an entry removed from the kit still allows")
	}

	// More contextual tuples than OpenFGA takes is an error, not a decision.
	many := make([]string, 0, 120)
	for i := range 120 {
		many = append(many, fmt.Sprintf("tool_%d", i))
	}
	big := Kit{Name: "big", Description: "d", Tools: many}
	if _, err := e.ApplyPolicy(ctx, Policy{Grants: policy.Grants, Kits: []Kit{big}}); err != nil {
		t.Fatal(err)
	}
	req = tool("tool_1", "", "")
	req.UserID, req.KitParts = testBob, []KitPart{{Kit: "big", Tools: many}}
	if ok, err := e.Check(ctx, req); err == nil || ok {
		t.Errorf("Check with 120 entries = %v, %v, want an error", ok, err)
	}
}

func TestEquivalenceKey_KitParts(t *testing.T) {
	base := Request{UserID: "u", Tool: "t"}
	a, b, c := base, base, base
	a.KitParts = []KitPart{{Kit: "k", Grants: []string{"x"}}}
	b.KitParts = []KitPart{{Kit: "k", Tools: []string{"x"}}}
	c.Kits = []string{"k"}
	if equivalenceKey(a) == equivalenceKey(b) || equivalenceKey(a) == equivalenceKey(c) || equivalenceKey(a) == equivalenceKey(base) {
		t.Error("parts of a kit share an equivalence key with other holdings")
	}
}

func TestApprovers_Addresses(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	f, err := ParseFile([]byte("grants: []\napprovers:\n  - name: alice\n    address: " + strings.ToUpper(testSigningAddress) +
		"\n  - name: bob\n    key_sha256: " + sum + "\n    address: tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx\n"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := ResolvePolicy(PolicyInput{File: f})
	if err != nil {
		t.Fatal(err)
	}
	if p.Approvers[0].Address != testSigningAddress || p.Approvers[0].KeySHA256 != "" {
		t.Errorf("approver = %+v, want the address in canonical form and no key", p.Approvers[0])
	}
	if _, ok := p.Approvers[0].SigningAddress(); !ok {
		t.Error("SigningAddress of an approver with an address")
	}
	if err := CheckApproverKeys(p.Approvers, map[string]string{"": "nothing"}); err != nil {
		t.Errorf("CheckApproverKeys on an approver without key = %v", err)
	}

	for _, tc := range []struct{ yaml, want string }{
		{"  - name: a\n", "give a key_sha256"},
		{"  - name: a\n    address: bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler\n", "taproot"},
		{"  - name: a\n    address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\n", "bech32"},
		{"  - name: a\n    address: " + testSigningAddress + "\n  - name: b\n    address: " + strings.ToUpper(testSigningAddress) + "\n", "same address"},
	} {
		if _, err := ParseFile([]byte("grants: []\napprovers:\n" + tc.yaml)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("ParseFile(%q) = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}
