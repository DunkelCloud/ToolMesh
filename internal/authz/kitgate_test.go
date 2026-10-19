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
	"slices"
	"strings"
	"testing"
)

// Names of the tests of kit coverage and approver scopes.
const (
	testScopeCheckmkRd = "checkmk:read"
	testGrantsNone     = "grants: []\n"
	testKitsYAML       = "kits:\n  net-diag-read:\n    description: Network diagnosis\n    grants: [graylog:read]\n"
	testApproverAlice  = "  - name: alice\n    key_sha256: "
)

func TestKit_PartCovers(t *testing.T) {
	k := Kit{Name: testKitNetDiag, Grants: []string{testScopeGraylogRd, testScopeUnifiRd}, Tools: []string{testNetboxGet}}
	// The part names a scope and a tool the kit no longer lists; they count
	// for nothing.
	p := KitPart{Kit: testKitNetDiag, Grants: []string{testScopeGraylogRd, testScopeCheckmkRd}, Tools: []string{testNetboxGet, testNetboxDeleteDevice}}
	for _, tc := range []struct {
		tool, backend, access string
		want                  bool
	}{
		{testGraylogSearch, testGraylog, AccessRead, true},
		{testGraylogSearch, testGraylog, testWrite, false},
		{testUnifiClients, testUnifi, AccessRead, false},
		{"checkmk_list_hosts", "checkmk", AccessRead, false},
		{testNetboxGet, testNetbox, testDangerous, true},
		{testNetboxDeleteDevice, testNetbox, testWrite, false},
	} {
		if got := k.PartCovers(p, tc.tool, tc.backend, tc.access); got != tc.want {
			t.Errorf("PartCovers(%s, %s, %s) = %v, want %v", tc.tool, tc.backend, tc.access, got, tc.want)
		}
	}
	if k.PartCovers(KitPart{Kit: testKitNetDiag}, testGraylogSearch, testGraylog, AccessRead) {
		t.Error("an empty part covers a tool")
	}
}

func TestParseFile_ApproverKits(t *testing.T) {
	f, err := ParseFile([]byte(testGrantsNone + testKitsYAML + "approvers:\n" + testApproverAlice + testKeySumA + "\n    kits: [net-diag-read]\n  - name: bob\n    key_sha256: " + testKeySumB + "\n"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	alice, bob := f.Approvers[0], f.Approvers[1]
	if !slices.Equal(alice.Kits, []string{testKitNetDiag}) || !alice.MayApprove(testKitNetDiag) || alice.MayApprove("other") {
		t.Errorf("alice = %+v, want her limited to %s", alice, testKitNetDiag)
	}
	if len(bob.Kits) != 0 || !bob.MayApprove(testKitNetDiag) || !bob.MayApprove("other") {
		t.Errorf("bob = %+v, want him unlimited", bob)
	}
	p, err := ResolvePolicy(PolicyInput{File: f})
	if err != nil || !slices.Equal(p.Approvers[0].Kits, []string{testKitNetDiag}) {
		t.Errorf("ResolvePolicy = %+v, %v; want the kits kept", p.Approvers, err)
	}
	for _, tc := range []struct{ name, approvers, want string }{
		{"kit not defined", testApproverAlice + testKeySumA + "\n    kits: [other]", `no kit "other"`},
		{"empty name", testApproverAlice + testKeySumA + "\n    kits: [\"\"]", "empty names"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile([]byte(testGrantsNone + testKitsYAML + "approvers:\n" + tc.approvers + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseFile error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestEmbedded_ApplyPolicy_ApproverKits(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	kit := Kit{Name: testKitNetDiag, Description: testKitDescription, Grants: []string{testScopeGraylogRd}}
	limited := Approver{Name: testBob, KeySHA256: testKeySumA, Kits: []string{testKitNetDiag}}
	if _, err := e.ApplyPolicy(ctx, Policy{Approvers: []Approver{limited}}); err == nil || !strings.Contains(err.Error(), "no kit") {
		t.Errorf("ApplyPolicy with an approver limited to an undefined kit = %v, want it refused", err)
	}
	if got := e.Approvers(); len(got) != 0 {
		t.Errorf("Approvers after a rejected policy = %+v, want none", got)
	}
	if _, err := e.ApplyPolicy(ctx, Policy{Kits: []Kit{kit}, Approvers: []Approver{limited}}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	if got := e.Approvers(); len(got) != 1 || !slices.Equal(got[0].Kits, []string{testKitNetDiag}) {
		t.Errorf("Approvers = %+v, want bob limited to %s", got, testKitNetDiag)
	}
}
