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
)

// Key hashes of the approver tests: SHA-256 values, not keys. The secret
// scan takes them for API keys, hence gitleaks:allow.
const (
	wantHexKey  = "64 hex characters"
	testKeySumA = "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08" // gitleaks:allow
	testKeySumB = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752" // gitleaks:allow
)

func TestParseFile_Approvers(t *testing.T) {
	f, err := ParseFile([]byte("grants: []\napprovers:\n  - name: alice@example.com\n    key_sha256: " + testKeySumA + "\n  - name: ops-lead\n    key_sha256: " + testKeySumB + "\n"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	p, err := ResolvePolicy(PolicyInput{File: f})
	if err != nil {
		t.Fatalf("ResolvePolicy: %v", err)
	}
	if len(p.Approvers) != 2 || p.Approvers[0].Name != "alice@example.com" || p.Approvers[0].KeySHA256 != strings.ToLower(testKeySumA) {
		t.Errorf("Approvers = %+v, want both, with the key hash in lower case", p.Approvers)
	}
}

func TestParseFile_InvalidApprovers(t *testing.T) {
	tests := []struct {
		name, approvers, want string
	}{
		{"bad name", "  - name: \"-x\"\n    key_sha256: " + testKeySumA, "approver name"},
		{"no hash", "  - name: alice", wantHexKey},
		{"short hash", "  - name: alice\n    key_sha256: abcd", wantHexKey},
		{"not hex", "  - name: alice\n    key_sha256: " + strings.Repeat("z", 64), wantHexKey},
		{"twice", "  - name: alice\n    key_sha256: " + testKeySumA + "\n  - name: alice\n    key_sha256: " + testKeySumB, "defined twice"},
		{"same key", "  - name: alice\n    key_sha256: " + testKeySumA + "\n  - name: bob\n    key_sha256: " + strings.ToLower(testKeySumA), "same key"},
		{"extra field", "  - name: alice\n    key: secret", "field key not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseFile([]byte("grants: []\napprovers:\n" + tc.approvers + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseFile error = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestEmbedded_Approvers(t *testing.T) {
	e := openTestEngine(t, filepath.Join(t.TempDir(), DBFileName), false)
	ctx := context.Background()
	if got := e.Approvers(); len(got) != 0 {
		t.Fatalf("Approvers before ApplyPolicy = %+v", got)
	}
	if _, err := e.ApplyPolicy(ctx, Policy{Approvers: []Approver{{Name: testBob, KeySHA256: testKeySumA}}}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	if got := e.Approvers(); len(got) != 1 || got[0].KeySHA256 != strings.ToLower(testKeySumA) {
		t.Errorf("Approvers = %+v", got)
	}
	// An invalid set is rejected and the approvers stay as they were.
	if _, err := e.ApplyPolicy(ctx, Policy{Approvers: []Approver{{Name: testCarol, KeySHA256: "nope"}}}); err == nil {
		t.Fatal("ApplyPolicy accepted an invalid approver")
	}
	if got := e.Approvers(); len(got) != 1 || got[0].Name != testBob {
		t.Errorf("Approvers after a rejected policy = %+v, want bob still", got)
	}
}

func TestCheckApproverKeys(t *testing.T) {
	approvers := []Approver{{Name: testBob, KeySHA256: testKeySumA}, {Name: testCarol, KeySHA256: testKeySumB}}
	if err := CheckApproverKeys(approvers, map[string]string{"0000": "elsewhere"}); err != nil {
		t.Errorf("distinct keys refused: %v", err)
	}
	err := CheckApproverKeys(approvers, map[string]string{strings.ToLower(testKeySumA): "TOOLMESH_API_KEY"})
	if err == nil || !strings.Contains(err.Error(), testBob) || !strings.Contains(err.Error(), "TOOLMESH_API_KEY") {
		t.Errorf("err = %v, want bob refused, naming where the key is used", err)
	}
}
