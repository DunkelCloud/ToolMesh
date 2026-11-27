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

package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// Usernames of the reload tests.
const (
	reloadAda   = "ada"
	reloadGrace = "grace"
	reloadLinus = "linus"
)

// TestParseUserStore_Problems pins what a reload of users.yaml refuses while
// the startup still loads it.
func TestParseUserStore_Problems(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{"fine", "users:\n  - username: ada\n", ""},
		{"empty list", "users: []\n", ""},
		{"empty file", "", "no users list"},
		{"misspelled key", "user:\n  - username: ada\n", "no users list"},
		{"no username", "users:\n  - plan: pro\n", "has no username"},
		{"listed twice", "users:\n  - username: ada\n  - username: ada\n", "listed more than once"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store, err := ParseUserStore([]byte(tc.content), nil)
			if err != nil {
				t.Fatalf("ParseUserStore: %v", err)
			}
			got := strings.Join(store.Problems(), "; ")
			if (tc.want == "") != (got == "") || !strings.Contains(got, tc.want) {
				t.Errorf("problems = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUserStore_Diff pins which users a reload reports as added, removed and
// changed.
func TestUserStore_Diff(t *testing.T) {
	parse := func(content string) *UserStore {
		t.Helper()
		store, err := ParseUserStore([]byte(content), nil)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	before := parse("users:\n  - username: ada\n    password_hash: a\n    roles: [admin]\n  - username: grace\n    password_hash: g\n  - username: linus\n    password_hash: l\n")
	after := parse("users:\n  - username: ada\n    password_hash: a\n    roles: [viewer]\n  - username: linus\n    password_hash: l2\n  - username: new\n    password_hash: n\n")

	added, removed, changed := before.Diff(after)
	if !slices.Equal(added, []string{"new"}) || !slices.Equal(removed, []string{reloadGrace}) || !slices.Equal(changed, []string{reloadAda, reloadLinus}) {
		t.Errorf("Diff = added %v removed %v changed %v", added, removed, changed)
	}

	// A nil store holds no users.
	added, removed, _ = (*UserStore)(nil).Diff(before)
	if len(added) != 3 || len(removed) != 0 {
		t.Errorf("Diff from nil = added %v removed %v", added, removed)
	}
}

// TestAPIKeyStore_Diff pins which entries a reload reports as added and
// removed, and the key_sha256 sums of the loaded entries.
func TestAPIKeyStore_Diff(t *testing.T) {
	sum := func(key string) string {
		s := sha256.Sum256([]byte(key))
		return hex.EncodeToString(s[:])
	}
	parse := func(content string) *APIKeyStore {
		t.Helper()
		store, err := ParseAPIKeyStore([]byte(content), nil)
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	before := parse("keys:\n  - user_id: ada\n    key_sha256: " + strings.ToUpper(sum("key-ada")) + "\n  - user_id: grace\n    key_sha256: " + sum("key-grace") + "\n")
	after := parse("keys:\n  - user_id: grace\n    key_sha256: " + sum("key-grace") + "\n  - user_id: linus\n    key_sha256: " + sum("key-linus") + "\n    caller_id: ci\n")

	added, removed := before.Diff(after)
	if !slices.Equal(added, []string{reloadLinus + " (caller_id ci)"}) || !slices.Equal(removed, []string{reloadAda}) {
		t.Errorf("Diff = added %v removed %v", added, removed)
	}
	sums := before.SHA256Sums()
	if _, ok := sums[sum("key-ada")]; !ok || len(sums) != 2 {
		t.Errorf("SHA256Sums = %v, want both entries in lower case", sums)
	}
}

// TestParseAPIKeyStore_Problems pins that a file without a keys list is
// reported.
func TestParseAPIKeyStore_Problems(t *testing.T) {
	for content, want := range map[string]bool{"keys: []\n": false, "": true, "key:\n  - user_id: ada\n": true} {
		store, err := ParseAPIKeyStore([]byte(content), nil)
		if err != nil {
			t.Fatalf("ParseAPIKeyStore(%q): %v", content, err)
		}
		if got := len(store.Problems()) > 0; got != want {
			t.Errorf("ParseAPIKeyStore(%q) problems = %v, want reported %v", content, store.Problems(), want)
		}
	}
}
