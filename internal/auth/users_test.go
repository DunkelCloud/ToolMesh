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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// testUserBroken names a users.yaml entry whose password_hash is unusable.
const testUserBroken = "broken"

func TestUserStore_Authenticate(t *testing.T) {
	adminHash, _ := bcrypt.GenerateFromPassword([]byte("admin-pw"), bcrypt.MinCost)
	demoHash, _ := bcrypt.GenerateFromPassword([]byte("demo-pw"), bcrypt.MinCost)

	dir := t.TempDir()
	path := filepath.Join(dir, "users.yaml")
	content := `users:
  - username: admin
    password_hash: "` + string(adminHash) + `"
    company: dunkelcloud
    plan: pro
    roles: [admin]
  - username: demo
    password_hash: "` + string(demoHash) + `"
    company: demo-corp
    plan: free
    roles: [viewer]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := NewUserStore(path)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}

	// Valid admin login
	user := store.Authenticate(testUserAdmin, "admin-pw")
	if user == nil {
		t.Fatal("expected admin to authenticate")
	}
	if user.Username != testUserAdmin {
		t.Errorf("Username = %q, want admin", user.Username)
	}
	if user.Company != testCompanyDunkel {
		t.Errorf("Company = %q, want dunkelcloud", user.Company)
	}
	if user.Plan != testPlanPro {
		t.Errorf("Plan = %q, want pro", user.Plan)
	}

	// Valid demo login
	user = store.Authenticate("demo", "demo-pw")
	if user == nil {
		t.Fatal("expected demo to authenticate")
	}
	if user.Plan != testPlanFree {
		t.Errorf("Plan = %q, want free", user.Plan)
	}

	// Wrong password
	if store.Authenticate(testUserAdmin, "wrong") != nil {
		t.Error("expected nil for wrong password")
	}

	// Unknown user
	if store.Authenticate("unknown", "admin-pw") != nil {
		t.Error("expected nil for unknown user")
	}
}

func TestUserStore_NonExistentFile(t *testing.T) {
	store, err := NewUserStore("/nonexistent/path/users.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store != nil {
		t.Error("expected nil store for nonexistent file")
	}
}

func TestAPIKeyStore_Match(t *testing.T) {
	key1Hash, _ := bcrypt.GenerateFromPassword([]byte("key-one"), bcrypt.MinCost)
	key2Hash, _ := bcrypt.GenerateFromPassword([]byte("key-two"), bcrypt.MinCost)

	dir := t.TempDir()
	path := filepath.Join(dir, "apikeys.yaml")
	content := `keys:
  - key_hash: "` + string(key1Hash) + `"
    user_id: user-one
    company_id: company-a
    plan: pro
    roles: [tool-executor]
    caller_id: claude
  - key_hash: "` + string(key2Hash) + `"
    user_id: user-two
    company_id: company-b
    plan: free
    roles: [viewer]
`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	store, err := NewAPIKeyStore(path)
	if err != nil {
		t.Fatalf("NewAPIKeyStore: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}

	// Match first key
	entry := store.Match("key-one")
	if entry == nil {
		t.Fatal("expected match for key-one")
	}
	if entry.UserID != "user-one" {
		t.Errorf("UserID = %q, want user-one", entry.UserID)
	}
	if entry.CompanyID != "company-a" {
		t.Errorf("CompanyID = %q, want company-a", entry.CompanyID)
	}
	if entry.Plan != testPlanPro {
		t.Errorf("Plan = %q, want pro", entry.Plan)
	}
	if entry.CallerID != "claude" {
		t.Errorf("CallerID = %q, want claude", entry.CallerID)
	}

	// Match second key
	entry = store.Match("key-two")
	if entry == nil {
		t.Fatal("expected match for key-two")
	}
	if entry.UserID != "user-two" {
		t.Errorf("UserID = %q, want user-two", entry.UserID)
	}
	if entry.Plan != testPlanFree {
		t.Errorf("Plan = %q, want free", entry.Plan)
	}

	// No match
	if store.Match("wrong-key") != nil {
		t.Error("expected nil for wrong key")
	}
}

func TestAPIKeyStore_NonExistentFile(t *testing.T) {
	store, err := NewAPIKeyStore("/nonexistent/path/apikeys.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store != nil {
		t.Error("expected nil store for nonexistent file")
	}
}

// writeUsersFile writes a users.yaml with one entry per name, each hashed at
// the given bcrypt cost with the password "<name>-pw".
func writeUsersFile(t *testing.T, costs map[string]int) string {
	t.Helper()
	content := "users:\n"
	for name, cost := range costs {
		hash, err := bcrypt.GenerateFromPassword([]byte(name+"-pw"), cost)
		if err != nil {
			t.Fatalf("hash for %s: %v", name, err)
		}
		content += "  - username: " + name + "\n    password_hash: \"" + string(hash) + "\"\n"
	}
	path := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestUserStore_UnknownUserRunsBcrypt pins the equal-timing path: an unknown
// username must cost one bcrypt comparison at the same cost as a configured
// user, instead of returning before any hashing happens.
func TestUserStore_UnknownUserRunsBcrypt(t *testing.T) {
	const cost = bcrypt.MinCost + 1
	store, err := NewUserStore(writeUsersFile(t, map[string]int{testUserAdmin: cost}))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	if got, err := bcrypt.Cost(store.dummyHash); err != nil || got != cost {
		t.Fatalf("dummy hash cost = %d (err %v), want %d like the configured user", got, err, cost)
	}

	var compared [][]byte
	store.compare = func(hash, password []byte) error {
		compared = append(compared, hash)
		return bcrypt.CompareHashAndPassword(hash, password)
	}

	if store.Authenticate("nobody", "admin-pw") != nil {
		t.Error("unknown user must not authenticate")
	}
	if len(compared) != 1 || string(compared[0]) != string(store.dummyHash) {
		t.Fatalf("unknown user: got %d comparisons, want exactly one against the dummy hash", len(compared))
	}

	compared = nil
	if store.Authenticate(testUserAdmin, "wrong") != nil {
		t.Error("wrong password must not authenticate")
	}
	if len(compared) != 1 || string(compared[0]) == string(store.dummyHash) {
		t.Fatalf("known user: got %d comparisons, want exactly one against the user's own hash", len(compared))
	}

	compared = nil
	if store.Authenticate(testUserAdmin, "admin-pw") == nil {
		t.Error("correct password must authenticate")
	}
	if len(compared) != 1 {
		t.Errorf("successful login: got %d comparisons, want 1", len(compared))
	}
}

// TestUserStore_DummyHashNeverMatches guards the one way the dummy hash could
// turn into a credential: a comparison that succeeds for an unknown user must
// still be rejected.
func TestUserStore_DummyHashNeverMatches(t *testing.T) {
	store, err := NewUserStore(writeUsersFile(t, map[string]int{testUserAdmin: bcrypt.MinCost}))
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}
	store.compare = func(_, _ []byte) error { return nil }

	if store.Authenticate("nobody", "anything") != nil {
		t.Error("unknown user authenticated although only the dummy hash matched")
	}
}

func TestDummyHashCost(t *testing.T) {
	hashAt := func(cost int) string {
		h, err := bcrypt.GenerateFromPassword([]byte("x"), cost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	low, high := hashAt(bcrypt.MinCost), hashAt(bcrypt.MinCost+1)

	tests := []struct {
		name   string
		hashes []string
		want   int
	}{
		{"no users", nil, bcrypt.DefaultCost},
		{"only unparseable hashes", []string{"", "not-a-hash"}, bcrypt.DefaultCost},
		{"single cost", []string{low, low}, bcrypt.MinCost},
		{"most common cost wins", []string{low, low, high}, bcrypt.MinCost},
		{"tie goes to the higher cost", []string{low, high}, bcrypt.MinCost + 1},
		{"unparseable hashes are ignored", []string{testUserBroken, high}, bcrypt.MinCost + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := make([]UserEntry, len(tt.hashes))
			for i, h := range tt.hashes {
				users[i].PasswordHash = h
			}
			if got := dummyHashCost(users); got != tt.want {
				t.Errorf("dummyHashCost = %d, want %d", got, tt.want)
			}
		})
	}
}

// An entry with a broken password_hash can never log in, but it must not
// answer faster than an unknown user either.
func TestUserStore_UnusableHashRunsBcryptAgainstDummy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.yaml")
	content := "users:\n  - username: broken\n    password_hash: \"not-a-bcrypt-hash\"\n  - username: empty\n    password_hash: \"\"\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewUserStore(path)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	for _, name := range []string{testUserBroken, "empty"} {
		var compared [][]byte
		store.compare = func(hash, password []byte) error {
			compared = append(compared, hash)
			return nil // even a comparison that "succeeds" must not log the user in
		}
		if store.Authenticate(name, "anything") != nil {
			t.Errorf("%s: authenticated despite an unusable password hash", name)
		}
		if len(compared) != 1 || string(compared[0]) != string(store.dummyHash) {
			t.Errorf("%s: got %d comparisons, want exactly one against the dummy hash", name, len(compared))
		}
	}
}

func TestUserStore_HashProblems(t *testing.T) {
	hashAt := func(cost int) string {
		h, err := bcrypt.GenerateFromPassword([]byte("x"), cost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}
	load := func(entries map[string]string) *UserStore {
		content := "users:\n"
		for name, hash := range entries {
			content += "  - username: " + name + "\n    password_hash: \"" + hash + "\"\n"
		}
		path := filepath.Join(t.TempDir(), "users.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		store, err := NewUserStore(path)
		if err != nil {
			t.Fatalf("NewUserStore: %v", err)
		}
		return store
	}

	unusable, costs := load(map[string]string{"a": hashAt(bcrypt.MinCost), "b": hashAt(bcrypt.MinCost)}).HashProblems()
	if len(unusable) != 0 || len(costs) != 0 {
		t.Errorf("uniform store: unusable=%v costs=%v, want none", unusable, costs)
	}

	unusable, costs = load(map[string]string{
		"a": hashAt(bcrypt.MinCost), "b": hashAt(bcrypt.MinCost + 1), "zed": "plaintext", testUserBroken: "",
	}).HashProblems()
	if len(unusable) != 2 || unusable[0] != testUserBroken || unusable[1] != "zed" {
		t.Errorf("unusable = %v, want [broken zed]", unusable)
	}
	if len(costs) != 2 || costs[0] != bcrypt.MinCost || costs[1] != bcrypt.MinCost+1 {
		t.Errorf("costs = %v, want [%d %d]", costs, bcrypt.MinCost, bcrypt.MinCost+1)
	}
}

// A hash that passes bcrypt's format check but has a damaged salt makes the
// comparison return at once. It must be treated like any other unusable hash:
// one comparison against the dummy, and reported at startup.
func TestUserStore_DamagedSaltIsUnusable(t *testing.T) {
	good, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// Same length and prefix, but '!' is outside bcrypt's base64 alphabet.
	damaged := string(good[:7]) + strings.Repeat("!", 22) + string(good[29:])
	if _, err := bcrypt.Cost([]byte(damaged)); err != nil {
		t.Fatalf("fixture must pass the format check: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(damaged), []byte("pw")); err == nil || errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("fixture must make the comparison fail without hashing, got %v", err)
	}
	if !usableHash(string(good)) {
		t.Fatal("a real bcrypt hash was judged unusable")
	}

	path := filepath.Join(t.TempDir(), "users.yaml")
	content := "users:\n  - username: " + testUserBroken + "\n    password_hash: '" + damaged + "'\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewUserStore(path)
	if err != nil {
		t.Fatalf("NewUserStore: %v", err)
	}

	var compared [][]byte
	store.compare = func(hash, password []byte) error {
		compared = append(compared, hash)
		return bcrypt.CompareHashAndPassword(hash, password)
	}
	if store.Authenticate(testUserBroken, "pw") != nil {
		t.Error("authenticated against a hash that cannot be evaluated")
	}
	if len(compared) != 1 || string(compared[0]) != string(store.dummyHash) {
		t.Errorf("got %d comparisons, want exactly one against the dummy hash", len(compared))
	}

	if unusable, _ := store.HashProblems(); len(unusable) != 1 || unusable[0] != testUserBroken {
		t.Errorf("HashProblems() unusable = %v, want [%s]", unusable, testUserBroken)
	}
}
