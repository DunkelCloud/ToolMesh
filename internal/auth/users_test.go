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
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

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
	user := store.Authenticate("admin", "admin-pw")
	if user == nil {
		t.Fatal("expected admin to authenticate")
	}
	if user.Username != "admin" {
		t.Errorf("Username = %q, want admin", user.Username)
	}
	if user.Company != "dunkelcloud" {
		t.Errorf("Company = %q, want dunkelcloud", user.Company)
	}
	if user.Plan != "pro" {
		t.Errorf("Plan = %q, want pro", user.Plan)
	}

	// Valid demo login
	user = store.Authenticate("demo", "demo-pw")
	if user == nil {
		t.Fatal("expected demo to authenticate")
	}
	if user.Plan != "free" {
		t.Errorf("Plan = %q, want free", user.Plan)
	}

	// Wrong password
	if store.Authenticate("admin", "wrong") != nil {
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
	if entry.Plan != "pro" {
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
	if entry.Plan != "free" {
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
