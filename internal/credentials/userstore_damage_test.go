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

package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// usRewrite loads the store file in dir, lets edit change it and writes it
// back, as someone with access to the file but not to the key could.
func usRewrite(t *testing.T, dir string, edit func(f *userFile)) {
	t.Helper()
	path := filepath.Join(dir, userFileName)
	data, err := os.ReadFile(path) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	var f userFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	edit(&f)
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFileUserStore_DamagedEntryIsUnreadable pins that an entry whose
// sealed parts were damaged reads as unreadable. A nonce of the wrong
// length makes the cipher panic when it is not checked first.
func TestFileUserStore_DamagedEntryIsUnreadable(t *testing.T) {
	ctx := context.Background()
	damage := map[string]func(e *userFileEntry){
		"empty nonce": func(e *userFileEntry) { e.Nonce = nil },
		"short nonce": func(e *userFileEntry) { e.Nonce = e.Nonce[:8] },
		"long nonce":  func(e *userFileEntry) { e.Nonce = append(e.Nonce, 1, 2, 3, 4) },
		"empty value": func(e *userFileEntry) { e.Value = nil },
		"cut value":   func(e *userFileEntry) { e.Value = e.Value[:len(e.Value)-1] },
		"other nonce": func(e *userFileEntry) { e.Nonce[0] ^= 1 },
	}
	for name, edit := range damage {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := usOpen(t, dir, usKey(1)).PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
				t.Fatal(err)
			}
			usRewrite(t, dir, func(f *userFile) { edit(&f.Entries[0]) })
			s := usOpen(t, dir, usKey(1))
			if _, err := s.GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrUserCredentialUnreadable) {
				t.Fatalf("GetUser: err = %v, want ErrUserCredentialUnreadable", err)
			}
			// The user can replace a damaged entry by storing it again.
			if err := s.PutUser(ctx, usSlot(usAlice), "again"); err != nil {
				t.Fatal(err)
			}
			if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != "again" {
				t.Errorf("after storing again: %q, %v", got, err)
			}
		})
	}
}

// TestFileUserStore_DuplicateEntriesStopTheStore pins that a file with two
// entries for one slot is not used: which of them is meant cannot be told.
func TestFileUserStore_DuplicateEntriesStopTheStore(t *testing.T) {
	dir := t.TempDir()
	if err := usOpen(t, dir, usKey(1)).PutUser(context.Background(), usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	usRewrite(t, dir, func(f *userFile) { f.Entries = append(f.Entries, f.Entries[0]) })
	if _, err := NewFileUserStore(dir, usKey(1)); err == nil {
		t.Fatal("the store opened a file with two entries for one slot")
	}
}

// TestFileUserStore_RefusesInvalidUTF8 pins that slot parts are text: the
// file is JSON, and two ids that differ in an invalid byte would read back
// as the same id after a restart.
func TestFileUserStore_RefusesInvalidUTF8(t *testing.T) {
	ctx := context.Background()
	s := usOpen(t, t.TempDir(), usKey(1))
	for name, slot := range map[string]UserSlot{
		"user id":         {UserID: "al\xffice", Backend: usBackend, Account: usAccount, Name: usName},
		"backend name":    {UserID: usAlice, Backend: "ma\xfeil", Account: usAccount, Name: usName},
		"credential name": {UserID: usAlice, Backend: usBackend, Account: usAccount, Name: "MAIL\xff"},
	} {
		if err := s.PutUser(ctx, slot, usSecret); err == nil {
			t.Errorf("%s with an invalid byte: stored", name)
		}
	}
}

func TestFileUserStore_Users(t *testing.T) {
	ctx := context.Background()
	s := usOpen(t, t.TempDir(), usKey(1))
	if got := s.Users(); len(got) != 0 {
		t.Errorf("empty store: Users = %v", got)
	}
	for _, user := range []string{usBob, usAlice, usAlice} {
		slot := UserSlot{UserID: user, Backend: usBackend, Account: user + "@example.com", Name: usName}
		if err := s.PutUser(ctx, slot, usSecret); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Users(); len(got) != 2 || got[0] != usAlice || got[1] != usBob {
		t.Errorf("Users = %v, want alice and bob once each, sorted", got)
	}
}

// TestFileUserStore_WriteFailureKeepsMemoryAndDiskAlike pins that a value
// that could not be written is not served from memory either: after a
// restart it would be gone without anybody having removed it.
func TestFileUserStore_WriteFailureKeepsMemoryAndDiskAlike(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))
	if err := s.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	// Writes fail from here: the store's file becomes a path that cannot
	// hold a temporary file next to it.
	s.path = filepath.Join(dir, "gone", userFileName)

	if err := s.PutUser(ctx, usSlot(usAlice), "new-value"); err == nil {
		t.Fatal("PutUser succeeded although the file cannot be written")
	}
	if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("after a failed replace: %q, %v, want the earlier value", got, err)
	}
	if err := s.PutUser(ctx, usSlot(usBob), "bobs"); err == nil {
		t.Fatal("PutUser of a new slot succeeded although the file cannot be written")
	}
	if _, err := s.GetUser(ctx, usSlot(usBob)); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("after a failed first store: err = %v, want nothing stored", err)
	}
	if had, err := s.DeleteUser(ctx, usSlot(usAlice)); err == nil || had {
		t.Fatalf("DeleteUser = %v, %v, want a failure", had, err)
	}
	if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("after a failed delete: %q, %v, want the value still there", got, err)
	}
	// The file on disk is what it was.
	if got, err := usOpen(t, dir, usKey(1)).GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("on disk: %q, %v", got, err)
	}
}

// listFailingStore is a UserStore whose listing fails with an error that
// wraps ErrCredentialNotFound, as a careless store might.
type listFailingStore struct{ UserStore }

func (listFailingStore) ListUser(context.Context, string) ([]UserCredentialInfo, error) {
	return nil, errors.Join(errors.New("backend of the store is away"), ErrCredentialNotFound)
}

// TestUserScopedStore_ErrorNeverReadsAsNotFound pins the error chain: for
// the auth layer ErrCredentialNotFound means "send without authentication".
// No failure of a user's credential may read as that, whatever the store's
// own error wraps.
func TestUserScopedStore_ErrorNeverReadsAsNotFound(t *testing.T) {
	s := NewUserScopedStore(instanceCreds{}, listFailingStore{}, usBackend, []string{usLower}, "")
	_, err := s.Get(context.Background(), usLower, TenantInfo{UserID: usAlice})
	uce := userErr(t, err) // fails the test when errors.Is finds ErrCredentialNotFound
	if uce.Reason != UserCredentialStoreFailed || uce.Err == nil {
		t.Errorf("error = %+v, want the store failure with its cause kept for logs", uce)
	}
}

// TestUserScopedStore_OwnAccountDoesNotOpenAnothers pins the case of a user
// who has an account and names the label of someone else's.
func TestUserScopedStore_OwnAccountDoesNotOpenAnothers(t *testing.T) {
	ctx := context.Background()
	s, users := scopedFixture(t)
	if err := users.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	bobs := UserSlot{UserID: usBob, Backend: usBackend, Account: usBobAcct, Name: usName}
	if err := users.PutUser(ctx, bobs, "bobs-secret"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get(ctx, usLower, TenantInfo{UserID: usBob, Account: usAccount})
	uce := userErr(t, err)
	if uce.Reason != UserCredentialUnknownAccount || len(uce.Accounts) != 1 || uce.Accounts[0] != usBobAcct {
		t.Errorf("bob naming alice's label: %+v, want his own accounts listed and nothing of hers", uce)
	}
	if got, err := s.Get(ctx, usLower, TenantInfo{UserID: usBob}); err != nil || got != "bobs-secret" {
		t.Errorf("bob's own account: %q, %v", got, err)
	}
}
