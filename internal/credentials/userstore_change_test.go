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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures of the tests of a change of several slots.
const (
	chPin      = "MAIL_PIN"
	chPinValue = "4711"
	chNewValue = "what-alice-stored-later" //nolint:gosec // test fixture, not a credential
)

func chSlot(name string) UserSlot {
	return UserSlot{UserID: usAlice, Backend: usBackend, Account: usAccount, Name: name}
}

// chFile returns the store's file as it is on disk.
func chFile(t *testing.T, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, userFileName)) //nolint:gosec // G304: a file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestFileUserStore_ChangeUserIsOneWrite pins that a change of several
// slots is applied whole: every value is there after it, and a change the
// store refuses or cannot write leaves memory and file as they were.
func TestFileUserStore_ChangeUserIsOneWrite(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))
	if err := s.PutUser(ctx, chSlot(optScope), optValue); err != nil {
		t.Fatal(err)
	}

	// Two values stored and one slot emptied, as one change.
	before, err := s.ChangeUser(ctx, UserChange{
		Put:    map[UserSlot]string{chSlot(usName): usSecret, chSlot(chPin): chPinValue},
		Delete: []UserSlot{chSlot(optScope), chSlot("NEVER_STORED")},
	})
	if err != nil {
		t.Fatalf("ChangeUser: %v", err)
	}
	if got, err := s.GetUser(ctx, chSlot(usName)); err != nil || got != usSecret {
		t.Errorf("first value: %q, %v", got, err)
	}
	if got, err := s.GetUser(ctx, chSlot(chPin)); err != nil || got != chPinValue {
		t.Errorf("second value: %q, %v", got, err)
	}
	if _, err := s.GetUser(ctx, chSlot(optScope)); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("the emptied slot: err = %v", err)
	}
	// The file holds the same: a store opened on it sees the change.
	reopened := usOpen(t, dir, usKey(1))
	if infos, _ := reopened.ListUser(ctx, usAlice); len(infos) != 2 {
		t.Errorf("the file holds %d entries, want 2", len(infos))
	}
	if len(before.entries) != 4 || before.entries[chSlot(optScope)] == nil || before.entries[chSlot(usName)] != nil {
		t.Errorf("the snapshot = %+v, want the four slots of the change with what they held", before.entries)
	}

	// Changes that are refused change nothing.
	file := chFile(t, dir)
	for name, change := range map[string]UserChange{
		"an empty value":        {Put: map[UserSlot]string{chSlot(usName): chNewValue, chSlot(chPin): ""}},
		"a value too long":      {Put: map[UserSlot]string{chSlot(usName): chNewValue, chSlot(chPin): strings.Repeat("x", MaxUserCredentialBytes+1)}},
		"a slot without a user": {Put: map[UserSlot]string{chSlot(usName): chNewValue, {Backend: usBackend, Account: usAccount, Name: chPin}: "v"}},
		"stored and removed":    {Put: map[UserSlot]string{chSlot(usName): chNewValue}, Delete: []UserSlot{chSlot(usLower)}},
	} {
		if _, err := s.ChangeUser(ctx, change); err == nil {
			t.Errorf("%s: the change was accepted", name)
		}
		if got, err := s.GetUser(ctx, chSlot(usName)); err != nil || got != usSecret {
			t.Errorf("%s: the other value of the refused change was stored: %q, %v", name, got, err)
		}
		if chFile(t, dir) != file {
			t.Errorf("%s: the file changed", name)
		}
	}

	// A change that cannot be written: memory follows the file.
	path := s.path
	s.path = filepath.Join(dir, "gone", userFileName)
	if _, err := s.ChangeUser(ctx, UserChange{Put: map[UserSlot]string{chSlot(usName): chNewValue}, Delete: []UserSlot{chSlot(chPin)}}); err == nil {
		t.Fatal("ChangeUser succeeded although the file cannot be written")
	}
	s.path = path
	if got, err := s.GetUser(ctx, chSlot(usName)); err != nil || got != usSecret {
		t.Errorf("after a change that could not be written: %q, %v, want the earlier value", got, err)
	}
	if got, err := s.GetUser(ctx, chSlot(chPin)); err != nil || got != chPinValue {
		t.Errorf("after a change that could not be written the removed slot holds %q, %v", got, err)
	}
	if chFile(t, dir) != file {
		t.Error("the file changed although the change failed")
	}
}

// TestFileUserStore_RestoreUserPutsEntriesBackAsTheyWere pins the rollback
// of a change: every slot holds again what it held, byte for byte. That
// includes an entry that cannot be read: it is neither lost nor made
// readable, so that an account whose limit cannot be read stays an account
// with a limit.
func TestFileUserStore_RestoreUserPutsEntriesBackAsTheyWere(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	// One entry sealed under a key that is gone, one readable entry.
	if err := usOpen(t, dir, usKey(9)).PutUser(ctx, chSlot(optScope), optValue); err != nil {
		t.Fatal(err)
	}
	s := usOpen(t, dir, usKey(1))
	at := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return at }
	if err := s.PutUser(ctx, chSlot(usName), usSecret); err != nil {
		t.Fatal(err)
	}
	file := chFile(t, dir)

	// A change over all three kinds of slot: readable, unreadable, empty.
	s.now = func() time.Time { return at.Add(time.Hour) }
	before, err := s.ChangeUser(ctx, UserChange{
		Put:    map[UserSlot]string{chSlot(usName): chNewValue, chSlot(chPin): chPinValue},
		Delete: []UserSlot{chSlot(optScope)},
	})
	if err != nil {
		t.Fatalf("ChangeUser: %v", err)
	}
	if chFile(t, dir) == file {
		t.Fatal("the change did not reach the file")
	}

	if err := s.RestoreUser(ctx, before); err != nil {
		t.Fatalf("RestoreUser: %v", err)
	}
	if got := chFile(t, dir); got != file {
		t.Errorf("the file after the rollback differs from the file before the change:\n%s\n--- before ---\n%s", got, file)
	}
	if got, err := s.GetUser(ctx, chSlot(usName)); err != nil || got != usSecret {
		t.Errorf("the readable entry: %q, %v", got, err)
	}
	if _, err := s.GetUser(ctx, chSlot(optScope)); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Errorf("the unreadable entry after the rollback: err = %v, want it back and still unreadable", err)
	}
	if _, err := s.GetUser(ctx, chSlot(chPin)); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("the slot that was empty: err = %v", err)
	}
	infos, _ := s.ListUser(ctx, usAlice)
	for _, info := range infos {
		if info.Name == usName && !info.UpdatedAt.Equal(at) {
			t.Errorf("the restored entry is dated %s, want the time it was stored, %s", info.UpdatedAt, at)
		}
	}

	// A rollback that cannot be written says so and leaves the change in
	// place, in memory as in the file.
	changed, err := s.ChangeUser(ctx, UserChange{Put: map[UserSlot]string{chSlot(usName): chNewValue}})
	if err != nil {
		t.Fatal(err)
	}
	path := s.path
	s.path = filepath.Join(dir, "gone", userFileName)
	if err := s.RestoreUser(ctx, changed); err == nil {
		t.Fatal("RestoreUser succeeded although the file cannot be written")
	}
	s.path = path
	if got, err := s.GetUser(ctx, chSlot(usName)); err != nil || got != chNewValue {
		t.Errorf("after a rollback that could not be written: %q, %v, want the changed value as in the file", got, err)
	}

	// A snapshot of nothing restores nothing.
	if err := s.RestoreUser(ctx, UserSnapshot{}); err != nil {
		t.Errorf("RestoreUser of an empty snapshot: %v", err)
	}
}

// lyingStore is a UserStore whose GetUser fails, for the optional name, in
// a way that reads as "not found".
type lyingStore struct {
	*FileUserStore
}

func (s *lyingStore) GetUser(ctx context.Context, slot UserSlot) (string, error) {
	if strings.EqualFold(slot.Name, optScope) {
		return "", ErrCredentialNotFound
	}
	return s.FileUserStore.GetUser(ctx, slot)
}

// TestUserScopedStore_OptionalAbsenceNeedsTheListing pins that an optional
// value counts as absent only when the listing has none either. A store
// that fails to return a value it lists must not make that value
// disappear: a reader would leave out a limit that exists.
func TestUserScopedStore_OptionalAbsenceNeedsTheListing(t *testing.T) {
	ctx := context.Background()
	users := usOpen(t, t.TempDir(), usKey(1))
	if err := users.PutUser(ctx, optSlot(usName), usSecret); err != nil {
		t.Fatal(err)
	}
	if err := users.PutUser(ctx, optSlot(optScope), optValue); err != nil {
		t.Fatal(err)
	}
	lying := &lyingStore{FileUserStore: users}
	s := NewUserScopedStore(instanceCreds{}, lying, usBackend, []string{usLower, optScopeLower}, scopedURL).WithOptional(optScopeLower)

	_, err := s.Get(ctx, optScopeLower, TenantInfo{UserID: usAlice})
	if uce := userErr(t, err); uce.Reason != UserCredentialStoreFailed {
		t.Fatalf("a listed value the store does not return: reason %q, want %q", uce.Reason, UserCredentialStoreFailed)
	}

	// The same store without the value: absent, as the listing agrees.
	if _, err := users.DeleteUser(ctx, optSlot(optScope)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, optScopeLower, TenantInfo{UserID: usAlice}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("an optional value neither stored nor listed: err = %v, want ErrCredentialNotFound", err)
	}
}
