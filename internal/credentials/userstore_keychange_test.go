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
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	kcBobValue = "what-bob-stored" //nolint:gosec // test fixture, not a credential
	kcThird    = "third@example.com"
)

// kcFile returns the bytes of the store's file in dir.
func kcFile(t *testing.T, dir string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, userFileName)) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// kcEntries returns the entries of the store's file in dir by user and
// account.
func kcEntries(t *testing.T, dir string) map[string]userFileEntry {
	t.Helper()
	out := map[string]userFileEntry{}
	usRewrite(t, dir, func(f *userFile) {
		for _, e := range f.Entries {
			out[e.User+"/"+e.Account] = e
		}
	})
	return out
}

// TestFileUserStore_ChangeKey is the change of the key as an operator makes
// it: the store is opened with the key in use and told the next one. What
// the old key opened is sealed under the next one, nobody has to store
// anything again, and the old key opens nothing any more.
func TestFileUserStore_ChangeKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := usKey(1), usKey(2)
	s := usOpen(t, dir, oldKey)
	stored := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return stored }
	if err := s.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	bob := UserSlot{UserID: usBob, Backend: usBackend, Account: usBobAcct, Name: usName}
	if err := s.PutUser(ctx, bob, kcBobValue); err != nil {
		t.Fatal(err)
	}
	s.now = time.Now

	change, err := s.ChangeKey(nextKey)
	if err != nil {
		t.Fatal(err)
	}
	if change != (KeyChange{Resealed: 2}) {
		t.Errorf("change = %+v, want both values sealed again", change)
	}
	// The store that made the change runs on the next key.
	if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("after the change: %q, %v", got, err)
	}
	office := UserSlot{UserID: usAlice, Backend: usBackend, Account: kcThird, Name: usName}
	if err := s.PutUser(ctx, office, "stored-after-the-change"); err != nil {
		t.Fatal(err)
	}

	// On disk: everything under the next key, still padded, and the time a
	// user stored a value is the time they stored it.
	entries := kcEntries(t, dir)
	if len(entries) != 3 {
		t.Fatalf("entries on disk = %d, want 3", len(entries))
	}
	for name, e := range entries {
		if e.KeyID != userKeyID(nextKey) {
			t.Errorf("%s: sealed under key %s, want the next key %s", name, e.KeyID, userKeyID(nextKey))
		}
		if (len(e.Value)-16)%userValueBlock != 0 {
			t.Errorf("%s: sealed value of %d bytes is not padded to the block", name, len(e.Value))
		}
	}
	if got := entries[usAlice+"/"+usAccount].UpdatedAt; !got.Equal(stored) {
		t.Errorf("the change moved the time alice stored her value to %s", got)
	}

	// A later start with the next key alone reads everything.
	onNext := usOpen(t, dir, nextKey)
	for slot, want := range map[UserSlot]string{usSlot(usAlice): usSecret, bob: kcBobValue, office: "stored-after-the-change"} {
		if got, err := onNext.GetUser(ctx, slot); err != nil || got != want {
			t.Errorf("with the next key, %s/%s: %q, %v", slot.UserID, slot.Account, got, err)
		}
	}
	// The old key opens nothing any more.
	onOld := usOpen(t, dir, oldKey)
	if _, err := onOld.GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Errorf("with the old key after the change: %v, want unreadable", err)
	}
	// A sealed value still belongs to its slot.
	usRewrite(t, dir, func(f *userFile) {
		for i := range f.Entries {
			if f.Entries[i].User == usBob {
				f.Entries[i].User = "mallory"
			}
		}
	})
	moved := UserSlot{UserID: "mallory", Backend: usBackend, Account: usBobAcct, Name: usName}
	if _, err := usOpen(t, dir, nextKey).GetUser(ctx, moved); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Errorf("an entry moved to another user after the change: %v, want unreadable", err)
	}
}

// TestFileUserStore_ChangeKey_StartAfterTheChange pins the start that
// follows a change while both keys are still configured: the key in use
// opens nothing, the next one opens everything, and nothing is written.
func TestFileUserStore_ChangeKey_StartAfterTheChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := usKey(1), usKey(2)
	first := usOpen(t, dir, oldKey)
	if err := first.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := first.ChangeKey(nextKey); err != nil {
		t.Fatal(err)
	}
	before := kcFile(t, dir)

	again := usOpen(t, dir, oldKey)
	if _, err := again.GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Fatalf("with the old key before the change is repeated: %v, want unreadable", err)
	}
	// The file cannot be written from here on: a change with nothing left
	// to do must not try to.
	path := again.path
	again.path = filepath.Join(dir, "gone", userFileName)
	change, err := again.ChangeKey(nextKey)
	again.path = path
	if err != nil {
		t.Fatalf("a change with nothing left to do tried to write the file: %v", err)
	}
	if change != (KeyChange{UnderNext: 1}) {
		t.Errorf("change = %+v, want the one value found under the next key", change)
	}
	if got, err := again.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("after the repeated change: %q, %v", got, err)
	}
	if !bytes.Equal(before, kcFile(t, dir)) {
		t.Error("a start with nothing left to change wrote the file")
	}
}

// TestFileUserStore_ChangeKey_Mixed pins what happens to each kind of
// entry: one under the key in use is sealed again, one under the next key
// is left alone, and one that neither key opens stays as it is, byte for
// byte.
func TestFileUserStore_ChangeKey_Mixed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey, otherKey := usKey(1), usKey(2), usKey(3)
	bob := UserSlot{UserID: usBob, Backend: usBackend, Account: usBobAcct, Name: usName}
	third := UserSlot{UserID: usAlice, Backend: usBackend, Account: kcThird, Name: usName}
	if err := usOpen(t, dir, oldKey).PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	if err := usOpen(t, dir, nextKey).PutUser(ctx, bob, kcBobValue); err != nil {
		t.Fatal(err)
	}
	if err := usOpen(t, dir, otherKey).PutUser(ctx, third, "under-a-key-nobody-has"); err != nil {
		t.Fatal(err)
	}
	before := kcEntries(t, dir)

	s := usOpen(t, dir, oldKey)
	change, err := s.ChangeKey(nextKey)
	if err != nil {
		t.Fatal(err)
	}
	if change != (KeyChange{Resealed: 1, UnderNext: 1, Unreadable: 1}) {
		t.Errorf("change = %+v, want one of each", change)
	}
	if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("the value under the old key: %q, %v", got, err)
	}
	if got, err := s.GetUser(ctx, bob); err != nil || got != kcBobValue {
		t.Errorf("the value under the next key: %q, %v", got, err)
	}
	if _, err := s.GetUser(ctx, third); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Errorf("the value under another key: %v, want unreadable", err)
	}
	after := kcEntries(t, dir)
	for _, name := range []string{usBob + "/" + usBobAcct, usAlice + "/" + kcThird} {
		if !bytes.Equal(before[name].Value, after[name].Value) || !bytes.Equal(before[name].Nonce, after[name].Nonce) || before[name].KeyID != after[name].KeyID {
			t.Errorf("%s: an entry the change had nothing to do with was rewritten", name)
		}
	}
	if name := usAlice + "/" + usAccount; bytes.Equal(before[name].Value, after[name].Value) || after[name].KeyID != userKeyID(nextKey) {
		t.Errorf("%s: the entry under the old key was not sealed again under the next one", name)
	}
	// Sealing again is a new seal: it takes a nonce of its own.
	if name := usAlice + "/" + usAccount; bytes.Equal(before[name].Nonce, after[name].Nonce) {
		t.Errorf("%s: the value was sealed again with the nonce it had", name)
	}
}

// TestFileUserStore_ChangeKey_Failures pins that a change that cannot be
// made changes nothing: the store keeps running on the key it was opened
// with, and the file is what it was.
func TestFileUserStore_ChangeKey_Failures(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := usKey(1), usKey(2)
	s := usOpen(t, dir, oldKey)
	if err := s.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	before := kcFile(t, dir)

	if _, err := s.ChangeKey(nextKey[:16]); err == nil {
		t.Error("a key of the wrong length was accepted")
	}
	// The file cannot be written: its path cannot hold a temporary file.
	path := s.path
	s.path = filepath.Join(dir, "gone", userFileName)
	if change, err := s.ChangeKey(nextKey); err == nil {
		t.Errorf("the change succeeded although the file cannot be written: %+v", change)
	}
	s.path = path

	if got, err := s.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("after a failed change the store reads %q, %v; want it to run on the old key", got, err)
	}
	bob := UserSlot{UserID: usBob, Backend: usBackend, Account: usBobAcct, Name: usName}
	if err := s.PutUser(ctx, bob, kcBobValue); err != nil {
		t.Fatal(err)
	}
	if e := kcEntries(t, dir)[usBob+"/"+usBobAcct]; e.KeyID != userKeyID(oldKey) {
		t.Errorf("after a failed change a new value is sealed under key %s, want the old key", e.KeyID)
	}
	if got, err := usOpen(t, dir, oldKey).GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Errorf("on disk after a failed change: %q, %v", got, err)
	}
	if bytes.Equal(before, kcFile(t, dir)) {
		t.Error("the later store of a value did not reach the file")
	}

	// And then the change goes through.
	change, err := s.ChangeKey(nextKey)
	if err != nil || change != (KeyChange{Resealed: 2}) {
		t.Errorf("the change after the failure: %+v, %v", change, err)
	}
}
