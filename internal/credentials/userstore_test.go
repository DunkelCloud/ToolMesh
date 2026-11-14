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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures of the user store tests.
const (
	usAlice   = "alice"
	usBob     = "bob"
	usBackend = "mail"
	usAccount = "alice@example.com"
	usName    = "MAIL_LOGIN"
	usLower   = "mail_login"        // usName as a DADL writes it
	usSecret  = "what-alice-stored" //nolint:gosec // test fixture, not a credential
	usBobAcct = "bob@example.com"
)

// usKey returns a fixed 32-byte key; fill varies it.
func usKey(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, UserCredentialsKeyBytes)
}

func usOpen(t *testing.T, dir string, key []byte) *FileUserStore {
	t.Helper()
	s, err := NewFileUserStore(dir, key)
	if err != nil {
		t.Fatalf("NewFileUserStore: %v", err)
	}
	return s
}

func usSlot(user string) UserSlot {
	return UserSlot{UserID: user, Backend: usBackend, Account: usAccount, Name: usName}
}

func TestFileUserStore_RoundTripAndPersistence(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))

	if _, err := s.GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("empty store: err = %v, want ErrCredentialNotFound", err)
	}
	if err := s.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatalf("PutUser: %v", err)
	}
	// The name is keyed in its upper-case form, the account lower-cased.
	lookup := UserSlot{UserID: usAlice, Backend: usBackend, Account: "Alice@Example.com", Name: usLower}
	if got, err := s.GetUser(ctx, lookup); err != nil || got != usSecret {
		t.Fatalf("GetUser = %q, %v", got, err)
	}
	// Another user, backend or account does not see it.
	for _, other := range []UserSlot{
		usSlot(usBob),
		{UserID: usAlice, Backend: "other", Account: usAccount, Name: usName},
		{UserID: usAlice, Backend: usBackend, Account: "second@example.com", Name: usName},
	} {
		if _, err := s.GetUser(ctx, other); !errors.Is(err, ErrCredentialNotFound) {
			t.Errorf("slot %+v: err = %v, want ErrCredentialNotFound", other, err)
		}
	}

	// A new process with the same key reads it back.
	reopened := usOpen(t, dir, usKey(1))
	if got, err := reopened.GetUser(ctx, usSlot(usAlice)); err != nil || got != usSecret {
		t.Fatalf("after reopen: GetUser = %q, %v", got, err)
	}
	infos, err := reopened.ListUser(ctx, usAlice)
	if err != nil || len(infos) != 1 {
		t.Fatalf("ListUser = %+v, %v", infos, err)
	}
	if infos[0].Backend != usBackend || infos[0].Account != usAccount || infos[0].Name != usName || !infos[0].Readable || infos[0].UpdatedAt.IsZero() {
		t.Errorf("ListUser entry = %+v", infos[0])
	}
	if infos, _ := reopened.ListUser(ctx, usBob); len(infos) != 0 {
		t.Errorf("bob lists %d entries of alice", len(infos))
	}

	if had, err := reopened.DeleteUser(ctx, usSlot(usAlice)); err != nil || !had {
		t.Fatalf("DeleteUser = %v, %v", had, err)
	}
	if had, err := reopened.DeleteUser(ctx, usSlot(usAlice)); err != nil || had {
		t.Errorf("second DeleteUser = %v, %v, want false", had, err)
	}
	if _, err := usOpen(t, dir, usKey(1)).GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrCredentialNotFound) {
		t.Errorf("after delete and reopen: err = %v", err)
	}
}

// TestFileUserStore_FileHoldsNoPlaintext pins that the value is not in the
// file, in any of the encodings a careless store would write.
func TestFileUserStore_FileHoldsNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))
	if err := s.PutUser(context.Background(), usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, userFileName)) //nolint:gosec // path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{usSecret, base64.StdEncoding.EncodeToString([]byte(usSecret)), hex.EncodeToString([]byte(usSecret))} {
		if bytes.Contains(data, []byte(form)) {
			t.Errorf("the file contains the value as %q", form)
		}
	}
	if !bytes.Contains(data, []byte(usAlice)) || !bytes.Contains(data, []byte(usName)) {
		t.Errorf("the file should name user and credential in the clear:\n%s", data)
	}
}

func TestFileUserStore_OtherKeyCannotRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := usOpen(t, dir, usKey(1)).PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	other := usOpen(t, dir, usKey(2))
	if _, err := other.GetUser(ctx, usSlot(usAlice)); !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Fatalf("other key: err = %v, want ErrUserCredentialUnreadable", err)
	}
	infos, _ := other.ListUser(ctx, usAlice)
	if len(infos) != 1 || infos[0].Readable {
		t.Errorf("ListUser under another key = %+v, want one unreadable entry", infos)
	}
	// Storing again under the new key makes it usable.
	if err := other.PutUser(ctx, usSlot(usAlice), "new"); err != nil {
		t.Fatal(err)
	}
	if got, err := other.GetUser(ctx, usSlot(usAlice)); err != nil || got != "new" {
		t.Errorf("after storing again: %q, %v", got, err)
	}
}

// TestFileUserStore_EntryDoesNotOpenElsewhere moves a sealed entry in the
// file to another user, backend, account and name. Whoever can write the
// file but lacks the key must not be able to hand one user's credential to
// another that way.
func TestFileUserStore_EntryDoesNotOpenElsewhere(t *testing.T) {
	ctx := context.Background()
	moves := map[string]func(e *userFileEntry){
		"another user":    func(e *userFileEntry) { e.User = usBob },
		"another backend": func(e *userFileEntry) { e.Backend = "other" },
		"another account": func(e *userFileEntry) { e.Account = usBobAcct },
		"another name":    func(e *userFileEntry) { e.Name = "OTHER_NAME" },
	}
	for what, move := range moves {
		t.Run(what, func(t *testing.T) {
			dir := t.TempDir()
			if err := usOpen(t, dir, usKey(1)).PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, userFileName)
			data, err := os.ReadFile(path) //nolint:gosec // path under t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			var f userFile
			if err := json.Unmarshal(data, &f); err != nil || len(f.Entries) != 1 {
				t.Fatalf("file: %v, %d entries", err, len(f.Entries))
			}
			move(&f.Entries[0])
			moved, _ := json.Marshal(f)
			if err := os.WriteFile(path, moved, 0o600); err != nil {
				t.Fatal(err)
			}
			s := usOpen(t, dir, usKey(1))
			e := f.Entries[0]
			_, err = s.GetUser(ctx, UserSlot{UserID: e.User, Backend: e.Backend, Account: e.Account, Name: e.Name})
			if !errors.Is(err, ErrUserCredentialUnreadable) {
				t.Errorf("moved entry: err = %v, want ErrUserCredentialUnreadable", err)
			}
		})
	}
}

func TestFileUserStore_RefusesBadInput(t *testing.T) {
	ctx := context.Background()
	s := usOpen(t, t.TempDir(), usKey(1))
	long := strings.Repeat("x", MaxUserCredentialBytes+1)
	cases := map[string]struct {
		slot  UserSlot
		value string
	}{
		"empty value":    {usSlot(usAlice), ""},
		"oversize value": {usSlot(usAlice), long},
		"empty user":     {UserSlot{Backend: usBackend, Account: usAccount, Name: usName}, usSecret},
		"empty backend":  {UserSlot{UserID: usAlice, Account: usAccount, Name: usName}, usSecret},
		"empty name":     {UserSlot{UserID: usAlice, Backend: usBackend, Account: usAccount}, usSecret},
		"empty account":  {UserSlot{UserID: usAlice, Backend: usBackend, Name: usName}, usSecret},
		"account spaces": {UserSlot{UserID: usAlice, Backend: usBackend, Account: "two words", Name: usName}, usSecret},
		"long user":      {UserSlot{UserID: strings.Repeat("u", maxUserSlotPartBytes+1), Backend: usBackend, Account: usAccount, Name: usName}, usSecret},
	}
	for name, c := range cases {
		if err := s.PutUser(ctx, c.slot, c.value); err == nil {
			t.Errorf("%s: PutUser succeeded", name)
		}
	}
	if infos, _ := s.ListUser(ctx, usAlice); len(infos) != 0 {
		t.Errorf("refused input left %d entries", len(infos))
	}
}

// TestFileUserStore_DamagedFileIsNotOverwritten pins that a file that does
// not parse stops the store instead of being replaced by the next change.
func TestFileUserStore_DamagedFileIsNotOverwritten(t *testing.T) {
	for name, content := range map[string]string{
		"not json":      "{",
		"other version": `{"version": 99, "entries": []}`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, userFileName), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileUserStore(dir, usKey(1)); err == nil {
			t.Errorf("%s: the store opened", name)
		}
	}
}

func TestParseUserCredentialsKey(t *testing.T) {
	key := usKey(7)
	for name, text := range map[string]string{
		"base64":        base64.StdEncoding.EncodeToString(key),
		"base64 raw":    base64.RawStdEncoding.EncodeToString(key),
		"base64 url":    base64.URLEncoding.EncodeToString(key),
		"hex":           hex.EncodeToString(key),
		"with newlines": "\n" + base64.StdEncoding.EncodeToString(key) + "\n",
	} {
		got, err := ParseUserCredentialsKey(text)
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
	for name, text := range map[string]string{
		"empty":     "",
		"too short": base64.StdEncoding.EncodeToString(key[:16]),
		"too long":  base64.StdEncoding.EncodeToString(append(key, 1)),
		"not a key": "correct horse battery staple",
	} {
		if _, err := ParseUserCredentialsKey(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewFileUserStore(t.TempDir(), key[:16]); err == nil {
		t.Error("NewFileUserStore accepted a 16-byte key")
	}
}

func TestNormalizeAccount(t *testing.T) {
	for in, want := range map[string]string{
		"Alice@Example.com":  "alice@example.com",
		"  work  ":           "work",
		"sales+eu@x.example": "sales+eu@x.example",
		"a":                  "a",
	} {
		if got, ok := NormalizeAccount(in); !ok || got != want {
			t.Errorf("NormalizeAccount(%q) = %q, %v, want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "two words", "@start", "ümlaut", "a/b", "a\nb", strings.Repeat("a", 101)} {
		if _, ok := NormalizeAccount(in); ok {
			t.Errorf("NormalizeAccount(%q) accepted", in)
		}
	}
}
