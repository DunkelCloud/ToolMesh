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

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const (
	keyNextEnv    = "TOOLMESH_USER_CREDENTIALS_KEY_NEXT" //nolint:gosec // the variable's name, not a credential
	keyChangeUser = "alice"
	keyChangeVal  = "what-alice-stored" //nolint:gosec // test fixture, not a credential
)

// keyChangeKey is a key of the store in the two forms the setting takes.
func keyChangeKey(fill byte, asHex bool) string {
	raw := bytes.Repeat([]byte{fill}, credentials.UserCredentialsKeyBytes)
	if asHex {
		return hex.EncodeToString(raw)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

var keyChangeSlot = credentials.UserSlot{UserID: keyChangeUser, Backend: "mail", Account: "alice@example.com", Name: "MAIL_LOGIN"}

// keyChangeStart is one start of ToolMesh as far as the user credential
// store goes: the settings as given, the data directory dir.
func keyChangeStart(t *testing.T, dir, key, next string) (*userCredentialSetup, string, error) {
	t.Helper()
	t.Setenv(testUserKeyEnv, key)
	t.Setenv(keyNextEnv, next)
	t.Setenv("TOOLMESH_DATA_DIR", dir)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	setup, err := newUserCredentialSetup(cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err == nil && (cfg.UserCredentialsKey != "" || cfg.UserCredentialsKeyNext != "") {
		t.Error("the keys are still in the configuration after the store was opened")
	}
	for _, name := range []string{testUserKeyEnv, keyNextEnv} {
		if v, set := os.LookupEnv(name); set && err == nil && (key != "" || next != "") {
			t.Errorf("%s is still in the environment (%d bytes) after the store was opened", name, len(v))
		}
	}
	return setup, logs.String(), err
}

// TestNewUserCredentialSetup_ChangeOfKey walks through a change of the key
// as an operator makes it, start by start: the key in use alone, then with
// the next key next to it, the same once more, and at last the next key as
// the key in use. No user stores anything again on the way.
func TestNewUserCredentialSetup_ChangeOfKey(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := keyChangeKey(1, false), keyChangeKey(2, true)
	read := func(setup *userCredentialSetup) (string, error) {
		return setup.store.GetUser(ctx, keyChangeSlot)
	}

	// Before the change.
	setup, logs, err := keyChangeStart(t, dir, oldKey, "")
	if err != nil || setup == nil {
		t.Fatalf("start with the key in use: %v, %v", setup, err)
	}
	if strings.Contains(logs, "change of key") {
		t.Errorf("a start without a next key speaks of a change:\n%s", logs)
	}
	if err := setup.store.PutUser(ctx, keyChangeSlot, keyChangeVal); err != nil {
		t.Fatal(err)
	}

	// The change: both keys.
	setup, logs, err = keyChangeStart(t, dir, oldKey, nextKey)
	if err != nil || setup == nil {
		t.Fatalf("start with both keys: %v, %v", setup, err)
	}
	if got, err := read(setup); err != nil || got != keyChangeVal {
		t.Errorf("after the change: %q, %v", got, err)
	}
	if !strings.Contains(logs, "change of key") || !strings.Contains(logs, "resealed=1") || !strings.Contains(logs, "underNextKey=0") {
		t.Errorf("the log does not say what the change did:\n%s", logs)
	}
	if !strings.Contains(logs, "To finish, make that key "+userCredentialsKeyEnv+" and remove "+keyNextEnv) {
		t.Errorf("the log does not say how to finish the change:\n%s", logs)
	}
	if strings.Contains(logs, "wrong way round") {
		t.Errorf("a change that sealed values again is suspected of swapped settings:\n%s", logs)
	}
	if strings.Contains(logs, oldKey) || strings.Contains(logs, nextKey) {
		t.Errorf("a key is in the log:\n%s", logs)
	}
	want := bytes.Repeat([]byte{2}, credentials.UserCredentialsKeyBytes)
	if !bytes.Equal(setup.key, want) {
		t.Error("the page's keys are not derived from the next key after the change")
	}

	// The operator has not finished yet: another start with both keys.
	setup, logs, err = keyChangeStart(t, dir, oldKey, nextKey)
	if err != nil || setup == nil {
		t.Fatalf("second start with both keys: %v, %v", setup, err)
	}
	if got, err := read(setup); err != nil || got != keyChangeVal {
		t.Errorf("second start with both keys: %q, %v", got, err)
	}
	if !strings.Contains(logs, "resealed=0") || !strings.Contains(logs, "underNextKey=1") {
		t.Errorf("the log of the second start:\n%s", logs)
	}
	if strings.Contains(logs, "level=WARN") {
		t.Errorf("a start with nothing left to change warns:\n%s", logs)
	}

	// Finished: the next key is the key in use.
	setup, logs, err = keyChangeStart(t, dir, nextKey, "")
	if err != nil || setup == nil {
		t.Fatalf("start with the next key as the key in use: %v, %v", setup, err)
	}
	if got, err := read(setup); err != nil || got != keyChangeVal {
		t.Errorf("after the change is finished: %q, %v", got, err)
	}
	if strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "keyId=") {
		t.Errorf("the log of the start after the change was finished:\n%s", logs)
	}

	// The old key alone opens nothing any more, and the start says so: an
	// operator who finished the change the wrong way learns it here, while
	// the other key still exists.
	setup, logs, err = keyChangeStart(t, dir, oldKey, "")
	if err != nil || setup == nil {
		t.Fatalf("start with the old key: %v, %v", setup, err)
	}
	if _, err := read(setup); !errors.Is(err, credentials.ErrUserCredentialUnreadable) {
		t.Errorf("with the old key after the change: %v, want unreadable", err)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "stored values do not open under "+userCredentialsKeyEnv) ||
		!strings.Contains(logs, "values=1") || !strings.Contains(logs, "ofValues=1") || !strings.Contains(logs, "sealedUnderKeyIds=") {
		t.Errorf("a start whose key opens nothing of what is stored does not say so:\n%s", logs)
	}
}

// TestNewUserCredentialSetup_ChangeOfKey_SettingsTheWrongWayRound pins what
// an operator sees who put the new key into the setting of the key in use
// and the old one into the other: nothing is sealed again, the instance
// keeps running on the old key, and the log says what that means before the
// old key is thrown away.
func TestNewUserCredentialSetup_ChangeOfKey_SettingsTheWrongWayRound(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, newKey := keyChangeKey(1, false), keyChangeKey(2, false)
	setup, _, err := keyChangeStart(t, dir, oldKey, "")
	if err != nil || setup == nil {
		t.Fatalf("start: %v, %v", setup, err)
	}
	if err := setup.store.PutUser(ctx, keyChangeSlot, keyChangeVal); err != nil {
		t.Fatal(err)
	}

	setup, logs, err := keyChangeStart(t, dir, newKey, oldKey)
	if err != nil || setup == nil {
		t.Fatalf("start with the settings the wrong way round: %v, %v", setup, err)
	}
	if got, err := setup.store.GetUser(ctx, keyChangeSlot); err != nil || got != keyChangeVal {
		t.Errorf("the stored value: %q, %v, want it readable", got, err)
	}
	if !strings.Contains(logs, "resealed=0") || !strings.Contains(logs, "underNextKey=1") || !strings.Contains(logs, "wrong way round") {
		t.Errorf("the log does not say that nothing was sealed again and what that can mean:\n%s", logs)
	}
	// Finishing as intended then shows at once: the new key opens nothing.
	_, logs, err = keyChangeStart(t, dir, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs, "stored values do not open under "+userCredentialsKeyEnv) {
		t.Errorf("the start after the botched change does not warn:\n%s", logs)
	}
	// And the value is not lost: the right way round still works.
	setup, logs, err = keyChangeStart(t, dir, oldKey, newKey)
	if err != nil || setup == nil {
		t.Fatalf("start with the settings the right way round: %v, %v", setup, err)
	}
	if got, err := setup.store.GetUser(ctx, keyChangeSlot); err != nil || got != keyChangeVal || !strings.Contains(logs, "resealed=1") {
		t.Errorf("the change the right way round: %q, %v\n%s", got, err, logs)
	}
}

// TestNewUserCredentialSetup_ChangeOfKey_EmptyStore pins a change of key on
// an instance where nobody has stored anything yet: no file appears, and
// what is stored from then on is under the next key.
func TestNewUserCredentialSetup_ChangeOfKey_EmptyStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := keyChangeKey(1, false), keyChangeKey(2, false)
	setup, logs, err := keyChangeStart(t, dir, oldKey, nextKey)
	if err != nil || setup == nil {
		t.Fatalf("start: %v, %v", setup, err)
	}
	if !strings.Contains(logs, "resealed=0") || !strings.Contains(logs, "underNextKey=0") || strings.Contains(logs, "level=WARN") || strings.Contains(logs, "wrong way round") {
		t.Errorf("the log of a change on an empty store:\n%s", logs)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("a change on an empty store left files behind: %v, %v", entries, err)
	}
	if err := setup.store.PutUser(ctx, keyChangeSlot, keyChangeVal); err != nil {
		t.Fatal(err)
	}
	setup, _, err = keyChangeStart(t, dir, nextKey, "")
	if err != nil || setup == nil {
		t.Fatalf("start with the next key: %v, %v", setup, err)
	}
	if got, err := setup.store.GetUser(ctx, keyChangeSlot); err != nil || got != keyChangeVal {
		t.Errorf("a value stored during the change, read with the next key: %q, %v", got, err)
	}
}

// TestNewUserCredentialSetup_ChangeOfKey_Unreadable pins that values which
// neither key opens are counted in a warning, with the ids of the keys they
// were sealed under: their users have to store them again, and nobody else
// can tell.
func TestNewUserCredentialSetup_ChangeOfKey_Unreadable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	setup, _, err := keyChangeStart(t, dir, keyChangeKey(3, false), "")
	if err != nil || setup == nil {
		t.Fatalf("start: %v, %v", setup, err)
	}
	if err := setup.store.PutUser(ctx, keyChangeSlot, keyChangeVal); err != nil {
		t.Fatal(err)
	}
	setup, logs, err := keyChangeStart(t, dir, keyChangeKey(1, false), keyChangeKey(2, false))
	if err != nil || setup == nil {
		t.Fatalf("start with two keys that do not open the value: %v, %v", setup, err)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "open under neither") || !strings.Contains(logs, "values=1") || !strings.Contains(logs, "sealedUnderKeyIds=") {
		t.Errorf("no warning about the value neither key opens:\n%s", logs)
	}
	if _, err := setup.store.GetUser(ctx, keyChangeSlot); !errors.Is(err, credentials.ErrUserCredentialUnreadable) {
		t.Errorf("the value neither key opens: %v, want unreadable", err)
	}
}

// TestNewUserCredentialSetup_KeysThatDoNotFit pins the settings ToolMesh
// does not start with: each of them would otherwise leave the operator
// believing in a change that does not happen.
func TestNewUserCredentialSetup_KeysThatDoNotFit(t *testing.T) {
	good, other := keyChangeKey(1, false), keyChangeKey(2, false)
	cases := []struct {
		name      string
		key, next string
		wantErr   string
	}{
		{"the next key without the key in use", "", other, keyNextEnv + " is set without " + userCredentialsKeyEnv},
		{"the next key is the key in use", good, good, "same key"},
		{"the same key written in another form", keyChangeKey(1, false), keyChangeKey(1, true), "same key"},
		{"a next key that is no key", good, "not-a-key", keyNextEnv},
		{"a next key of the wrong length", good, base64.StdEncoding.EncodeToString([]byte("short")), keyNextEnv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setup, _, err := keyChangeStart(t, t.TempDir(), tc.key, tc.next)
			if err == nil || setup != nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("setup = %v, err = %v; want an error that names %q", setup, err, tc.wantErr)
			}
			if strings.Contains(err.Error(), good) || strings.Contains(err.Error(), other) {
				t.Errorf("the error carries a key: %v", err)
			}
		})
	}
	// Neither key: the store is off, which is no error.
	if setup, _, err := keyChangeStart(t, t.TempDir(), "", ""); err != nil || setup != nil {
		t.Errorf("without keys: %v, %v, want no store and no error", setup, err)
	}
}
