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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestPadValue_RoundTrip(t *testing.T) {
	for _, n := range []int{1, 2, userValueBlock - 5, userValueBlock - 4, userValueBlock - 3, 2*userValueBlock - 4, 2*userValueBlock - 3, MaxUserCredentialBytes} {
		value := strings.Repeat("x", n)
		padded := padValue(value)
		if len(padded)%userValueBlock != 0 || len(padded) < n+4 || len(padded) >= n+4+userValueBlock {
			t.Errorf("value of %d bytes padded to %d: want the next multiple of %d that holds the value and its length", n, len(padded), userValueBlock)
		}
		got, ok := unpadValue(padded)
		if !ok || got != value {
			t.Errorf("value of %d bytes did not come back: ok %v, %d bytes", n, ok, len(got))
		}
	}
}

// TestUnpadValue_RefusesOtherForms pins that only what padValue writes
// reads as a value. Anything else is damage or an entry in another form,
// and must not come back as a credential.
func TestUnpadValue_RefusesOtherForms(t *testing.T) {
	framed := func(length uint32, total int, fill byte) []byte {
		b := bytes.Repeat([]byte{fill}, total)
		binary.BigEndian.PutUint32(b, length)
		return b
	}
	extraBlock := append(padValue("value"), make([]byte, userValueBlock)...)
	dirty := padValue("value")
	dirty[len(dirty)-1] = 1
	cases := map[string][]byte{
		"nothing":                       nil,
		"shorter than a block":          padValue("value")[:userValueBlock-1],
		"not a multiple of the block":   append(padValue("value"), 0),
		"a value without the frame":     []byte("Basic " + strings.Repeat("QUJD", (userValueBlock-6)/4) + "=="),
		"length zero":                   framed(0, userValueBlock, 0),
		"length beyond the room":        framed(userValueBlock, userValueBlock, 0),
		"more padding than a block":     extraBlock,
		"padding that is not zero":      dirty,
		"length field of a large value": framed(1<<31, userValueBlock, 0),
	}
	for name, padded := range cases {
		if got, ok := unpadValue(padded); ok {
			t.Errorf("%s: read as a value of %d bytes", name, len(got))
		}
	}
}

// TestFileUserStore_SealedLengthDoesNotFollowTheValue pins what the padding
// is for: the file must not tell a short password from a long one.
func TestFileUserStore_SealedLengthDoesNotFollowTheValue(t *testing.T) {
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))
	ctx := context.Background()
	values := map[string]string{
		usAlice: "short",
		usBob:   strings.Repeat("a long passphrase ", 12), // 216 bytes
	}
	for user, v := range values {
		if err := s.PutUser(ctx, usSlot(user), v); err != nil {
			t.Fatal(err)
		}
	}
	sealed := map[string]int{}
	usRewrite(t, dir, func(f *userFile) {
		for _, e := range f.Entries {
			sealed[e.User] = len(e.Value)
		}
	})
	if len(sealed) != 2 || sealed[usAlice] != sealed[usBob] {
		t.Errorf("sealed lengths = %v, want the same for a value of %d and one of %d bytes", sealed, len(values[usAlice]), len(values[usBob]))
	}
	for user, v := range values {
		if got, err := usOpen(t, dir, usKey(1)).GetUser(ctx, usSlot(user)); err != nil || got != v {
			t.Errorf("%s: read back %d bytes, %v", user, len(got), err)
		}
	}
}

// TestFileUserStore_UnframedEntryIsUnreadable pins that an entry sealed
// under the right key and slot but without the frame, which is not what
// this store writes, reads as unreadable and not as a credential.
func TestFileUserStore_UnframedEntryIsUnreadable(t *testing.T) {
	dir := t.TempDir()
	s := usOpen(t, dir, usKey(1))
	ctx := context.Background()
	slot := usSlot(usAlice)
	if err := s.PutUser(ctx, slot, usSecret); err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	unframed := s.aead.Seal(nil, nonce, []byte(usSecret), sealAAD(slot.canonical()))
	usRewrite(t, dir, func(f *userFile) {
		f.Entries[0].Nonce, f.Entries[0].Value = nonce, unframed
	})
	reopened := usOpen(t, dir, usKey(1))
	_, err := reopened.GetUser(ctx, slot)
	if !errors.Is(err, ErrUserCredentialUnreadable) {
		t.Errorf("GetUser of an unframed entry = %v, want it unreadable", err)
	}
	// The list says the same as a read: a page that shows the account as
	// stored while every call fails on it would send the user nowhere.
	infos, err := reopened.ListUser(ctx, usAlice)
	if err != nil || len(infos) != 1 || infos[0].Readable {
		t.Errorf("ListUser of an unframed entry = %+v, %v, want one entry that is not readable", infos, err)
	}
}

// TestFileUserStore_ListTellsWhatAReadWouldFind pins that the list reports
// an entry as readable only when a read of it succeeds: an entry whose
// sealed value was changed, or that was moved to another account in the
// file, opens no more than one sealed under another key.
func TestFileUserStore_ListTellsWhatAReadWouldFind(t *testing.T) {
	ctx := context.Background()
	readable := func(dir string) bool {
		t.Helper()
		infos, err := usOpen(t, dir, usKey(1)).ListUser(ctx, usAlice)
		if err != nil || len(infos) != 1 {
			t.Fatalf("ListUser = %+v, %v", infos, err)
		}
		return infos[0].Readable
	}
	stored := func() string {
		t.Helper()
		dir := t.TempDir()
		if err := usOpen(t, dir, usKey(1)).PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	if dir := stored(); !readable(dir) {
		t.Error("an untouched entry lists as unreadable")
	}
	dir := stored()
	usRewrite(t, dir, func(f *userFile) { f.Entries[0].Value[0] ^= 1 })
	if readable(dir) {
		t.Error("an entry with a changed value lists as readable")
	}
	dir = stored()
	usRewrite(t, dir, func(f *userFile) { f.Entries[0].Account = "someone-else@example.com" })
	if readable(dir) {
		t.Error("an entry moved to another account lists as readable")
	}
}
