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
	"fmt"
	"reflect"
	"sync"
	"testing"
)

// TestFileUserStore_KeyState pins what a start reports about the key the
// store runs on: how many stored values it opens, how many it does not, and
// under which keys those were sealed.
func TestFileUserStore_KeyState(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	keyA, keyB, keyC := usKey(1), usKey(2), usKey(3)
	slot := func(account string) UserSlot {
		return UserSlot{UserID: usAlice, Backend: usBackend, Account: account, Name: usName}
	}

	if got := usOpen(t, dir, keyA).KeyState(); !reflect.DeepEqual(got, KeyState{KeyID: userKeyID(keyA)}) {
		t.Errorf("empty store: %+v", got)
	}
	for account, key := range map[string][]byte{"a1@example.com": keyA, "a2@example.com": keyA, "b@example.com": keyB, "c@example.com": keyC} {
		if err := usOpen(t, dir, key).PutUser(ctx, slot(account), usSecret); err != nil {
			t.Fatal(err)
		}
	}

	got := usOpen(t, dir, keyA).KeyState()
	otherIDs := []string{userKeyID(keyB), userKeyID(keyC)}
	if otherIDs[0] > otherIDs[1] {
		otherIDs[0], otherIDs[1] = otherIDs[1], otherIDs[0]
	}
	want := KeyState{KeyID: userKeyID(keyA), Readable: 2, Unreadable: 2, OtherKeyIDs: otherIDs}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KeyState = %+v, want %+v", got, want)
	}

	// A damaged value under the store's own key counts as unreadable, and
	// the store's own id among the others says that it is damage.
	usRewrite(t, dir, func(f *userFile) {
		for i := range f.Entries {
			if f.Entries[i].Account == "a1@example.com" {
				f.Entries[i].Value[0] ^= 1
			}
		}
	})
	got = usOpen(t, dir, keyA).KeyState()
	if got.Readable != 1 || got.Unreadable != 3 || len(got.OtherKeyIDs) != 3 {
		t.Errorf("with a damaged value: %+v", got)
	}

	// After a change of key the state is that of the next key.
	s := usOpen(t, dir, keyC)
	if _, err := s.ChangeKey(keyB); err != nil {
		t.Fatal(err)
	}
	if got := s.KeyState(); got.KeyID != userKeyID(keyB) || got.Readable != 2 || got.Unreadable != 2 {
		t.Errorf("after a change from the third key to the second: %+v", got)
	}
}

// TestFileUserStore_ChangeKey_WhileInUse pins that the store may be in use
// while its key changes: a value stored during the change is sealed under
// whichever key the store runs on at that moment and is readable afterwards.
// Sealed under the key of a moment ago it would be unreadable, and lost once
// the old key is retired.
func TestFileUserStore_ChangeKey_WhileInUse(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	oldKey, nextKey := usKey(1), usKey(2)
	s := usOpen(t, dir, oldKey)
	const writers, perWriter = 8, 12
	slot := func(w, i int) UserSlot {
		return UserSlot{UserID: usAlice, Backend: usBackend, Account: fmt.Sprintf("w%d-%d@example.com", w, i), Name: usName}
	}
	for w := range writers {
		if err := s.PutUser(ctx, slot(w, 0), usSecret); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make(chan error, writers*perWriter+writers)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 1; i < perWriter; i++ {
				if err := s.PutUser(ctx, slot(w, i), usSecret); err != nil {
					errs <- fmt.Errorf("store %d/%d: %w", w, i, err)
				}
				if got, err := s.GetUser(ctx, slot(w, 0)); err != nil || got != usSecret {
					errs <- fmt.Errorf("read %d/0 during the change: %q, %w", w, got, err)
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := s.ChangeKey(nextKey); err != nil {
			errs <- fmt.Errorf("change: %w", err)
		}
	}()
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// Everything stored, before and during the change, opens under the next
	// key: in the store that made the change and in one opened afterwards.
	for _, store := range []*FileUserStore{s, usOpen(t, dir, nextKey)} {
		state := store.KeyState()
		if state.KeyID != userKeyID(nextKey) || state.Unreadable != 0 || state.Readable != writers*perWriter {
			t.Errorf("after the change: %+v, want %d values, all under the next key", state, writers*perWriter)
		}
	}
}
