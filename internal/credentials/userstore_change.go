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
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// UserChange is a set of writes to a UserStore that belong together, such
// as the credentials of one account: values to store and slots to empty.
type UserChange struct {
	// Put holds the values to store, by slot.
	Put map[UserSlot]string
	// Delete lists the slots to empty. A slot that holds nothing stays
	// empty.
	Delete []UserSlot
}

// UserSnapshot is what the slots of a change held before it: each entry as
// it was stored, sealed, or nothing. It carries no readable value. The zero
// value holds no slot.
type UserSnapshot struct {
	// entries holds a copy of the entry of each slot, nil for a slot that
	// was empty.
	entries map[UserSlot]*userFileEntry
}

// seal returns the entry that holds value in slot, sealed under the key the
// store runs on. The caller holds s.mu: ChangeKey replaces that key, and a
// value sealed under the key of a moment ago would be unreadable from then
// on.
func (s *FileUserStore) seal(slot UserSlot, value string) (userFileEntry, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return userFileEntry{}, fmt.Errorf("user credential: %w", err)
	}
	return userFileEntry{
		User:      slot.UserID,
		Backend:   slot.Backend,
		Account:   slot.Account,
		Name:      slot.Name,
		KeyID:     s.keyID,
		Nonce:     nonce,
		Value:     s.aead.Seal(nil, nonce, padValue(value), sealAAD(slot)),
		UpdatedAt: s.now().UTC().Truncate(time.Second),
	}, nil
}

// checkUserValue refuses a value PutUser would refuse.
func checkUserValue(value string) error {
	if value == "" {
		return errors.New("user credential: the value is empty")
	}
	if len(value) > MaxUserCredentialBytes {
		return fmt.Errorf("user credential: the value is longer than %d bytes", MaxUserCredentialBytes)
	}
	return nil
}

// put replaces the entries of the store with those of to, slot by slot: an
// entry, or nil for an empty slot. The caller holds s.mu.
func (s *FileUserStore) put(to map[UserSlot]*userFileEntry) {
	for slot, e := range to {
		if e == nil {
			delete(s.entries, slot)
		} else {
			s.entries[slot] = *e
		}
	}
}

// held returns a copy of what the slots hold now. The caller holds s.mu.
func (s *FileUserStore) held(slots map[UserSlot]*userFileEntry) map[UserSlot]*userFileEntry {
	out := make(map[UserSlot]*userFileEntry, len(slots))
	for slot := range slots {
		if e, ok := s.entries[slot]; ok {
			kept := e
			out[slot] = &kept
		} else {
			out[slot] = nil
		}
	}
	return out
}

// swap writes to into the store and its file and returns what the slots
// held before. When the file cannot be written, memory is put back: it
// follows the file. The caller holds s.mu.
func (s *FileUserStore) swap(to map[UserSlot]*userFileEntry) (map[UserSlot]*userFileEntry, error) {
	before := s.held(to)
	s.put(to)
	if err := s.save(); err != nil {
		s.put(before)
		return nil, err
	}
	return before, nil
}

// ChangeUser implements UserStore. A slot named both under Put and under
// Delete, or a value PutUser would refuse, refuses the whole change.
func (s *FileUserStore) ChangeUser(_ context.Context, change UserChange) (UserSnapshot, error) {
	values := make(map[UserSlot]string, len(change.Put))
	for slot, value := range change.Put {
		slot = slot.canonical()
		if err := checkSlot(slot); err != nil {
			return UserSnapshot{}, err
		}
		if err := checkUserValue(value); err != nil {
			return UserSnapshot{}, err
		}
		if _, twice := values[slot]; twice {
			return UserSnapshot{}, errors.New("user credential: a change stores one slot twice")
		}
		values[slot] = value
	}
	to := make(map[UserSlot]*userFileEntry, len(values)+len(change.Delete))
	for _, slot := range change.Delete {
		slot = slot.canonical()
		if _, stored := values[slot]; stored {
			return UserSnapshot{}, errors.New("user credential: a change stores and removes the same slot")
		}
		to[slot] = nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for slot, value := range values {
		e, err := s.seal(slot, value)
		if err != nil {
			return UserSnapshot{}, err
		}
		to[slot] = &e
	}
	before, err := s.swap(to)
	if err != nil {
		return UserSnapshot{}, err
	}
	return UserSnapshot{entries: before}, nil
}

// RestoreUser implements UserStore. The entries go back as they were
// stored, with the key they were sealed under and the time they were
// stored: one that could not be read before cannot be read after, and is
// not gone either.
func (s *FileUserStore) RestoreUser(_ context.Context, snapshot UserSnapshot) error {
	if len(snapshot.entries) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.swap(snapshot.entries)
	return err
}
