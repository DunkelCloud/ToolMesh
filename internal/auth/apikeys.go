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
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// APIKeyEntry represents an API key from apikeys.yaml.
type APIKeyEntry struct {
	// KeyHash is the bcrypt hash of the key. An entry that has only this is
	// found by comparing a presented key against the hash, which costs a
	// bcrypt computation, until the key has been presented once.
	KeyHash string `yaml:"key_hash"`
	// KeySHA256 is the SHA-256 of the key as 64 hex characters. An entry that
	// has it is found by a table lookup and never compared with bcrypt. It is
	// meant for randomly generated keys only: unlike bcrypt, SHA-256 does not
	// slow down guessing a weak key from a leaked file.
	KeySHA256 string   `yaml:"key_sha256"`
	UserID    string   `yaml:"user_id"`
	CompanyID string   `yaml:"company_id"`
	Plan      string   `yaml:"plan"`
	Roles     []string `yaml:"roles"`
	CallerID  string   `yaml:"caller_id"`
}

// APIKeysConfig is the top-level structure of apikeys.yaml.
type APIKeysConfig struct {
	Keys []APIKeyEntry `yaml:"keys"`
}

// APIKeySummary says how the keys of a loaded apikeys.yaml are found.
type APIKeySummary struct {
	// Indexed counts the entries with a key_sha256.
	Indexed int
	// BcryptOnly counts the entries with only a key_hash.
	BcryptOnly int
	// Unusable names the entries (by user_id) that have neither a key_sha256
	// nor a key_hash bcrypt can work on. No key matches them.
	Unusable []string
}

// indexKey addresses an entry in the in-memory index of an APIKeyStore.
type indexKey [sha256.Size]byte

// APIKeyStore manages API key authentication from apikeys.yaml.
//
// A presented key is found through an index over SHA-256 digests, not by
// comparing it with bcrypt against every entry: the cost of rejecting a value
// that is no key must not grow with the number of keys, or anyone who can
// send a bearer credential decides how much CPU the server spends.
//
// The index holds the entries that carry a key_sha256 from the start. An
// entry with only a bcrypt key_hash cannot be put there when the file is
// loaded, because the hash does not reveal the key. It joins the index the
// first time its key is presented and verified with bcrypt; from then on it
// is found like the others. Until then it is one of the unseen entries, the
// only ones a bcrypt comparison is still spent on.
type APIKeyStore struct {
	keys    []APIKeyEntry
	summary APIKeySummary
	limiter *CompareLimiter

	// compare is bcrypt.CompareHashAndPassword; a field so tests can observe
	// how many comparisons a lookup costs.
	compare func(hashedKey, key []byte) error

	// secret keys the index for this process. Entries are addressed by
	// HMAC(secret, SHA-256(key)) rather than by the plain digest, so that
	// nobody outside can compute where a value lands in the table, and the
	// table does not hold plain digests of keys that were protected by bcrypt
	// on disk.
	secret [sha256.Size]byte

	mu     sync.RWMutex
	index  map[indexKey]int // position in keys
	unseen []int            // positions in keys
}

// NewAPIKeyStore loads API keys from a YAML file. Returns nil if the file
// doesn't exist. limiter bounds the bcrypt comparisons for entries without a
// key_sha256; nil leaves them unbounded.
func NewAPIKeyStore(path string, limiter *CompareLimiter) (*APIKeyStore, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read apikeys config: %w", err)
	}

	var cfg APIKeysConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse apikeys config: %w", err)
	}

	store := &APIKeyStore{
		keys:    cfg.Keys,
		limiter: limiter,
		compare: bcrypt.CompareHashAndPassword,
		index:   make(map[indexKey]int, len(cfg.Keys)),
	}
	if _, err := rand.Read(store.secret[:]); err != nil {
		return nil, fmt.Errorf("prepare apikeys index: %w", err)
	}

	for i := range store.keys {
		entry := &store.keys[i]
		switch digest := strings.ToLower(strings.TrimSpace(entry.KeySHA256)); {
		case digest != "":
			// A key_sha256 that cannot be read stops the server: the entry
			// would silently never match, and the operator who added the
			// field meant it to.
			raw, err := hex.DecodeString(digest)
			if err != nil || len(raw) != sha256.Size {
				return nil, fmt.Errorf("apikeys config: key %d (user_id %q): key_sha256 must be the SHA-256 of the key as %d hex characters", i+1, entry.UserID, 2*sha256.Size)
			}
			at := store.keyed(raw)
			if other, dup := store.index[at]; dup {
				return nil, fmt.Errorf("apikeys config: key %d (user_id %q) has the same key_sha256 as key %d (user_id %q)", i+1, entry.UserID, other+1, store.keys[other].UserID)
			}
			store.index[at] = i
			store.summary.Indexed++
		case usableHash(entry.KeyHash):
			store.unseen = append(store.unseen, i)
			store.summary.BcryptOnly++
		default:
			store.summary.Unusable = append(store.summary.Unusable, entry.UserID)
		}
	}
	return store, nil
}

// Summary reports how the loaded keys are found, as they were at load time.
func (s *APIKeyStore) Summary() APIKeySummary {
	return s.summary
}

// Find returns the entry for key if the index has it. It never runs a bcrypt
// comparison and does no I/O, so its cost does not depend on whether key is a
// key at all. A nil result does not rule out an entry that has not been seen
// yet; that is what Verify is for.
func (s *APIKeyStore) Find(key string) *APIKeyEntry {
	return s.lookup(s.indexKeyOf(key))
}

// Verify compares key with bcrypt against the entries that are not in the
// index yet: those with only a key_hash whose key has not been presented
// since the file was loaded. A match puts the entry into the index, so the
// comparison is not repeated for that key. Once every such entry has been
// seen, Verify compares nothing.
//
// It returns (nil, nil) if no entry matches, and an error if a comparison
// could not be run (see CompareLimiter.Do); in that case key was not checked
// against every entry and the caller must not treat it as rejected.
//
// An entry is bound to the key that first matched it. That changes nothing
// for keys shorter than 72 bytes, which bcrypt matches exactly. bcrypt ignores
// everything beyond 72 bytes, so several longer values can match one hash;
// of those only the first one presented is accepted from then on.
func (s *APIKeyStore) Verify(ctx context.Context, key string) (*APIKeyEntry, error) {
	at := s.indexKeyOf(key)
	unseen := s.unseenEntries()
	for n := 0; ; n++ {
		// The index is asked before every comparison: a concurrent request
		// may have verified the same key in the meantime.
		if entry := s.lookup(at); entry != nil {
			return entry, nil
		}
		if n == len(unseen) {
			return nil, nil
		}
		i := unseen[n]
		var mismatch error
		err := s.limiter.Do(ctx, func() {
			mismatch = s.compare([]byte(s.keys[i].KeyHash), []byte(key))
		})
		if err != nil {
			return nil, err
		}
		if mismatch == nil {
			return s.remember(i, at), nil
		}
	}
}

func (s *APIKeyStore) lookup(at indexKey) *APIKeyEntry {
	s.mu.RLock()
	i, ok := s.index[at]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	return &s.keys[i]
}

func (s *APIKeyStore) unseenEntries() []int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return slices.Clone(s.unseen)
}

// remember puts the entry at position i into the index under at and returns
// it. If another key was remembered for the entry in the meantime, that one
// stays and the result is nil.
func (s *APIKeyStore) remember(i int, at indexKey) *APIKeyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	if known, ok := s.index[at]; ok {
		return &s.keys[known]
	}
	pos := slices.Index(s.unseen, i)
	if pos < 0 {
		return nil
	}
	s.unseen = slices.Delete(s.unseen, pos, pos+1)
	s.index[at] = i
	return &s.keys[i]
}

func (s *APIKeyStore) indexKeyOf(key string) indexKey {
	digest := sha256.Sum256([]byte(key))
	return s.keyed(digest[:])
}

func (s *APIKeyStore) keyed(digest []byte) indexKey {
	mac := hmac.New(sha256.New, s.secret[:])
	mac.Write(digest)
	var at indexKey
	mac.Sum(at[:0])
	return at
}
