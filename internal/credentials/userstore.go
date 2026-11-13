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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// UserSlot names one credential of one user: whose it is, the backends.yaml
// entry it is for, which of the user's accounts at that backend it belongs
// to, and its logical name. A user can hold several accounts at one
// backend, several mailboxes for instance, each under a label of their
// choice.
type UserSlot struct {
	UserID  string
	Backend string
	Account string
	Name    string
}

// canonical returns the slot as the store keys it: the credential name in
// the form of its environment variable, the account label lower-cased,
// user and backend as given.
func (s UserSlot) canonical() UserSlot {
	s.Name = userCredentialKey(s.Name)
	if a, ok := NormalizeAccount(s.Account); ok {
		s.Account = a
	}
	return s
}

// accountRe is the form of an account label: what a mail address or a
// short name is made of, without spaces.
var accountRe = regexp.MustCompile(`^[a-z0-9][a-z0-9@._+-]{0,99}$`)

// NormalizeAccount returns the label of a user's account in the form it is
// stored and compared in, trimmed and lower-cased, and whether it is a
// label at all: 1 to 100 letters, digits and @ . _ + -, starting with a
// letter or digit. Labels are names the user picks, such as a mail address;
// they are not secret and appear in tool calls, logs and the audit trail.
func NormalizeAccount(label string) (string, bool) {
	label = strings.ToLower(strings.TrimSpace(label))
	return label, accountRe.MatchString(label)
}

// userCredentialKey is the form a credential name takes as a key: trimmed
// and upper-cased, as in CREDENTIAL_<NAME>.
func userCredentialKey(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

// UserCredentialInfo describes a stored credential of a user without its
// value.
type UserCredentialInfo struct {
	Backend   string
	Account   string
	Name      string
	UpdatedAt time.Time
	// Readable is false when the entry was written under another key than
	// the store runs with now: it is kept but cannot be used.
	Readable bool
}

// UserStore holds the credentials users deposit for themselves, one per
// user, backend, account and name. Unlike a CredentialStore it is written at run
// time. It never returns a value in a listing.
type UserStore interface {
	// GetUser returns the credential in slot. It returns an error that
	// wraps ErrCredentialNotFound when the user has none, and
	// ErrUserCredentialUnreadable when one is stored that the store cannot
	// decrypt.
	GetUser(ctx context.Context, slot UserSlot) (string, error)
	// PutUser stores value in slot, replacing what was there.
	PutUser(ctx context.Context, slot UserSlot, value string) error
	// DeleteUser removes the credential in slot and reports whether there
	// was one.
	DeleteUser(ctx context.Context, slot UserSlot) (bool, error)
	// ListUser lists what is stored for userID, sorted by backend, account
	// and name.
	ListUser(ctx context.Context, userID string) ([]UserCredentialInfo, error)
}

// ErrUserCredentialUnreadable is returned for a stored user credential that
// cannot be decrypted: the key changed, or the entry was altered.
var ErrUserCredentialUnreadable = errors.New("stored user credential cannot be decrypted")

// Limits of what a user can store.
const (
	// MaxUserCredentialBytes bounds one credential value.
	MaxUserCredentialBytes = 16 << 10
	// maxUserSlotPartBytes bounds user id, backend and name of a slot.
	maxUserSlotPartBytes = 256
)

// UserCredentialsKeyBytes is the length of the key user credentials are
// encrypted with.
const UserCredentialsKeyBytes = 32

// ParseUserCredentialsKey decodes the key user credentials are encrypted
// with: 32 random bytes, written as base64 (standard or URL alphabet, with
// or without padding) or as 64 hex digits.
func ParseUserCredentialsKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("the key is empty")
	}
	if len(s) == 2*UserCredentialsKeyBytes {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			if len(b) != UserCredentialsKeyBytes {
				return nil, fmt.Errorf("the key decodes to %d bytes, need %d (for example: openssl rand -base64 32)", len(b), UserCredentialsKeyBytes)
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("the key is neither base64 nor %d hex digits (for example: openssl rand -base64 32)", 2*UserCredentialsKeyBytes)
}

// userFileVersion is the format of the file a FileUserStore writes.
const userFileVersion = 1

// userFileName is the file of a FileUserStore in its data directory.
const userFileName = "user-credentials.json"

// userFile is the file of a FileUserStore.
type userFile struct {
	Version int             `json:"version"`
	Entries []userFileEntry `json:"entries"`
}

// userFileEntry is one stored credential. Everything but the value is in
// the clear, so the file can be inspected and, while ToolMesh is stopped,
// an entry removed by hand.
type userFileEntry struct {
	User      string    `json:"user"`
	Backend   string    `json:"backend"`
	Account   string    `json:"account"`
	Name      string    `json:"name"`
	KeyID     string    `json:"key_id"`
	Nonce     []byte    `json:"nonce"`
	Value     []byte    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FileUserStore is a UserStore on one JSON file in the data directory. Each
// value is sealed with AES-256-GCM under the operator's key; user, backend,
// account and name are bound into the seal, so an entry copied to another
// user, backend, account or name does not open. The file is rewritten atomically on every
// change and held in memory in between. It is the store of one process: two
// instances do not share it.
type FileUserStore struct {
	path  string
	aead  cipher.AEAD
	keyID string
	now   func() time.Time

	mu      sync.RWMutex
	entries map[UserSlot]userFileEntry
}

// NewFileUserStore opens the store in dataDir, creating the directory when
// needed, and loads what is there. key is the 32-byte encryption key (see
// ParseUserCredentialsKey).
func NewFileUserStore(dataDir string, key []byte) (*FileUserStore, error) {
	if len(key) != UserCredentialsKeyBytes {
		return nil, fmt.Errorf("user credentials key has %d bytes, need %d", len(key), UserCredentialsKeyBytes)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("user credentials key: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("user credentials key: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	s := &FileUserStore{
		path:    filepath.Join(dataDir, userFileName),
		aead:    aead,
		keyID:   userKeyID(key),
		now:     time.Now,
		entries: map[UserSlot]userFileEntry{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// userKeyID names a key without revealing it: the first bytes of a hash of
// the key under a label of its own.
func userKeyID(key []byte) string {
	h := sha256.New()
	h.Write([]byte("toolmesh user credentials key id\x00"))
	h.Write(key)
	return hex.EncodeToString(h.Sum(nil)[:4])
}

// load reads the file. A missing file is an empty store; a file that does
// not parse or has another version is an error, so that a damaged file is
// not overwritten by the next change.
func (s *FileUserStore) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	var f userFile
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse %s: %w", s.path, err)
	}
	if f.Version != userFileVersion {
		return fmt.Errorf("%s has format version %d, this ToolMesh reads version %d", s.path, f.Version, userFileVersion)
	}
	for _, e := range f.Entries {
		slot := UserSlot{UserID: e.User, Backend: e.Backend, Account: e.Account, Name: e.Name}
		// Two entries for one slot do not come from this store: which of
		// them is meant cannot be told, so the file is not used at all.
		if _, twice := s.entries[slot]; twice {
			return fmt.Errorf("%s holds two entries for the credential %q of account %q of user %q at backend %q", s.path, e.Name, e.Account, e.User, e.Backend)
		}
		s.entries[slot] = e
	}
	return nil
}

// readable reports whether the store can open the entry: it was sealed
// under the store's key and has a nonce of the right length. A nonce of
// another length would make the cipher panic instead of failing.
func (s *FileUserStore) readable(e userFileEntry) bool {
	return e.KeyID == s.keyID && len(e.Nonce) == s.aead.NonceSize()
}

// Users returns the ids of the users who have something stored, sorted.
func (s *FileUserStore) Users() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]bool{}
	var out []string
	for slot := range s.entries {
		if !seen[slot.UserID] {
			seen[slot.UserID] = true
			out = append(out, slot.UserID)
		}
	}
	sort.Strings(out)
	return out
}

// save writes the entries to a temporary file next to the store's file and
// renames it into place. The caller holds s.mu.
func (s *FileUserStore) save() error {
	f := userFile{Version: userFileVersion, Entries: make([]userFileEntry, 0, len(s.entries))}
	for _, e := range s.entries {
		f.Entries = append(f.Entries, e)
	}
	sort.Slice(f.Entries, func(i, j int) bool {
		a, b := f.Entries[i], f.Entries[j]
		if a.User != b.User {
			return a.User < b.User
		}
		if a.Backend != b.Backend {
			return a.Backend < b.Backend
		}
		if a.Account != b.Account {
			return a.Account < b.Account
		}
		return a.Name < b.Name
	})
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("encode user credentials: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), userFileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("write user credentials: %w", err)
	}
	// CreateTemp makes the file readable and writable by its owner only.
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write user credentials: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("write user credentials: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("write user credentials: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		cleanup()
		return fmt.Errorf("write user credentials: %w", err)
	}
	return nil
}

// checkSlot refuses a slot with an empty or oversized part or an account
// that is no label.
func checkSlot(slot UserSlot) error {
	for _, p := range []struct{ what, v string }{{"user id", slot.UserID}, {"backend name", slot.Backend}, {"credential name", slot.Name}} {
		if p.v == "" {
			return fmt.Errorf("user credential: %s is empty", p.what)
		}
		if len(p.v) > maxUserSlotPartBytes {
			return fmt.Errorf("user credential: %s is longer than %d bytes", p.what, maxUserSlotPartBytes)
		}
		// The file is JSON, which cannot hold other text: two slots that
		// differ in an invalid byte would read back as one.
		if !utf8.ValidString(p.v) {
			return fmt.Errorf("user credential: %s is not valid UTF-8", p.what)
		}
	}
	if _, ok := NormalizeAccount(slot.Account); !ok {
		return errors.New("user credential: the account label must be 1 to 100 letters, digits and @ . _ + -, starting with a letter or digit")
	}
	// A credential name is what a DADL can name: anything else, an invalid
	// byte included, would be folded into another name by the upper-casing
	// of the key.
	if !slotNameRe.MatchString(slot.Name) {
		return errors.New("user credential: the credential name must be letters, digits and _ only")
	}
	return nil
}

// slotNameRe is the form of a credential name as a key.
var slotNameRe = regexp.MustCompile(`^[A-Z0-9_]+$`)

// sealAAD is what a value is bound to besides the key: the format version
// and the slot, each part with its length so that parts cannot run into
// each other.
func sealAAD(slot UserSlot) []byte {
	aad := []byte{userFileVersion}
	for _, p := range []string{slot.UserID, slot.Backend, slot.Account, slot.Name} {
		aad = binary.BigEndian.AppendUint32(aad, uint32(len(p))) //nolint:gosec // bounded by maxUserSlotPartBytes
		aad = append(aad, p...)
	}
	return aad
}

// GetUser implements UserStore.
func (s *FileUserStore) GetUser(_ context.Context, slot UserSlot) (string, error) {
	slot = slot.canonical()
	s.mu.RLock()
	e, ok := s.entries[slot]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("user credential %q of account %q at backend %q: %w", slot.Name, slot.Account, slot.Backend, ErrCredentialNotFound)
	}
	if !s.readable(e) {
		return "", fmt.Errorf("user credential %q of account %q at backend %q was stored under another key or is damaged: %w", slot.Name, slot.Account, slot.Backend, ErrUserCredentialUnreadable)
	}
	plain, err := s.aead.Open(nil, e.Nonce, e.Value, sealAAD(slot))
	if err != nil {
		return "", fmt.Errorf("user credential %q of account %q at backend %q: %w", slot.Name, slot.Account, slot.Backend, ErrUserCredentialUnreadable)
	}
	return string(plain), nil
}

// PutUser implements UserStore.
func (s *FileUserStore) PutUser(_ context.Context, slot UserSlot, value string) error {
	slot = slot.canonical()
	if err := checkSlot(slot); err != nil {
		return err
	}
	if value == "" {
		return errors.New("user credential: the value is empty")
	}
	if len(value) > MaxUserCredentialBytes {
		return fmt.Errorf("user credential: the value is longer than %d bytes", MaxUserCredentialBytes)
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("user credential: %w", err)
	}
	e := userFileEntry{
		User:      slot.UserID,
		Backend:   slot.Backend,
		Account:   slot.Account,
		Name:      slot.Name,
		KeyID:     s.keyID,
		Nonce:     nonce,
		Value:     s.aead.Seal(nil, nonce, []byte(value), sealAAD(slot)),
		UpdatedAt: s.now().UTC().Truncate(time.Second),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.entries[slot]
	s.entries[slot] = e
	if err := s.save(); err != nil {
		// Memory follows the file: a value that is not on disk would be
		// gone after a restart without anybody having removed it.
		if had {
			s.entries[slot] = prev
		} else {
			delete(s.entries, slot)
		}
		return err
	}
	return nil
}

// DeleteUser implements UserStore.
func (s *FileUserStore) DeleteUser(_ context.Context, slot UserSlot) (bool, error) {
	slot = slot.canonical()
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.entries[slot]
	if !had {
		return false, nil
	}
	delete(s.entries, slot)
	if err := s.save(); err != nil {
		s.entries[slot] = prev
		return false, err
	}
	return true, nil
}

// ListUser implements UserStore.
func (s *FileUserStore) ListUser(_ context.Context, userID string) ([]UserCredentialInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []UserCredentialInfo
	for slot, e := range s.entries {
		if slot.UserID != userID {
			continue
		}
		out = append(out, UserCredentialInfo{
			Backend:   slot.Backend,
			Account:   slot.Account,
			Name:      slot.Name,
			UpdatedAt: e.UpdatedAt,
			Readable:  s.readable(e),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Backend != out[j].Backend {
			return out[i].Backend < out[j].Backend
		}
		if out[i].Account != out[j].Account {
			return out[i].Account < out[j].Account
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}
