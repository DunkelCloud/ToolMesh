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
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"sort"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// UserEntry represents a user from users.yaml.
type UserEntry struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Company      string   `yaml:"company"`
	Plan         string   `yaml:"plan"`
	Roles        []string `yaml:"roles"`
}

// UsersConfig is the top-level structure of users.yaml.
type UsersConfig struct {
	Users []UserEntry `yaml:"users"`
}

// UserStore manages user authentication from users.yaml.
type UserStore struct {
	users map[string]*UserEntry

	// dummyHash stands in for the password hash of a username that does not
	// exist, so an unknown user costs the same bcrypt work as a wrong password
	// and the response time does not reveal which usernames are configured.
	dummyHash []byte

	// compare is bcrypt.CompareHashAndPassword; a field so tests can observe
	// which hash a login attempt was checked against.
	compare func(hashedPassword, password []byte) error

	limiter *CompareLimiter

	// problems lists what in the file is most likely a mistake, although it
	// loads (see Problems).
	problems []string
}

// NewUserStore loads users from a YAML file. Returns nil if the file doesn't
// exist. limiter bounds the bcrypt comparisons of login attempts, for known
// and unknown usernames alike; nil leaves them unbounded.
func NewUserStore(path string, limiter *CompareLimiter) (*UserStore, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read users config: %w", err)
	}
	return ParseUserStore(data, limiter)
}

// usersFile is UsersConfig with the list as a pointer, so that a document
// without a users key can be told from one with an empty list.
type usersFile struct {
	Users *[]UserEntry `yaml:"users"`
}

// ParseUserStore builds a UserStore from the contents of a users.yaml, as
// NewUserStore does from the file. A username listed twice keeps its last
// entry, as it always has; that and the other doubtful contents are reported
// by Problems.
func ParseUserStore(data []byte, limiter *CompareLimiter) (*UserStore, error) {
	var file usersFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse users config: %w", err)
	}
	var users []UserEntry
	var problems []string
	if file.Users == nil {
		problems = append(problems, "the file has no users list")
	} else {
		users = *file.Users
	}

	dummyHash, err := newDummyHash(dummyHashCost(users))
	if err != nil {
		return nil, fmt.Errorf("prepare dummy password hash: %w", err)
	}

	store := &UserStore{
		users:     make(map[string]*UserEntry, len(users)),
		dummyHash: dummyHash,
		compare:   bcrypt.CompareHashAndPassword,
		limiter:   limiter,
	}
	for i := range users {
		name := users[i].Username
		switch {
		case name == "":
			problems = append(problems, fmt.Sprintf("user %d has no username", i+1))
		case store.users[name] != nil:
			problems = append(problems, fmt.Sprintf("username %q is listed more than once", name))
		}
		store.users[name] = &users[i]
	}
	store.problems = problems
	return store, nil
}

// Problems reports what in the loaded file is most likely a mistake although
// it loads: no users list at all (an empty file, or a misspelled key), a user
// without a username, a username listed twice. A reload of users.yaml while
// ToolMesh runs refuses such a file and keeps the users in force; at startup
// they are logged.
func (s *UserStore) Problems() []string {
	if s == nil {
		return nil
	}
	return slices.Clone(s.problems)
}

// Count returns how many usernames the store holds.
func (s *UserStore) Count() int {
	if s == nil {
		return 0
	}
	return len(s.users)
}

// Diff compares the users of s with those of next and returns the usernames
// next adds, removes and changes (password hash, company, plan or roles),
// each sorted. A nil store holds no users.
func (s *UserStore) Diff(next *UserStore) (added, removed, changed []string) {
	var before, after map[string]*UserEntry
	if s != nil {
		before = s.users
	}
	if next != nil {
		after = next.users
	}
	for name, u := range after {
		old, ok := before[name]
		switch {
		case !ok:
			added = append(added, name)
		case old.PasswordHash != u.PasswordHash || old.Company != u.Company || old.Plan != u.Plan || !slices.Equal(old.Roles, u.Roles):
			changed = append(changed, name)
		}
	}
	for name := range before {
		if _, ok := after[name]; !ok {
			removed = append(removed, name)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}

// HashProblems reports what in the loaded password hashes weakens the login:
// the usernames whose password_hash is not a usable bcrypt hash (they can
// never log in), and whether the usable hashes differ in cost (then response time still
// tells some configured users from unknown ones). Both come back sorted.
func (s *UserStore) HashProblems() (unusable []string, costs []int) {
	seen := make(map[int]bool)
	for name, u := range s.users {
		if !usableHash(u.PasswordHash) {
			unusable = append(unusable, name)
			continue
		}
		cost, err := bcrypt.Cost([]byte(u.PasswordHash))
		if err != nil {
			continue
		}
		if !seen[cost] {
			seen[cost] = true
			costs = append(costs, cost)
		}
	}
	sort.Strings(unusable)
	sort.Ints(costs)
	if len(costs) < 2 {
		costs = nil
	}
	return unusable, costs
}

// dummyHashCost picks the bcrypt cost for the dummy hash: the most common cost
// among the configured password hashes, so that as many accounts as possible
// are indistinguishable from an unknown one by response time. Ties go to the
// higher cost; without a parseable hash it falls back to bcrypt.DefaultCost.
func dummyHashCost(users []UserEntry) int {
	counts := make(map[int]int)
	for i := range users {
		if cost, err := bcrypt.Cost([]byte(users[i].PasswordHash)); err == nil {
			counts[cost]++
		}
	}
	best, bestCount := bcrypt.DefaultCost, 0
	for cost, count := range counts {
		if count > bestCount || (count == bestCount && cost > best) {
			best, bestCount = cost, count
		}
	}
	return best
}

// newDummyHash returns the bcrypt hash of a random secret that is discarded
// right away, so no password can ever match it.
func newDummyHash(cost int) ([]byte, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("read random secret: %w", err)
	}
	return bcrypt.GenerateFromPassword(secret, cost)
}

// Authenticate verifies a username/password combination and returns the matching user.
// It runs exactly one bcrypt comparison whether or not the username exists. An
// entry whose password_hash cannot be used is treated like an unknown user,
// since comparing against it would return without doing any work.
//
// It returns (nil, nil) for a wrong password or an unknown username, and an
// error if the comparison could not be run (see CompareLimiter.Do). In that
// case the password was not checked, and the attempt is not a failed login.
func (s *UserStore) Authenticate(ctx context.Context, username, password string) (*UserEntry, error) {
	u, known := s.users[username]
	usable := known && usableHash(u.PasswordHash)
	hash := s.dummyHash
	if usable {
		hash = []byte(u.PasswordHash)
	}
	var mismatch error
	if err := s.limiter.Do(ctx, func() { mismatch = s.compare(hash, []byte(password)) }); err != nil {
		return nil, err
	}
	if mismatch != nil || !usable {
		return nil, nil
	}
	return u, nil
}

// Lookup returns a copy of the configured user with this username, or nil
// when there is none or its password_hash is not usable, which is how a user
// is disabled without removing the entry (e.g. password_hash: "!"). It does
// no password check: token renewal and bearer validation use it to apply the
// users.yaml in force now to tokens issued earlier.
func (s *UserStore) Lookup(username string) *UserEntry {
	if s == nil {
		return nil
	}
	u, ok := s.users[username]
	if !ok || !usableHash(u.PasswordHash) {
		return nil
	}
	cp := *u
	cp.Roles = append([]string(nil), u.Roles...)
	return &cp
}

// bcryptSalt decodes the salt part of a bcrypt hash, which uses its own
// base64 alphabet.
var bcryptSalt = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

// usableHash reports whether hash is something bcrypt will actually work on:
// well-formed, and with a salt it can decode. For anything else the comparison
// returns an error at once instead of hashing.
func usableHash(hash string) bool {
	const saltStart, saltLen = 7, 22 // "$2a$10$" precedes the salt
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return false
	}
	if len(hash) < saltStart+saltLen {
		return false
	}
	_, err := bcryptSalt.DecodeString(hash[saltStart : saltStart+saltLen])
	return err == nil
}
