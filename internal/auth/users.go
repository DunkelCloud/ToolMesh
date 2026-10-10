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

	var cfg UsersConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse users config: %w", err)
	}

	dummyHash, err := newDummyHash(dummyHashCost(cfg.Users))
	if err != nil {
		return nil, fmt.Errorf("prepare dummy password hash: %w", err)
	}

	store := &UserStore{
		users:     make(map[string]*UserEntry, len(cfg.Users)),
		dummyHash: dummyHash,
		compare:   bcrypt.CompareHashAndPassword,
		limiter:   limiter,
	}
	for i := range cfg.Users {
		store.users[cfg.Users[i].Username] = &cfg.Users[i]
	}
	return store, nil
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
