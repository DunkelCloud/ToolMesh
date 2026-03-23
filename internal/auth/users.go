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
	"fmt"
	"os"

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
}

// NewUserStore loads users from a YAML file. Returns nil if the file doesn't exist.
func NewUserStore(path string) (*UserStore, error) {
	data, err := os.ReadFile(path)
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

	store := &UserStore{users: make(map[string]*UserEntry, len(cfg.Users))}
	for i := range cfg.Users {
		store.users[cfg.Users[i].Username] = &cfg.Users[i]
	}
	return store, nil
}

// Authenticate verifies a username/password combination and returns the matching user.
func (s *UserStore) Authenticate(username, password string) *UserEntry {
	u, ok := s.users[username]
	if !ok {
		return nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil
	}
	return u
}

// APIKeyEntry represents an API key from apikeys.yaml.
type APIKeyEntry struct {
	KeyHash   string   `yaml:"key_hash"`
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

// APIKeyStore manages API key authentication from apikeys.yaml.
type APIKeyStore struct {
	keys []APIKeyEntry
}

// NewAPIKeyStore loads API keys from a YAML file. Returns nil if the file doesn't exist.
func NewAPIKeyStore(path string) (*APIKeyStore, error) {
	data, err := os.ReadFile(path)
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

	return &APIKeyStore{keys: cfg.Keys}, nil
}

// Match finds the API key entry that matches the given plaintext key.
// Iterates over all keys and compares with bcrypt.
func (s *APIKeyStore) Match(key string) *APIKeyEntry {
	for i := range s.keys {
		if err := bcrypt.CompareHashAndPassword([]byte(s.keys[i].KeyHash), []byte(key)); err == nil {
			return &s.keys[i]
		}
	}
	return nil
}
