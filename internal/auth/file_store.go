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
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// fileState is the structure serialized to disk.
type fileState struct {
	Clients       map[string]*OAuthClient `json:"clients"`
	AccessTokens  map[string]*TokenInfo   `json:"access_tokens,omitempty"`
	RefreshTokens map[string]*TokenInfo   `json:"refresh_tokens,omitempty"`
}

// FileTokenStore implements TokenStore backed by a JSON file on disk.
// All state is kept in-memory for fast access and persisted atomically
// on every mutation (write to .tmp, then rename).
type FileTokenStore struct {
	mu            sync.Mutex
	dataDir       string
	clients       map[string]*OAuthClient
	authCodes     map[string]*AuthCode
	accessTokens  map[string]*TokenInfo
	refreshTokens map[string]*TokenInfo
}

// NewFileTokenStore creates a new file-backed token store. It creates the
// data directory if needed and restores any previously persisted state.
func NewFileTokenStore(dataDir string) (*FileTokenStore, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &FileTokenStore{
		dataDir:       dataDir,
		clients:       make(map[string]*OAuthClient),
		authCodes:     make(map[string]*AuthCode),
		accessTokens:  make(map[string]*TokenInfo),
		refreshTokens: make(map[string]*TokenInfo),
	}

	if err := s.loadState(); err != nil {
		slog.Warn("failed to load persisted OAuth state", "error", err)
	}

	return s, nil
}

func (s *FileTokenStore) statePath() string {
	return filepath.Join(s.dataDir, "oauth-state.json")
}

// loadState reads persisted state from disk and filters expired entries.
func (s *FileTokenStore) loadState() error {
	data, err := os.ReadFile(s.statePath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var state fileState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("parse oauth state: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	if state.Clients != nil {
		for k, v := range state.Clients {
			s.clients[k] = v
		}
		slog.Info("restored registered OAuth clients from disk", "count", len(state.Clients))
	}

	if state.AccessTokens != nil {
		restored := 0
		for k, v := range state.AccessTokens {
			if v.ExpiresAt.After(now) {
				s.accessTokens[k] = v
				restored++
			}
		}
		if restored > 0 {
			slog.Info("restored valid access tokens from disk", "count", restored)
		}
	}

	if state.RefreshTokens != nil {
		restored := 0
		for k, v := range state.RefreshTokens {
			if v.ExpiresAt.After(now) {
				s.refreshTokens[k] = v
				restored++
			}
		}
		if restored > 0 {
			slog.Info("restored valid refresh tokens from disk", "count", restored)
		}
	}

	return nil
}

// saveState persists clients and tokens to disk atomically.
// Must be called with s.mu held.
func (s *FileTokenStore) saveState() {
	state := fileState{
		Clients:       s.clients,
		AccessTokens:  s.accessTokens,
		RefreshTokens: s.refreshTokens,
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		slog.Warn("failed to marshal OAuth state", "error", err)
		return
	}

	tmpPath := s.statePath() + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		slog.Warn("failed to write OAuth state", "error", err)
		return
	}
	if err := os.Rename(tmpPath, s.statePath()); err != nil {
		slog.Warn("failed to rename OAuth state file", "error", err)
	}
}

// SaveClient stores an OAuth client registration.
func (s *FileTokenStore) SaveClient(_ context.Context, c *OAuthClient) error {
	s.mu.Lock()
	s.clients[c.ClientID] = c
	s.saveState()
	s.mu.Unlock()
	return nil
}

// GetClient retrieves an OAuth client by its client ID.
func (s *FileTokenStore) GetClient(_ context.Context, clientID string) (*OAuthClient, error) {
	s.mu.Lock()
	c, ok := s.clients[clientID]
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}

// SaveAuthCode stores an authorization code (in-memory only, short-lived).
func (s *FileTokenStore) SaveAuthCode(_ context.Context, ac *AuthCode) error {
	s.mu.Lock()
	s.authCodes[ac.Code] = ac
	s.mu.Unlock()
	return nil
}

// ConsumeAuthCode atomically retrieves and deletes an authorization code.
func (s *FileTokenStore) ConsumeAuthCode(_ context.Context, code string) (*AuthCode, error) {
	s.mu.Lock()
	ac, ok := s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return ac, nil
}

// SaveToken stores an access token.
func (s *FileTokenStore) SaveToken(_ context.Context, ti *TokenInfo) error {
	s.mu.Lock()
	s.accessTokens[ti.AccessToken] = ti
	s.saveState()
	s.mu.Unlock()
	return nil
}

// GetToken retrieves token information by access token.
func (s *FileTokenStore) GetToken(_ context.Context, accessToken string) (*TokenInfo, error) {
	s.mu.Lock()
	ti, ok := s.accessTokens[accessToken]
	if ok && ti.ExpiresAt.Before(time.Now()) {
		delete(s.accessTokens, accessToken)
		s.saveState()
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return ti, nil
}

// DeleteToken removes an access token from the store.
func (s *FileTokenStore) DeleteToken(_ context.Context, accessToken string) error {
	s.mu.Lock()
	delete(s.accessTokens, accessToken)
	s.saveState()
	s.mu.Unlock()
	return nil
}

// SaveRefreshToken stores a refresh token.
func (s *FileTokenStore) SaveRefreshToken(_ context.Context, ti *TokenInfo) error {
	s.mu.Lock()
	s.refreshTokens[ti.RefreshToken] = ti
	s.saveState()
	s.mu.Unlock()
	return nil
}

// ConsumeRefreshToken atomically retrieves and deletes a refresh token.
func (s *FileTokenStore) ConsumeRefreshToken(_ context.Context, refreshToken string) (*TokenInfo, error) {
	s.mu.Lock()
	ti, ok := s.refreshTokens[refreshToken]
	if ok {
		delete(s.refreshTokens, refreshToken)
		s.saveState()
	}
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return ti, nil
}

// Cleanup periodically removes expired entries. Run as a goroutine.
func (s *FileTokenStore) Cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			dirty := false

			for k, v := range s.authCodes {
				if v.ExpiresAt.Before(now) {
					delete(s.authCodes, k)
				}
			}
			for k, v := range s.accessTokens {
				if v.ExpiresAt.Before(now) {
					delete(s.accessTokens, k)
					dirty = true
				}
			}
			for k, v := range s.refreshTokens {
				if v.ExpiresAt.Before(now) {
					delete(s.refreshTokens, k)
					dirty = true
				}
			}

			if dirty {
				s.saveState()
			}
			s.mu.Unlock()
		}
	}
}
