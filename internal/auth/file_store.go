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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fileState is the structure serialized to disk.
type fileState struct {
	Clients       map[string]*OAuthClient `json:"clients"`
	AccessTokens  map[string]*TokenInfo   `json:"access_tokens,omitempty"`
	RefreshTokens map[string]*TokenInfo   `json:"refresh_tokens,omitempty"`
	// Removed holds the removals another store may not know about: the
	// kind followed by the token, and the time the entry expires (see
	// removals).
	Removed map[string]time.Time `json:"removed,omitempty"`
}

// removalReconcileInterval is how often Cleanup tells the primary store
// about removals it has not been told about. With nothing to tell, a tick
// costs one atomic read.
const removalReconcileInterval = 30 * time.Second

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
	// refreshByAccess names the refresh token issued together with an
	// access token, so that RefreshTokenOf looks the pair up instead of
	// walking every refresh token while it holds mu.
	refreshByAccess map[string]string
	// fromDisk holds the tokens that were restored from disk at startup.
	// They are the ones a primary store can hold a copy of when this
	// process never reached it (see RememberRemovals).
	fromDisk map[string]bool

	// removed remembers removals another store may not know about. It is
	// persisted with the state and has a lock of its own.
	removed *removals
	// standalone reports that removals made here are to be remembered
	// because a primary store exists that this process does not use (see
	// RememberRemovals).
	standalone atomic.Bool
	// primary is the store Cleanup tells about remembered removals, once
	// WarmUp has named it.
	primary atomic.Pointer[primaryStore]
}

// primaryStore names the store a FileTokenStore keeps told about removals.
type primaryStore struct {
	TokenStore
}

// NewFileTokenStore creates a new file-backed token store. It creates the
// data directory if needed and restores any previously persisted state.
func NewFileTokenStore(dataDir string) (*FileTokenStore, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	s := &FileTokenStore{
		dataDir:         dataDir,
		clients:         make(map[string]*OAuthClient),
		authCodes:       make(map[string]*AuthCode),
		accessTokens:    make(map[string]*TokenInfo),
		refreshTokens:   make(map[string]*TokenInfo),
		refreshByAccess: make(map[string]string),
		fromDisk:        make(map[string]bool),
		removed:         newRemovals(),
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
		restored := 0
		for k, v := range state.Clients {
			if !v.Expired(now) {
				s.clients[k] = v
				restored++
			}
		}
		slog.Info("restored registered OAuth clients from disk", "count", restored)
	}

	if state.AccessTokens != nil {
		restored := 0
		for k, v := range state.AccessTokens {
			if v.ExpiresAt.After(now) {
				s.accessTokens[k] = v
				s.fromDisk[k] = true
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
			if v.RefreshExpiry().After(now) {
				s.refreshTokens[k] = v
				if v.AccessToken != "" {
					s.refreshByAccess[v.AccessToken] = k
				}
				s.fromDisk[k] = true
				restored++
			}
		}
		if restored > 0 {
			slog.Info("restored valid refresh tokens from disk", "count", restored)
		}
	}

	s.removed.load(state.Removed, now)

	return nil
}

// saveState persists clients and tokens to disk atomically.
// Must be called with s.mu held.
func (s *FileTokenStore) saveState() {
	state := fileState{
		Clients:       s.clients,
		AccessTokens:  s.accessTokens,
		RefreshTokens: s.refreshTokens,
		Removed:       s.removed.snapshot(),
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

// persist writes the state to disk.
func (s *FileTokenStore) persist() {
	s.mu.Lock()
	s.saveState()
	s.mu.Unlock()
}

// SaveClient stores an OAuth client registration.
func (s *FileTokenStore) SaveClient(_ context.Context, c *OAuthClient) error {
	s.mu.Lock()
	s.clients[c.ClientID] = c
	s.saveState()
	s.mu.Unlock()
	return nil
}

// GetClient retrieves an OAuth client by its client ID. An expired client is
// not found, even before Cleanup has removed it.
func (s *FileTokenStore) GetClient(_ context.Context, clientID string) (*OAuthClient, error) {
	s.mu.Lock()
	c, ok := s.clients[clientID]
	s.mu.Unlock()
	if !ok || c.Expired(time.Now()) {
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
	ac := s.removeCode(code, false)
	if ac == nil {
		return nil, ErrNotFound
	}
	return ac, nil
}

// removeCode removes an authorization code and returns it, or nil when it
// was not stored. With remember the removal is remembered in the same step
// (see removeAccess).
func (s *FileTokenStore) removeCode(code string, remember bool) *AuthCode {
	s.mu.Lock()
	defer s.mu.Unlock()
	ac, ok := s.authCodes[code]
	if !ok {
		return nil
	}
	delete(s.authCodes, code)
	if remember && s.removed.mark(removedCode, code, ac.ExpiresAt, time.Now()) {
		s.saveState()
	}
	return ac
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
		delete(s.fromDisk, accessToken)
		s.saveState()
		ok = false
	}
	s.mu.Unlock()
	if !ok {
		return nil, ErrNotFound
	}
	return ti, nil
}

// RefreshTokenOf implements PairLookup: it returns the refresh token issued
// together with accessToken, whether or not the access token is still
// stored, or ErrNotFound.
func (s *FileTokenStore) RefreshTokenOf(_ context.Context, accessToken string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ti, ok := s.accessTokens[accessToken]; ok && ti.RefreshToken != "" {
		return ti.RefreshToken, nil
	}
	if rt, ok := s.refreshByAccess[accessToken]; ok {
		return rt, nil
	}
	return "", ErrNotFound
}

// Holds implements TokenHolder: it reports whether token is an access or
// refresh token stored here, or the access token of a stored refresh
// token. It costs a lookup in memory.
func (s *FileTokenStore) Holds(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accessTokens[token]; ok {
		return true
	}
	if _, ok := s.refreshTokens[token]; ok {
		return true
	}
	_, ok := s.refreshByAccess[token]
	return ok
}

// putRefreshLocked stores the refresh token of ti and records which access
// token it was issued with. Callers must hold s.mu.
func (s *FileTokenStore) putRefreshLocked(ti *TokenInfo) {
	s.dropRefreshLocked(ti.RefreshToken)
	s.refreshTokens[ti.RefreshToken] = ti
	if ti.AccessToken != "" {
		s.refreshByAccess[ti.AccessToken] = ti.RefreshToken
	}
}

// dropRefreshLocked removes the refresh token rt together with its entry in
// refreshByAccess and returns its record, or nil when it is not stored.
// Callers must hold s.mu.
func (s *FileTokenStore) dropRefreshLocked(rt string) *TokenInfo {
	ti, ok := s.refreshTokens[rt]
	if !ok {
		return nil
	}
	delete(s.refreshTokens, rt)
	if s.refreshByAccess[ti.AccessToken] == rt {
		delete(s.refreshByAccess, ti.AccessToken)
	}
	return ti
}

// DeleteToken removes an access token from the store.
func (s *FileTokenStore) DeleteToken(_ context.Context, accessToken string) error {
	s.removeAccess(accessToken, false)
	return nil
}

// removeAccess removes an access token and returns its record, or nil when
// it was not stored. With remember, or when the store stands alone and
// restored the token from disk (see RememberRemovals), the removal is
// remembered in the same step and the same write to disk. There is no
// moment at which the token is gone and its removal is not on record yet,
// for another request or for a crash to fall into.
func (s *FileTokenStore) removeAccess(accessToken string, remember bool) *TokenInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	ti := s.accessTokens[accessToken]
	delete(s.accessTokens, accessToken)
	if ti != nil && (remember || s.restoredStandaloneLocked(accessToken)) {
		s.removed.mark(removedAccess, accessToken, ti.ExpiresAt, time.Now())
	}
	delete(s.fromDisk, accessToken)
	s.saveState()
	return ti
}

// SaveRefreshToken stores a refresh token.
func (s *FileTokenStore) SaveRefreshToken(_ context.Context, ti *TokenInfo) error {
	s.mu.Lock()
	s.putRefreshLocked(ti)
	s.saveState()
	s.mu.Unlock()
	return nil
}

// ConsumeRefreshToken atomically retrieves and deletes a refresh token.
func (s *FileTokenStore) ConsumeRefreshToken(_ context.Context, refreshToken string) (*TokenInfo, error) {
	ti := s.removeRefresh(refreshToken, false)
	if ti == nil {
		return nil, ErrNotFound
	}
	return ti, nil
}

// removeRefresh removes a refresh token and returns its record, or nil
// when it was not stored. The removal is remembered as removeAccess says.
func (s *FileTokenStore) removeRefresh(refreshToken string, remember bool) *TokenInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	ti := s.dropRefreshLocked(refreshToken)
	if ti == nil {
		return nil
	}
	if remember || s.restoredStandaloneLocked(refreshToken) {
		s.removed.mark(removedRefresh, refreshToken, ti.RefreshExpiry(), time.Now())
	}
	delete(s.fromDisk, refreshToken)
	s.saveState()
	return ti
}

// RememberRemovals makes the store remember the removal of every token it
// restored from disk. Call it when a primary store is configured that this
// process does not use, such as a Redis that did not answer at startup.
//
// That store may hold a copy of the tokens issued before this process
// started, and this process cannot tell it when one of them is revoked or
// spent. Without a record, the copy would count again in the next process
// that does reach the store: WarmUp would find nothing to remove there.
// Tokens issued by this process never reach the other store and need no
// record.
func (s *FileTokenStore) RememberRemovals() {
	s.standalone.Store(true)
}

// restoredStandaloneLocked reports whether the removal of token is to be
// remembered because RememberRemovals is in force and the token was
// restored from disk. Callers must hold s.mu.
func (s *FileTokenStore) restoredStandaloneLocked(token string) bool {
	return s.standalone.Load() && s.fromDisk[token]
}

// markRemoved remembers until the time until that the entry of the given
// kind was deleted or consumed here while another store could not be told.
func (s *FileTokenStore) markRemoved(kind removedKind, token string, until time.Time) {
	if s.removed.mark(kind, token, until, time.Now()) {
		s.persist()
	}
}

// isRemoved reports whether a removal of the entry is remembered. It does
// not wait for the store's lock.
func (s *FileTokenStore) isRemoved(kind removedKind, token string) bool {
	return s.removed.has(kind, token, time.Now())
}

// WarmUp copies all current in-memory state to dst. Call this after
// connecting to a Redis instance that may have just restarted and lost
// its data, so tokens stored in the file store are immediately available
// in the primary store without waiting for a read-through fallback.
// Refresh tokens that have expired but were not cleaned up yet are not
// copied, so a restart cannot bring one back. Removals that dst was not told
// about while it was unreachable are applied to it, so a token revoked or
// spent during an outage does not come back with dst either. From then on
// Cleanup keeps dst told about removals.
func (s *FileTokenStore) WarmUp(ctx context.Context, dst TokenStore) {
	s.mu.Lock()
	now := time.Now()
	clients := make([]*OAuthClient, 0, len(s.clients))
	for _, c := range s.clients {
		if !c.Expired(now) {
			clients = append(clients, c)
		}
	}
	tokens := make([]*TokenInfo, 0, len(s.accessTokens))
	for _, t := range s.accessTokens {
		tokens = append(tokens, t)
	}
	refreshTokens := make([]*TokenInfo, 0, len(s.refreshTokens))
	for _, t := range s.refreshTokens {
		if t.RefreshExpiry().After(now) {
			refreshTokens = append(refreshTokens, t)
		}
	}
	s.mu.Unlock()

	for _, c := range clients {
		if err := dst.SaveClient(ctx, c); err != nil {
			slog.Warn("warm-up: failed to copy client to primary store", "clientID", c.ClientID, "error", err)
		}
	}
	for _, t := range tokens {
		if err := dst.SaveToken(ctx, t); err != nil {
			slog.Warn("warm-up: failed to copy access token to primary store", "error", err)
		}
	}
	for _, t := range refreshTokens {
		if err := dst.SaveRefreshToken(ctx, t); err != nil {
			slog.Warn("warm-up: failed to copy refresh token to primary store", "error", err)
		}
	}
	s.primary.Store(&primaryStore{dst})
	applied := s.applyRemovals(ctx, dst)
	slog.Info("warm-up: file store state copied to primary store",
		"clients", len(clients), "access_tokens", len(tokens), "refresh_tokens", len(refreshTokens),
		"removals", applied)
}

// applyRemovals removes from dst every entry whose removal dst has not been
// told about, and returns how many it could tell. It stops at the first
// entry dst cannot be told about: dst is unreachable then, and every
// further attempt would wait for it again. The removals stay remembered for
// a while after dst was told (removalGrace).
func (s *FileTokenStore) applyRemovals(ctx context.Context, dst TokenStore) int {
	applied := 0
	for _, r := range s.removed.pendingList() {
		var err error
		switch r.kind {
		case removedAccess:
			err = dst.DeleteToken(ctx, r.token)
		case removedRefresh:
			_, err = dst.ConsumeRefreshToken(ctx, r.token)
		case removedCode:
			_, err = dst.ConsumeAuthCode(ctx, r.token)
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			slog.Warn("failed to apply a removal to the primary store", "kind", strings.TrimSuffix(string(r.kind), ":"), "error", err)
			break
		}
		s.removed.setApplied(r.kind, r.token, time.Now())
		applied++
	}
	return applied
}

// reconcile tells the primary store about the removals it has not been
// told about. A token that was revoked while that store was unreachable
// goes from it this way without anyone presenting it here, which matters
// where another process reads the same store.
func (s *FileTokenStore) reconcile(ctx context.Context) {
	if p := s.primary.Load(); p != nil && s.removed.hasPending() {
		s.applyRemovals(ctx, p.TokenStore)
	}
}

// Cleanup periodically removes expired entries and keeps the primary store
// told about removals. Run as a goroutine.
func (s *FileTokenStore) Cleanup(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	reconcile := time.NewTicker(removalReconcileInterval)
	defer reconcile.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.removeExpired(time.Now())
		case <-reconcile.C:
			s.reconcile(ctx)
		}
	}
}

// removeExpired drops every entry that has expired at now and persists the
// result when anything that is persisted went away.
func (s *FileTokenStore) removeExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dirty := false

	for k, v := range s.clients {
		if v.Expired(now) {
			delete(s.clients, k)
			dirty = true
		}
	}
	for k, v := range s.authCodes {
		if v.ExpiresAt.Before(now) {
			delete(s.authCodes, k)
		}
	}
	for k, v := range s.accessTokens {
		if v.ExpiresAt.Before(now) {
			delete(s.accessTokens, k)
			delete(s.fromDisk, k)
			dirty = true
		}
	}
	for k, v := range s.refreshTokens {
		if v.RefreshExpiry().Before(now) {
			s.dropRefreshLocked(k)
			delete(s.fromDisk, k)
			dirty = true
		}
	}
	if s.removed.expire(now) {
		dirty = true
	}

	if dirty {
		s.saveState()
	}
}
