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
	"errors"
	"testing"
	"time"
)

func newTestFileStore(t *testing.T) *FileTokenStore {
	t.Helper()
	store, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	return store
}

func TestFileTokenStore_RefreshTokenSurvivesAccessExpiry(t *testing.T) {
	store := newTestFileStore(t)
	ctx := context.Background()

	// Simulate a token where the access token has expired but the refresh
	// token should still be valid (RefreshExpiresAt is 7 days out).
	ti := &TokenInfo{ //nolint:gosec // test data, not real credentials
		AccessToken:      "at-expired",
		RefreshToken:     "rt-still-valid",
		ClientID:         "c1",
		UserID:           "user1",
		CompanyID:        "company1",
		Plan:             "pro",
		Roles:            []string{"admin"},
		Scope:            "claudeai",
		ExpiresAt:        time.Now().Add(-1 * time.Hour), // access token expired 1h ago
		RefreshExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := store.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	// Refresh token should be consumable even though ExpiresAt is in the past.
	got, err := store.ConsumeRefreshToken(ctx, "rt-still-valid")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken: %v", err)
	}
	if got.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user1")
	}
}

func TestFileTokenStore_RefreshTokenPersistenceAfterRestart(t *testing.T) {
	dir := t.TempDir()

	// Store 1: save a token with expired access but valid refresh.
	store1, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}

	ctx := context.Background()
	ti := &TokenInfo{
		AccessToken:      "at-old",
		RefreshToken:     "rt-persistent",
		ClientID:         "c1",
		UserID:           "user1",
		CompanyID:        "company1",
		Plan:             "pro",
		Roles:            []string{"admin"},
		Scope:            "claudeai",
		ExpiresAt:        time.Now().Add(-2 * time.Hour), // access expired 2h ago
		RefreshExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	if err := store1.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	// Store 2: simulate restart — loads state from disk.
	store2, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatalf("NewFileTokenStore (restart): %v", err)
	}

	// Refresh token should have survived the restart despite expired access token.
	got, err := store2.ConsumeRefreshToken(ctx, "rt-persistent")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken after restart: %v", err)
	}
	if got.UserID != "user1" {
		t.Errorf("UserID = %q, want %q", got.UserID, "user1")
	}
}

func TestFileTokenStore_ExpiredRefreshTokenIsCleanedUp(t *testing.T) {
	store := newTestFileStore(t)
	ctx := context.Background()

	// Token where both access and refresh have expired.
	ti := &TokenInfo{
		AccessToken:      "at-dead",
		RefreshToken:     "rt-dead",
		ClientID:         "c1",
		UserID:           "user1",
		CompanyID:        "company1",
		Plan:             "pro",
		Roles:            []string{"admin"},
		Scope:            "claudeai",
		ExpiresAt:        time.Now().Add(-2 * time.Hour),
		RefreshExpiresAt: time.Now().Add(-1 * time.Hour), // refresh also expired
	}

	if err := store.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	// Simulate restart — loadState should filter out the expired refresh token.
	dir := store.dataDir
	store2, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}

	_, err = store2.ConsumeRefreshToken(ctx, "rt-dead")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired refresh token, got %v", err)
	}
}

func TestTokenInfo_RefreshExpiry_Fallback(t *testing.T) {
	// When RefreshExpiresAt is zero (old tokens), fall back to ExpiresAt.
	ti := &TokenInfo{
		ExpiresAt: time.Date(2026, 3, 29, 12, 0, 0, 0, time.UTC),
	}
	if got := ti.RefreshExpiry(); !got.Equal(ti.ExpiresAt) {
		t.Errorf("RefreshExpiry() = %v, want %v (fallback to ExpiresAt)", got, ti.ExpiresAt)
	}

	// When RefreshExpiresAt is set, use it.
	ti.RefreshExpiresAt = time.Date(2026, 4, 5, 12, 0, 0, 0, time.UTC)
	if got := ti.RefreshExpiry(); !got.Equal(ti.RefreshExpiresAt) {
		t.Errorf("RefreshExpiry() = %v, want %v", got, ti.RefreshExpiresAt)
	}
}
