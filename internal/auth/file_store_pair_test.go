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
	"fmt"
	"testing"
	"time"
)

// TestFileTokenStore_RefreshTokenOf pins the lookup of a token pair by its
// access token, which revocation makes for every token it does not know:
// it finds the refresh token of an access token that is gone from the
// store, follows a rotation, forgets a consumed or expired refresh token,
// and still answers after a restart. The lookup is by key, so its cost does
// not grow with the number of refresh tokens while the store's lock is held.
func TestFileTokenStore_RefreshTokenOf(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	fs, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	pair := func(i int, refreshFor time.Duration) *TokenInfo {
		return &TokenInfo{
			AccessToken: fmt.Sprintf("at-%d", i), RefreshToken: fmt.Sprintf("rt-%d", i),
			ExpiresAt: now.Add(-time.Minute), RefreshExpiresAt: now.Add(refreshFor),
		}
	}
	// The access tokens have expired and are not stored: only the refresh
	// tokens name them.
	for i := range 3 {
		if err := fs.SaveRefreshToken(ctx, pair(i, time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	lookup := func(s *FileTokenStore, at string) string {
		t.Helper()
		rt, err := s.RefreshTokenOf(ctx, at)
		if err != nil && !errors.Is(err, ErrNotFound) {
			t.Fatalf("RefreshTokenOf(%q): %v", at, err)
		}
		return rt
	}
	if got := lookup(fs, "at-1"); got != "rt-1" {
		t.Errorf("RefreshTokenOf(at-1) = %q, want rt-1", got)
	}
	if got := lookup(fs, "at-unknown"); got != "" {
		t.Errorf("an unknown access token has refresh token %q", got)
	}
	if n := len(fs.refreshByAccess); n != 3 {
		t.Errorf("index holds %d entries, want 3", n)
	}

	// Consuming a refresh token ends the pair.
	if _, err := fs.ConsumeRefreshToken(ctx, "rt-1"); err != nil {
		t.Fatal(err)
	}
	if got := lookup(fs, "at-1"); got != "" {
		t.Errorf("after the refresh token was consumed: %q", got)
	}

	// Saving a refresh token again for another access token moves it.
	moved := pair(2, time.Hour)
	moved.AccessToken = "at-2b"
	if err := fs.SaveRefreshToken(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if got := lookup(fs, "at-2"); got != "" {
		t.Errorf("the old access token still names the refresh token: %q", got)
	}
	if got := lookup(fs, "at-2b"); got != "rt-2" {
		t.Errorf("RefreshTokenOf(at-2b) = %q, want rt-2", got)
	}

	// An expired refresh token goes with the cleanup.
	if err := fs.SaveRefreshToken(ctx, pair(9, time.Minute)); err != nil {
		t.Fatal(err)
	}
	fs.removeExpired(now.Add(2 * time.Minute))
	if got := lookup(fs, "at-9"); got != "" {
		t.Errorf("after the refresh token expired: %q", got)
	}
	if n := len(fs.refreshByAccess); n != 2 {
		t.Errorf("index holds %d entries, want those of rt-0 and rt-2", n)
	}

	// A restart rebuilds the index from the file.
	restarted, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := lookup(restarted, "at-0"); got != "rt-0" {
		t.Errorf("after a restart: RefreshTokenOf(at-0) = %q, want rt-0", got)
	}
	if got := lookup(restarted, "at-2b"); got != "rt-2" {
		t.Errorf("after a restart: RefreshTokenOf(at-2b) = %q, want rt-2", got)
	}
}
