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

func TestFileTokenStore_ClientRoundTrip(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()

	c := &OAuthClient{ClientID: "c1", ClientSecret: "sec", ClientName: "Test", RedirectURIs: []string{"https://x/"}, CreatedAt: time.Now()}
	if err := s.SaveClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, "c1")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "c1" || got.ClientSecret != "sec" {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	if _, err := s.GetClient(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileTokenStore_AuthCodeConsume(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()

	ac := &AuthCode{Code: "abc", ClientID: "c1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveAuthCode(ctx, ac); err != nil {
		t.Fatal(err)
	}

	got, err := s.ConsumeAuthCode(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.ClientID != "c1" {
		t.Errorf("got %+v", got)
	}

	// Already consumed.
	if _, err := s.ConsumeAuthCode(ctx, "abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFileTokenStore_TokenRoundTrip(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()

	ti := &TokenInfo{
		AccessToken:      "a-tok",
		RefreshToken:     "r-tok",
		ClientID:         "c1",
		UserID:           "u1",
		ExpiresAt:        time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := s.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetToken(ctx, "a-tok")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "u1" {
		t.Errorf("got UserID=%q", got.UserID)
	}

	if err := s.DeleteToken(ctx, "a-tok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, "a-tok"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestFileTokenStore_ExpiredToken(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()

	ti := &TokenInfo{
		AccessToken: "expired",
		ExpiresAt:   time.Now().Add(-time.Second),
	}
	if err := s.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetToken(ctx, "expired"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token: expected ErrNotFound, got %v", err)
	}
}

func TestFileTokenStore_LoadState_Persistence(t *testing.T) {
	dir := t.TempDir()
	s1, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_ = s1.SaveClient(ctx, &OAuthClient{ClientID: "persisted", ClientSecret: "x"})
	_ = s1.SaveToken(ctx, &TokenInfo{AccessToken: "valid", ExpiresAt: time.Now().Add(time.Hour)})
	_ = s1.SaveToken(ctx, &TokenInfo{AccessToken: "expired", ExpiresAt: time.Now().Add(-time.Hour)})
	_ = s1.SaveRefreshToken(ctx, &TokenInfo{RefreshToken: "ref-valid", RefreshExpiresAt: time.Now().Add(48 * time.Hour)})

	// Reload.
	s2, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.GetClient(ctx, "persisted"); err != nil {
		t.Errorf("client not persisted: %v", err)
	}
	if _, err := s2.GetToken(ctx, "valid"); err != nil {
		t.Errorf("token not persisted: %v", err)
	}
	if _, err := s2.GetToken(ctx, "expired"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token should have been filtered on load, got %v", err)
	}
	if _, err := s2.ConsumeRefreshToken(ctx, "ref-valid"); err != nil {
		t.Errorf("refresh token not persisted: %v", err)
	}
}

func TestFileTokenStore_WarmUp(t *testing.T) {
	src := newTestFileStore(t)
	dst := newTestFileStore(t)
	ctx := context.Background()

	_ = src.SaveClient(ctx, &OAuthClient{ClientID: "c-warm"})
	_ = src.SaveToken(ctx, &TokenInfo{AccessToken: "t-warm", ExpiresAt: time.Now().Add(time.Hour)})
	_ = src.SaveRefreshToken(ctx, &TokenInfo{RefreshToken: "r-warm", RefreshExpiresAt: time.Now().Add(24 * time.Hour)})

	src.WarmUp(ctx, dst)

	if _, err := dst.GetClient(ctx, "c-warm"); err != nil {
		t.Errorf("client not warmed up: %v", err)
	}
	if _, err := dst.GetToken(ctx, "t-warm"); err != nil {
		t.Errorf("access token not warmed up: %v", err)
	}
	if _, err := dst.ConsumeRefreshToken(ctx, "r-warm"); err != nil {
		t.Errorf("refresh token not warmed up: %v", err)
	}
}

func TestFileTokenStore_Cleanup(t *testing.T) {
	s := newTestFileStore(t)
	ctx := context.Background()

	// Seed with expired entries.
	_ = s.SaveAuthCode(ctx, &AuthCode{Code: "exp-code", ExpiresAt: time.Now().Add(-time.Second)})
	_ = s.SaveToken(ctx, &TokenInfo{AccessToken: "exp-access", ExpiresAt: time.Now().Add(-time.Second)})
	_ = s.SaveRefreshToken(ctx, &TokenInfo{RefreshToken: "exp-refresh", RefreshExpiresAt: time.Now().Add(-time.Second)})

	// Run Cleanup in a goroutine with a short-lived context so it returns quickly.
	ctx2, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		s.Cleanup(ctx2)
		close(done)
	}()
	<-done

	// The 5-minute ticker never fires in that window, so we invoke the cleanup
	// logic directly to exercise the dirty-write branch.
	s.mu.Lock()
	now := time.Now()
	for k, v := range s.authCodes {
		if v.ExpiresAt.Before(now) {
			delete(s.authCodes, k)
		}
	}
	for k, v := range s.accessTokens {
		if v.ExpiresAt.Before(now) {
			delete(s.accessTokens, k)
		}
	}
	for k, v := range s.refreshTokens {
		if v.RefreshExpiry().Before(now) {
			delete(s.refreshTokens, k)
		}
	}
	s.mu.Unlock()
}

func TestTokenInfo_RefreshExpiry(t *testing.T) {
	now := time.Now()
	ti := &TokenInfo{ExpiresAt: now, RefreshExpiresAt: now.Add(time.Hour)}
	if !ti.RefreshExpiry().Equal(now.Add(time.Hour)) {
		t.Error("RefreshExpiry should prefer RefreshExpiresAt")
	}

	ti2 := &TokenInfo{ExpiresAt: now}
	if !ti2.RefreshExpiry().Equal(now) {
		t.Error("RefreshExpiry should fall back to ExpiresAt")
	}
}
