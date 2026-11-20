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

// outagePrimary is a fakePrimary that can be switched off: while down, every
// operation fails and changes nothing, as a Redis that cannot be reached.
// It keeps what it held, as a Redis that comes back does.
type outagePrimary struct {
	*fakePrimary
	down bool
}

var errPrimaryDown = errors.New("primary down")

func (o *outagePrimary) SaveClient(ctx context.Context, c *OAuthClient) error {
	if o.down {
		return errPrimaryDown
	}
	return o.fakePrimary.SaveClient(ctx, c)
}

func (o *outagePrimary) GetClient(ctx context.Context, id string) (*OAuthClient, error) {
	if o.down {
		return nil, errPrimaryDown
	}
	return o.fakePrimary.GetClient(ctx, id)
}

func (o *outagePrimary) SaveAuthCode(ctx context.Context, ac *AuthCode) error {
	if o.down {
		return errPrimaryDown
	}
	return o.fakePrimary.SaveAuthCode(ctx, ac)
}

func (o *outagePrimary) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	if o.down {
		return nil, errPrimaryDown
	}
	return o.fakePrimary.ConsumeAuthCode(ctx, code)
}

func (o *outagePrimary) SaveToken(ctx context.Context, ti *TokenInfo) error {
	if o.down {
		return errPrimaryDown
	}
	return o.fakePrimary.SaveToken(ctx, ti)
}

func (o *outagePrimary) GetToken(ctx context.Context, t string) (*TokenInfo, error) {
	if o.down {
		return nil, errPrimaryDown
	}
	return o.fakePrimary.GetToken(ctx, t)
}

func (o *outagePrimary) DeleteToken(ctx context.Context, t string) error {
	if o.down {
		return errPrimaryDown
	}
	return o.fakePrimary.DeleteToken(ctx, t)
}

func (o *outagePrimary) SaveRefreshToken(ctx context.Context, ti *TokenInfo) error {
	if o.down {
		return errPrimaryDown
	}
	return o.fakePrimary.SaveRefreshToken(ctx, ti)
}

func (o *outagePrimary) ConsumeRefreshToken(ctx context.Context, t string) (*TokenInfo, error) {
	if o.down {
		return nil, errPrimaryDown
	}
	return o.fakePrimary.ConsumeRefreshToken(ctx, t)
}

// outageStore is a hybrid store over a primary that can be switched off,
// holding one token pair and one authorization code in both stores.
type outageStore struct {
	h       *HybridTokenStore
	primary *outagePrimary
	file    *FileTokenStore
	dir     string
	pair    *TokenInfo
	code    *AuthCode
}

func newOutageStore(t *testing.T) *outageStore {
	t.Helper()
	dir := t.TempDir()
	fs, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p := &outagePrimary{fakePrimary: newFakePrimary()}
	now := time.Now()
	s := &outageStore{
		h: NewHybridTokenStore(p, fs), primary: p, file: fs, dir: dir,
		pair: &TokenInfo{
			AccessToken: "outage-access", RefreshToken: "outage-refresh", UserID: "u1",
			ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
		},
		code: &AuthCode{Code: "outage-code", UserID: "u1", ExpiresAt: now.Add(5 * time.Minute)},
	}
	ctx := context.Background()
	for _, err := range []error{s.h.SaveToken(ctx, s.pair), s.h.SaveRefreshToken(ctx, s.pair), s.h.SaveAuthCode(ctx, s.code)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// revoke does what the revocation endpoint does with an access token.
func (s *outageStore) revoke(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	ti, err := s.h.GetToken(ctx, s.pair.AccessToken)
	if err != nil {
		t.Fatalf("the token to revoke was not found: %v", err)
	}
	_ = s.h.DeleteToken(ctx, ti.AccessToken)
	if _, err := s.h.ConsumeRefreshToken(ctx, ti.RefreshToken); err != nil {
		t.Fatalf("the refresh token of the pair was not found: %v", err)
	}
}

// TestHybridStore_RevocationDuringOutageHolds pins that a token pair revoked
// while the primary store cannot be reached stays revoked when the store
// answers again with the copy it kept, and that the copy is removed there.
func TestHybridStore_RevocationDuringOutageHolds(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()

	s.primary.down = true
	s.revoke(t)
	if _, err := s.h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("during the outage the revoked access token is found: %v", err)
	}

	s.primary.down = false
	if _, ok := s.primary.tokens[s.pair.AccessToken]; !ok {
		t.Fatal("test setup: the primary store was expected to keep its copy")
	}
	if _, err := s.h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked access token works again after the outage: %v", err)
	}
	if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked refresh token works again after the outage: %v", err)
	}
	if _, ok := s.primary.tokens[s.pair.AccessToken]; ok {
		t.Error("the primary store still holds the revoked access token")
	}
	if _, ok := s.primary.refreshes[s.pair.RefreshToken]; ok {
		t.Error("the primary store still holds the revoked refresh token")
	}
	if n := s.file.removedCount.Load(); n != 0 {
		t.Errorf("%d removals are still remembered after they were completed", n)
	}
}

// TestHybridStore_SpentTokensStaySpent pins that a refresh token and an
// authorization code consumed through the file store during an outage are
// handed out once: not a second time during the outage, and not again from
// the copy the primary store kept.
func TestHybridStore_SpentTokensStaySpent(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()

	s.primary.down = true
	if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); err != nil {
		t.Fatalf("the refresh token could not be used during the outage: %v", err)
	}
	if _, err := s.h.ConsumeAuthCode(ctx, s.code.Code); err != nil {
		t.Fatalf("the code could not be used during the outage: %v", err)
	}
	if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refresh token was handed out twice during the outage: %v", err)
	}

	s.primary.down = false
	if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the spent refresh token came back with the primary store: %v", err)
	}
	if _, err := s.h.ConsumeAuthCode(ctx, s.code.Code); !errors.Is(err, ErrNotFound) {
		t.Errorf("the spent code came back with the primary store: %v", err)
	}
	if len(s.primary.refreshes) != 0 || len(s.primary.codes) != 0 {
		t.Errorf("the primary store still holds spent entries: %d refresh tokens, %d codes", len(s.primary.refreshes), len(s.primary.codes))
	}
}

// TestHybridStore_RemovalSurvivesRestart pins that a revocation made during
// an outage is not forgotten when ToolMesh restarts before the primary
// store answers again: the warm-up after the restart removes the copies the
// primary store kept instead of honoring them.
func TestHybridStore_RemovalSurvivesRestart(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()

	s.primary.down = true
	s.revoke(t)

	restarted, err := NewFileTokenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	if n := restarted.removedCount.Load(); n != 2 {
		t.Fatalf("after the restart %d removals are remembered, want those of the access and the refresh token", n)
	}
	s.primary.down = false
	h := NewHybridTokenStore(s.primary, restarted)
	restarted.WarmUp(ctx, s.primary)

	if _, ok := s.primary.tokens[s.pair.AccessToken]; ok {
		t.Error("after the warm-up the primary store still holds the revoked access token")
	}
	if _, ok := s.primary.refreshes[s.pair.RefreshToken]; ok {
		t.Error("after the warm-up the primary store still holds the revoked refresh token")
	}
	if _, err := h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked access token works after the restart: %v", err)
	}
	if _, err := h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked refresh token works after the restart: %v", err)
	}
	if n := restarted.removedCount.Load(); n != 0 {
		t.Errorf("%d removals are still remembered after the warm-up applied them", n)
	}
}

// TestHybridStore_OutageRemembersOnlyHeldEntries pins the bounds of what is
// remembered: nothing for a token the file store never held, so requests
// with made-up tokens during an outage leave nothing behind, nothing while
// the primary store answers, and a remembered removal goes when the entry
// would have expired anyway.
func TestHybridStore_OutageRemembersOnlyHeldEntries(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()

	s.primary.down = true
	for _, made := range []string{"made-up-1", "made-up-2"} {
		if _, err := s.h.ConsumeRefreshToken(ctx, made); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a made-up refresh token was found: %v", err)
		}
		if _, err := s.h.ConsumeAuthCode(ctx, made); !errors.Is(err, ErrNotFound) {
			t.Fatalf("a made-up code was found: %v", err)
		}
		_ = s.h.DeleteToken(ctx, made)
	}
	if n := s.file.removedCount.Load(); n != 0 {
		t.Errorf("made-up tokens left %d remembered removals", n)
	}

	s.primary.down = false
	s.revoke(t)
	if n := s.file.removedCount.Load(); n != 0 {
		t.Errorf("a revocation the primary store took part in left %d remembered removals", n)
	}

	// A removal is remembered until the entry expires, not longer.
	s.file.markRemoved(removedAccess, "short-lived", time.Now().Add(time.Minute))
	s.file.markRemoved(removedAccess, "already-expired", time.Now().Add(-time.Minute))
	if n := s.file.removedCount.Load(); n != 1 {
		t.Fatalf("%d removals remembered, want the one that has not expired", n)
	}
	s.file.removeExpired(time.Now().Add(2 * time.Minute))
	if n := s.file.removedCount.Load(); n != 0 {
		t.Errorf("%d removals remembered after their entries expired", n)
	}
}
