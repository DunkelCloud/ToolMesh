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
//
// afterFetch, when set, runs once inside the next read or consume, after
// the store has handed its copy out and before the caller sees it. A test
// puts a second request there, the way two requests overlap in a server.
type outagePrimary struct {
	*fakePrimary
	down       bool
	afterFetch func()
}

var errPrimaryDown = errors.New("primary down")

// fetched runs afterFetch once.
func (o *outagePrimary) fetched() {
	if hook := o.afterFetch; hook != nil {
		o.afterFetch = nil
		hook()
	}
}

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
	ac, err := o.fakePrimary.ConsumeAuthCode(ctx, code)
	if err == nil {
		o.fetched()
	}
	return ac, err
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
	ti, err := o.fakePrimary.GetToken(ctx, t)
	if err == nil {
		o.fetched()
	}
	return ti, err
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
	ti, err := o.fakePrimary.ConsumeRefreshToken(ctx, t)
	if err == nil {
		o.fetched()
	}
	return ti, err
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
	revokePair(t, s.h, s.pair.AccessToken)
}

// revokePair revokes the pair of accessToken through store, as the
// revocation endpoint does.
func revokePair(t *testing.T, store TokenStore, accessToken string) {
	t.Helper()
	ctx := context.Background()
	ti, err := store.GetToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("the token to revoke was not found: %v", err)
	}
	_ = store.DeleteToken(ctx, ti.AccessToken)
	if _, err := store.ConsumeRefreshToken(ctx, ti.RefreshToken); err != nil {
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
	// Presented more than once: every time it is refused.
	for i := range 3 {
		if _, err := s.h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
			t.Errorf("presentation %d: the revoked access token works again after the outage: %v", i+1, err)
		}
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
	if s.file.removed.hasPending() {
		t.Error("removals are still waiting for the primary store after it was told")
	}
}

// TestHybridStore_RemovalHoldsAgainstOverlappingRequests pins the removal
// against two requests that present the same token at once after the
// outage. The first one has fetched the copy from the primary store when
// the second one runs; whatever the second one does, the first must not
// come back with the token. A removal that is forgotten as soon as the
// copy is gone from the primary store would let it through.
func TestHybridStore_RemovalHoldsAgainstOverlappingRequests(t *testing.T) {
	ctx := context.Background()
	t.Run("access token", func(t *testing.T) {
		s := newOutageStore(t)
		s.primary.down = true
		s.revoke(t)
		s.primary.down = false
		s.primary.afterFetch = func() {
			if _, err := s.h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
				t.Errorf("second request: the revoked access token is honored: %v", err)
			}
		}
		if _, err := s.h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
			t.Errorf("first request: the revoked access token is honored: %v", err)
		}
	})
	t.Run("refresh token", func(t *testing.T) {
		s := newOutageStore(t)
		s.primary.down = true
		s.revoke(t)
		s.primary.down = false
		s.primary.afterFetch = func() {
			if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
				t.Errorf("second request: the revoked refresh token is honored: %v", err)
			}
		}
		if _, err := s.h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
			t.Errorf("first request: the revoked refresh token is honored: %v", err)
		}
	})
	t.Run("authorization code", func(t *testing.T) {
		s := newOutageStore(t)
		s.primary.down = true
		if _, err := s.h.ConsumeAuthCode(ctx, s.code.Code); err != nil {
			t.Fatal(err)
		}
		s.primary.down = false
		s.primary.afterFetch = func() {
			if _, err := s.h.ConsumeAuthCode(ctx, s.code.Code); !errors.Is(err, ErrNotFound) {
				t.Errorf("second request: the spent code is honored: %v", err)
			}
		}
		if _, err := s.h.ConsumeAuthCode(ctx, s.code.Code); !errors.Is(err, ErrNotFound) {
			t.Errorf("first request: the spent code is honored: %v", err)
		}
	})
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

// TestHybridStore_WritesDuringOutage pins that what is written while the
// primary store cannot be reached is not lost and does not fail the
// request: a client registered, a code issued and a token pair saved then
// are found during the outage and after it. A refresh that spent its
// refresh token and then failed to store the new pair would leave the
// client with nothing.
func TestHybridStore_WritesDuringOutage(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()
	now := time.Now()

	s.primary.down = true
	client := &OAuthClient{ClientID: "outage-client"}
	code := &AuthCode{Code: "outage-new-code", ExpiresAt: now.Add(5 * time.Minute)}
	pair := &TokenInfo{ //nolint:gosec // test tokens, not credentials
		AccessToken: "outage-new-access", RefreshToken: "outage-new-refresh",
		ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	for op, err := range map[string]error{
		"SaveClient":       s.h.SaveClient(ctx, client),
		"SaveAuthCode":     s.h.SaveAuthCode(ctx, code),
		"SaveToken":        s.h.SaveToken(ctx, pair),
		"SaveRefreshToken": s.h.SaveRefreshToken(ctx, pair),
	} {
		if err != nil {
			t.Errorf("%s failed during the outage: %v", op, err)
		}
	}
	check := func(when string) {
		t.Helper()
		if _, err := s.h.GetClient(ctx, client.ClientID); err != nil {
			t.Errorf("%s: the client is not found: %v", when, err)
		}
		if _, err := s.h.GetToken(ctx, pair.AccessToken); err != nil {
			t.Errorf("%s: the access token is not found: %v", when, err)
		}
	}
	check("during the outage")
	s.primary.down = false
	check("after the outage")
	if _, err := s.h.ConsumeAuthCode(ctx, code.Code); err != nil {
		t.Errorf("after the outage the code is not found: %v", err)
	}
	if _, err := s.h.ConsumeRefreshToken(ctx, pair.RefreshToken); err != nil {
		t.Errorf("after the outage the refresh token is not found: %v", err)
	}
	if _, err := s.h.ConsumeRefreshToken(ctx, pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the refresh token was handed out twice: %v", err)
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
	if n := restarted.removed.size(); n != 2 {
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
	if restarted.removed.hasPending() {
		t.Error("removals are still waiting for the primary store after the warm-up")
	}
}

// TestHybridStore_RestartWithoutPrimary pins the case in which ToolMesh
// restarts while the primary store is down and runs on the file store
// alone, as it does when Redis does not answer at startup. A token issued
// before that restart and revoked after it must not come back when a later
// start reaches the primary store again, which still holds its copy. Tokens
// issued by the process that never reached the primary store need no
// record: the primary store never had them.
func TestHybridStore_RestartWithoutPrimary(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()
	s.primary.down = true

	alone, err := NewFileTokenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	alone.RememberRemovals()
	revokePair(t, alone, s.pair.AccessToken)
	now := time.Now()
	own := &TokenInfo{ //nolint:gosec // test tokens, not credentials
		AccessToken: "issued-alone-access", RefreshToken: "issued-alone-refresh",
		ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	_ = alone.SaveToken(ctx, own)
	_ = alone.SaveRefreshToken(ctx, own)
	revokePair(t, alone, own.AccessToken)
	if n := alone.removed.size(); n != 2 {
		t.Fatalf("%d removals remembered, want those of the pair issued before the restart", n)
	}

	s.primary.down = false
	again, err := NewFileTokenStore(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHybridTokenStore(s.primary, again)
	again.WarmUp(ctx, s.primary)
	if _, err := h.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked access token works again: %v", err)
	}
	if _, err := h.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the revoked refresh token works again: %v", err)
	}
	if len(s.primary.tokens) != 0 || len(s.primary.refreshes) != 0 {
		t.Errorf("the primary store still holds revoked tokens: %d access, %d refresh", len(s.primary.tokens), len(s.primary.refreshes))
	}
}

// TestHybridStore_RemovalReachesOtherProcesses pins that a removal made
// during an outage reaches the primary store without the token being
// presented to the process that remembers it. Another process on the same
// primary store, with a file store of its own, would otherwise go on
// honoring the copy.
func TestHybridStore_RemovalReachesOtherProcesses(t *testing.T) {
	s := newOutageStore(t)
	ctx := context.Background()
	// The warm-up at startup names the store to keep told.
	s.file.WarmUp(ctx, s.primary)

	otherFile, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := NewHybridTokenStore(s.primary, otherFile)
	if _, err := other.GetToken(ctx, s.pair.AccessToken); err != nil {
		t.Fatalf("test setup: the other process does not see the token: %v", err)
	}

	s.primary.down = true
	s.revoke(t)
	s.file.reconcile(ctx)
	if !s.file.removed.hasPending() {
		t.Fatal("the removals count as told although the primary store is down")
	}

	s.primary.down = false
	s.file.reconcile(ctx)
	if _, err := other.GetToken(ctx, s.pair.AccessToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other process honors the revoked access token: %v", err)
	}
	if _, err := other.ConsumeRefreshToken(ctx, s.pair.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("the other process honors the revoked refresh token: %v", err)
	}
	if s.file.removed.hasPending() {
		t.Error("removals are still waiting for the primary store after it was told")
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
	if n := s.file.removed.size(); n != 0 {
		t.Errorf("made-up tokens left %d remembered removals", n)
	}

	s.primary.down = false
	s.revoke(t)
	if n := s.file.removed.size(); n != 0 {
		t.Errorf("a revocation the primary store took part in left %d remembered removals", n)
	}

	// A removal is remembered until the entry expires, not longer.
	s.file.markRemoved(removedAccess, "short-lived", time.Now().Add(time.Minute))
	s.file.markRemoved(removedAccess, "already-expired", time.Now().Add(-time.Minute))
	if n := s.file.removed.size(); n != 1 {
		t.Fatalf("%d removals remembered, want the one that has not expired", n)
	}
	if !s.file.isRemoved(removedAccess, "short-lived") || s.file.isRemoved(removedRefresh, "short-lived") {
		t.Error("the removal is not found under its kind, or under another one")
	}
	s.file.removeExpired(time.Now().Add(2 * time.Minute))
	if n := s.file.removed.size(); n != 0 {
		t.Errorf("%d removals remembered after their entries expired", n)
	}
}
