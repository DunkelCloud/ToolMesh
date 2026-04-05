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

// fakePrimary is a minimal in-memory TokenStore for exercising the hybrid store.
type fakePrimary struct {
	clients     map[string]*OAuthClient
	codes       map[string]*AuthCode
	tokens      map[string]*TokenInfo
	refreshes   map[string]*TokenInfo
	failGet     bool
	failConsume bool
}

func newFakePrimary() *fakePrimary {
	return &fakePrimary{
		clients:   map[string]*OAuthClient{},
		codes:     map[string]*AuthCode{},
		tokens:    map[string]*TokenInfo{},
		refreshes: map[string]*TokenInfo{},
	}
}

func (f *fakePrimary) SaveClient(_ context.Context, c *OAuthClient) error {
	f.clients[c.ClientID] = c
	return nil
}
func (f *fakePrimary) GetClient(_ context.Context, id string) (*OAuthClient, error) {
	if f.failGet {
		return nil, errors.New("primary down")
	}
	c, ok := f.clients[id]
	if !ok {
		return nil, ErrNotFound
	}
	return c, nil
}
func (f *fakePrimary) SaveAuthCode(_ context.Context, ac *AuthCode) error {
	f.codes[ac.Code] = ac
	return nil
}
func (f *fakePrimary) ConsumeAuthCode(_ context.Context, code string) (*AuthCode, error) {
	if f.failConsume {
		return nil, errors.New("primary down")
	}
	ac, ok := f.codes[code]
	if !ok {
		return nil, ErrNotFound
	}
	delete(f.codes, code)
	return ac, nil
}
func (f *fakePrimary) SaveToken(_ context.Context, ti *TokenInfo) error {
	f.tokens[ti.AccessToken] = ti
	return nil
}
func (f *fakePrimary) GetToken(_ context.Context, t string) (*TokenInfo, error) {
	if f.failGet {
		return nil, errors.New("primary down")
	}
	ti, ok := f.tokens[t]
	if !ok {
		return nil, ErrNotFound
	}
	return ti, nil
}
func (f *fakePrimary) DeleteToken(_ context.Context, t string) error {
	delete(f.tokens, t)
	return nil
}
func (f *fakePrimary) SaveRefreshToken(_ context.Context, ti *TokenInfo) error {
	f.refreshes[ti.RefreshToken] = ti
	return nil
}
func (f *fakePrimary) ConsumeRefreshToken(_ context.Context, t string) (*TokenInfo, error) {
	if f.failConsume {
		return nil, errors.New("primary down")
	}
	ti, ok := f.refreshes[t]
	if !ok {
		return nil, ErrNotFound
	}
	delete(f.refreshes, t)
	return ti, nil
}

func newHybridTestStore(t *testing.T) (*HybridTokenStore, *fakePrimary, *FileTokenStore) {
	t.Helper()
	fs, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := newFakePrimary()
	return NewHybridTokenStore(p, fs), p, fs
}

func TestHybridStore_ClientFallback(t *testing.T) {
	h, p, fs := newHybridTestStore(t)
	ctx := context.Background()

	c := &OAuthClient{ClientID: "c1"}
	if err := h.SaveClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Both stores should have it.
	if _, err := p.GetClient(ctx, "c1"); err != nil {
		t.Error("primary missing client")
	}
	if _, err := fs.GetClient(ctx, "c1"); err != nil {
		t.Error("file missing client")
	}

	got, err := h.GetClient(ctx, "c1")
	if err != nil || got.ClientID != "c1" {
		t.Errorf("hybrid GetClient: %v %v", got, err)
	}

	// Primary fails → fallback to file store.
	p.failGet = true
	got, err = h.GetClient(ctx, "c1")
	if err != nil || got == nil {
		t.Errorf("fallback failed: %v", err)
	}
}

func TestHybridStore_AuthCode(t *testing.T) {
	h, _, _ := newHybridTestStore(t)
	ctx := context.Background()
	ac := &AuthCode{Code: "abc", ClientID: "c"}
	if err := h.SaveAuthCode(ctx, ac); err != nil {
		t.Fatal(err)
	}
	got, err := h.ConsumeAuthCode(ctx, "abc")
	if err != nil || got.Code != "abc" {
		t.Errorf("consume: %v %v", got, err)
	}
}

func TestHybridStore_AuthCodeFallback(t *testing.T) {
	h, p, _ := newHybridTestStore(t)
	ctx := context.Background()

	_ = h.SaveAuthCode(ctx, &AuthCode{Code: "abc", ClientID: "c"})
	p.failConsume = true

	got, err := h.ConsumeAuthCode(ctx, "abc")
	if err != nil || got == nil {
		t.Errorf("fallback consume: %v", err)
	}
}

func TestHybridStore_TokenRoundTrip(t *testing.T) {
	h, _, _ := newHybridTestStore(t)
	ctx := context.Background()

	ti := &TokenInfo{AccessToken: "a", ExpiresAt: time.Now().Add(time.Hour)}
	if err := h.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	if _, err := h.GetToken(ctx, "a"); err != nil {
		t.Errorf("GetToken: %v", err)
	}
	if err := h.DeleteToken(ctx, "a"); err != nil {
		t.Errorf("DeleteToken: %v", err)
	}
}

func TestHybridStore_RefreshTokenRoundTrip(t *testing.T) {
	h, _, _ := newHybridTestStore(t)
	ctx := context.Background()

	ti := &TokenInfo{RefreshToken: "r", RefreshExpiresAt: time.Now().Add(time.Hour)}
	if err := h.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	got, err := h.ConsumeRefreshToken(ctx, "r")
	if err != nil || got == nil {
		t.Errorf("consume refresh: %v %v", got, err)
	}
}

func TestHybridStore_GetTokenFallback(t *testing.T) {
	h, p, _ := newHybridTestStore(t)
	ctx := context.Background()

	_ = h.SaveToken(ctx, &TokenInfo{AccessToken: "t", ExpiresAt: time.Now().Add(time.Hour)})
	p.failGet = true

	if _, err := h.GetToken(ctx, "t"); err != nil {
		t.Errorf("fallback GetToken: %v", err)
	}
}

func TestHybridStore_RefreshTokenFallback(t *testing.T) {
	h, p, _ := newHybridTestStore(t)
	ctx := context.Background()

	_ = h.SaveRefreshToken(ctx, &TokenInfo{RefreshToken: "r", RefreshExpiresAt: time.Now().Add(time.Hour)})
	p.failConsume = true

	if _, err := h.ConsumeRefreshToken(ctx, "r"); err != nil {
		t.Errorf("fallback ConsumeRefreshToken: %v", err)
	}
}
