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

package mcp

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

// countingTokenStore counts the lookups revocation makes in a token store.
type countingTokenStore struct {
	auth.TokenStore
	lookups atomic.Int64
}

func (c *countingTokenStore) GetToken(ctx context.Context, token string) (*auth.TokenInfo, error) {
	c.lookups.Add(1)
	return c.TokenStore.GetToken(ctx, token)
}

func (c *countingTokenStore) ConsumeRefreshToken(ctx context.Context, token string) (*auth.TokenInfo, error) {
	c.lookups.Add(1)
	return c.TokenStore.ConsumeRefreshToken(ctx, token)
}

// RefreshTokenOf implements auth.PairLookup through the wrapped store.
func (c *countingTokenStore) RefreshTokenOf(ctx context.Context, accessToken string) (string, error) {
	c.lookups.Add(1)
	if pl, ok := c.TokenStore.(auth.PairLookup); ok {
		return pl.RefreshTokenOf(ctx, accessToken)
	}
	return "", auth.ErrNotFound
}

// Holds implements auth.TokenHolder through the wrapped store. It is the
// lookup in memory a request over the limit is allowed, so it is not
// counted.
func (c *countingTokenStore) Holds(token string) bool {
	holder, ok := c.TokenStore.(auth.TokenHolder)
	return ok && holder.Holds(token)
}

// TestRevoke_LimitedPerAddress pins that the revocation endpoint, which
// takes no credential and makes the token store look a token up on every
// request, lets one client address reach the store only a bounded number
// of times per minute with tokens nobody holds: the requests over the limit
// get 429 with Retry-After and cost no lookup. A real token is revoked all
// the same, from that address too: a sign-out must not fail because others
// at the address have used the limit up.
func TestRevoke_LimitedPerAddress(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fs, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := &countingTokenStore{TokenStore: fs}
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	srv := NewServer(handler, loginTestConfig(), logger, store, nil, nil, auth.NewLocalDCRRateLimiter(), nil, nil)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	revoke := func(remote, token string) *httptest.ResponseRecorder {
		form := url.Values{oauthRevokeToken: {token}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pathRevoke, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}

	ctx := context.Background()
	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken: generateID(), RefreshToken: generateID(), ClientID: "c1", UserID: testLoginOwner,
		ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	_ = fs.SaveToken(ctx, ti)
	_ = fs.SaveRefreshToken(ctx, ti)

	const flooder, other = "203.0.113.40:1234", "203.0.113.41:1234"
	// Find the limit by sending unknown tokens until the first refusal.
	var limit int
	for limit = 0; limit < 10_000; limit++ {
		if w := revoke(flooder, generateID()); w.Code != http.StatusOK {
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: status %d, want 200 or 429", limit+1, w.Code)
			}
			if w.Header().Get("Retry-After") == "" {
				t.Error("the refusal names no Retry-After")
			}
			break
		}
	}
	if limit < 10 || limit >= 10_000 {
		t.Fatalf("the limit let %d requests through; want a bounded number a client never needs", limit)
	}

	lookups := store.lookups.Load()
	for range 20 {
		if w := revoke(flooder, generateID()); w.Code != http.StatusTooManyRequests {
			t.Fatalf("request over the limit: status %d, want 429", w.Code)
		}
	}
	if got := store.lookups.Load(); got != lookups {
		t.Errorf("refused requests reached the token store: %d lookups", got-lookups)
	}

	// Another address is served.
	if w := revoke(other, generateID()); w.Code != http.StatusOK {
		t.Fatalf("another address: status %d, want 200", w.Code)
	}

	// The real token is revoked from the address that is over its limit.
	if w := revoke(flooder, ti.AccessToken); w.Code != http.StatusOK {
		t.Fatalf("real token from the address over its limit: status %d, want 200", w.Code)
	}
	if _, err := fs.GetToken(ctx, ti.AccessToken); err == nil {
		t.Error("the access token survived its revocation")
	}
	if _, err := fs.ConsumeRefreshToken(ctx, ti.RefreshToken); err == nil {
		t.Error("the refresh token survived the revocation of its access token")
	}
}
