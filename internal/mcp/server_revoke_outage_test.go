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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestRevoke_HoldsAfterRedisOutage pins revocation with Redis and the file
// store together: a token revoked while Redis answers every command with
// an error stays revoked once Redis answers again, although Redis kept the
// token, and the token is then removed from Redis.
func TestRevoke_HoldsAfterRedisOutage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	fs, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewHybridTokenStore(auth.NewRedisTokenStore(rdb), fs)

	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	srv := NewServer(handler, loginTestConfig(), logger, store, nil, nil, auth.NewLocalDCRRateLimiter(), nil, nil)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	ctx := context.Background()
	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken: generateID(), RefreshToken: generateID(), ClientID: "c1", UserID: testLoginOwner,
		ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	if err := store.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	accessKey, refreshKey := "oauth:token:"+ti.AccessToken, "oauth:refresh:"+ti.RefreshToken

	mr.SetError("LOADING Redis is loading the dataset in memory")
	form := url.Values{oauthRevokeToken: {ti.AccessToken}}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, pathRevoke, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke during the outage: status %d", w.Code)
	}

	mr.SetError("")
	if !mr.Exists(accessKey) || !mr.Exists(refreshKey) {
		t.Fatal("test setup: Redis was expected to keep both tokens through the outage")
	}
	if _, err := store.GetToken(ctx, ti.AccessToken); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("the revoked access token is honored again after the outage: %v", err)
	}
	if _, err := store.ConsumeRefreshToken(ctx, ti.RefreshToken); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("the revoked refresh token is honored again after the outage: %v", err)
	}
	if mr.Exists(accessKey) || mr.Exists(refreshKey) {
		t.Error("Redis still holds a revoked token after it was presented")
	}
}
