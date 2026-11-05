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
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

// TestRevoke_FileStoreExpiredAccessToken pins revocation parity on the file
// store, which drops an expired access token on lookup: revoking with such a
// token must still end its refresh token.
func TestRevoke_FileStoreExpiredAccessToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fs, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	srv := NewServer(handler, loginTestConfig(), logger, fs, nil, nil, auth.NewLocalDCRRateLimiter(), nil, metrics.New(metrics.Options{}))
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	post := func(path string, form url.Values) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = testLoginAddr
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}

	ctx := context.Background()
	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken: generateID(), RefreshToken: generateID(), ClientID: "c1", UserID: testLoginOwner,
		ExpiresAt: now.Add(-time.Minute), RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	_ = fs.SaveToken(ctx, ti)
	_ = fs.SaveRefreshToken(ctx, ti)
	// The expired access token is dropped on lookup, as on any request.
	if _, err := fs.GetToken(ctx, ti.AccessToken); err == nil {
		t.Fatal("expected the file store to refuse the expired access token")
	}

	if code := post(pathRevoke, url.Values{oauthRevokeToken: {ti.AccessToken}}); code != http.StatusOK {
		t.Fatalf("revoke: status %d", code)
	}
	code := post("/token", url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {ti.RefreshToken}, oauthClientID: {"c1"}})
	if code == http.StatusOK {
		t.Error("refresh token survived revocation with its expired access token")
	}
}
