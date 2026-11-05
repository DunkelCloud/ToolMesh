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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

const (
	refreshTestRole = "admin"
	refreshTestUser = "alice"
)

// issuePair stores an access and refresh token for userID with the given
// roles, as a login some time ago would have, and returns both.
func (ts *loginTestServer) issuePair(t *testing.T, userID string, roles []string) (access, refresh string) {
	t.Helper()
	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken:      generateID(),
		RefreshToken:     generateID(),
		ClientID:         ts.clientID,
		UserID:           userID,
		CompanyID:        "old-company",
		Plan:             "old-plan",
		Roles:            roles,
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(24 * time.Hour),
	}
	ctx := context.Background()
	if err := ts.srv.tokenStore.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	if err := ts.srv.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	return ti.AccessToken, ti.RefreshToken
}

func (ts *loginTestServer) refreshGrant(refresh string) *httptest.ResponseRecorder {
	return ts.token(url.Values{
		oauthGrantType:    {oauthRefreshToken},
		oauthRefreshToken: {refresh},
		oauthClientID:     {ts.clientID},
	})
}

// refreshedToken runs a refresh grant that must succeed and returns the
// stored TokenInfo of the new access token.
func (ts *loginTestServer) refreshedToken(t *testing.T, refresh string) *auth.TokenInfo {
	t.Helper()
	w := ts.refreshGrant(refresh)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: status %d, body %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	access, _ := resp["access_token"].(string)
	ti, err := ts.srv.tokenStore.GetToken(context.Background(), access)
	if err != nil {
		t.Fatalf("new access token not stored: %v", err)
	}
	return ti
}

// writeUsers builds a UserStore from entries "name" -> password_hash.
func writeUsers(t *testing.T, users map[string]string, roles string) *auth.UserStore {
	t.Helper()
	content := "users:\n"
	for name, hash := range users {
		content += fmt.Sprintf("  - username: %s\n    password_hash: %q\n    company: example\n    plan: team\n    roles: [%s]\n", name, hash, roles)
	}
	path := filepath.Join(t.TempDir(), "users.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := auth.NewUserStore(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func bcryptHash(t *testing.T, pw string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestRefresh_TakesCurrentSinglePasswordIdentity(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	_, refresh := ts.issuePair(t, testLoginOwner, []string{refreshTestRole})

	ts.srv.cfg.AuthRoles = "viewer"
	ts.srv.cfg.AuthPlan = "free"
	ti := ts.refreshedToken(t, refresh)
	if !slices.Equal(ti.Roles, []string{"viewer"}) || ti.Plan != "free" || ti.CompanyID != userDefault {
		t.Errorf("refreshed token: roles %v plan %q company %q; want the current configuration", ti.Roles, ti.Plan, ti.CompanyID)
	}

	// A token of another user than the configured owner is not renewed.
	_, other := ts.issuePair(t, "former-owner", []string{refreshTestRole})
	if w := ts.refreshGrant(other); w.Code != http.StatusBadRequest {
		t.Errorf("refresh for a user who is no longer the owner: status %d, want 400", w.Code)
	}
}

func TestRefresh_ChecksUsersYAML(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{users: map[string]string{refreshTestUser: "pw-alice"}})

	// Current roles from users.yaml win over the roles in the old token.
	_, refresh := ts.issuePair(t, refreshTestUser, []string{"superuser"})
	ti := ts.refreshedToken(t, refresh)
	if !slices.Equal(ti.Roles, []string{refreshTestRole}) {
		t.Errorf("refreshed roles = %v, want [admin] from users.yaml", ti.Roles)
	}

	// Removed from users.yaml: no renewal.
	_, refresh = ts.issuePair(t, refreshTestUser, []string{refreshTestRole})
	ts.srv.userStore = writeUsers(t, map[string]string{"bob": bcryptHash(t, "pw-bob")}, refreshTestRole)
	if w := ts.refreshGrant(refresh); w.Code != http.StatusBadRequest {
		t.Errorf("refresh for a removed user: status %d, want 400", w.Code)
	}

	// Disabled by an unusable password_hash: no renewal either.
	ts.srv.userStore = writeUsers(t, map[string]string{refreshTestUser: "!"}, refreshTestRole)
	_, refresh = ts.issuePair(t, refreshTestUser, []string{refreshTestRole})
	if w := ts.refreshGrant(refresh); w.Code != http.StatusBadRequest {
		t.Errorf("refresh for a disabled user: status %d, want 400", w.Code)
	}
}

// TestBearer_TokenOfRemovedUserRefused pins that an access token stops
// working as soon as its user is no longer configured.
func TestBearer_TokenOfRemovedUserRefused(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{users: map[string]string{refreshTestUser: "pw-alice"}})
	access, _ := ts.issuePair(t, refreshTestUser, []string{refreshTestRole})
	if w := ts.mcpCall("Bearer " + access); w.Code != http.StatusOK {
		t.Fatalf("token of a configured user: status %d, want 200", w.Code)
	}
	ts.srv.userStore = writeUsers(t, map[string]string{"bob": bcryptHash(t, "pw-bob")}, refreshTestRole)
	if w := ts.mcpCall("Bearer " + access); w.Code != http.StatusUnauthorized {
		t.Errorf("token of a removed user: status %d, want 401", w.Code)
	}
}

func (ts *loginTestServer) revoke(token string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pathRevoke, strings.NewReader(url.Values{"token": {token}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

func TestRevoke(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	t.Run("refresh token revokes the pair", func(t *testing.T) {
		access, refresh := ts.issuePair(t, testLoginOwner, nil)
		if w := ts.revoke(refresh); w.Code != http.StatusOK {
			t.Fatalf("revoke: status %d", w.Code)
		}
		if w := ts.refreshGrant(refresh); w.Code != http.StatusBadRequest {
			t.Errorf("revoked refresh token still works: status %d", w.Code)
		}
		if w := ts.mcpCall("Bearer " + access); w.Code != http.StatusUnauthorized {
			t.Errorf("access token of a revoked pair still works: status %d", w.Code)
		}
	})

	t.Run("access token revokes the pair", func(t *testing.T) {
		access, refresh := ts.issuePair(t, testLoginOwner, nil)
		if w := ts.revoke(access); w.Code != http.StatusOK {
			t.Fatalf("revoke: status %d", w.Code)
		}
		if w := ts.mcpCall("Bearer " + access); w.Code != http.StatusUnauthorized {
			t.Errorf("revoked access token still works: status %d", w.Code)
		}
		if w := ts.refreshGrant(refresh); w.Code != http.StatusBadRequest {
			t.Errorf("refresh token of a revoked pair still works: status %d", w.Code)
		}
	})

	t.Run("unknown token is 200", func(t *testing.T) {
		if w := ts.revoke("not-a-token"); w.Code != http.StatusOK {
			t.Errorf("status %d, want 200", w.Code)
		}
	})

	t.Run("missing token is 400", func(t *testing.T) {
		if w := ts.revoke(""); w.Code != http.StatusBadRequest {
			t.Errorf("status %d, want 400", w.Code)
		}
	})

	t.Run("metadata advertises the endpoint", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/oauth-authorization-server", nil)
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		var meta map[string]any
		if err := json.NewDecoder(w.Body).Decode(&meta); err != nil {
			t.Fatal(err)
		}
		if got, _ := meta["revocation_endpoint"].(string); !strings.HasSuffix(got, pathRevoke) {
			t.Errorf("revocation_endpoint = %q", got)
		}
	})
}
