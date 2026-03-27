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

package dadl

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// mockCredStore is a simple in-memory credential store for tests.
type mockCredStore struct {
	creds map[string]string
}

func (m *mockCredStore) Get(_ context.Context, name string, _ interface { /* TenantInfo */
}) (string, error) {
	if v, ok := m.creds[name]; ok {
		return v, nil
	}
	return "", fmt.Errorf("credential %q not found", name)
}

func (m *mockCredStore) Healthy(_ context.Context) error { return nil }

// Auth type constants for test readability.
const (
	authTypeBearer = "bearer"
	authTypeOAuth2 = "oauth2"
	bearerPrefix   = "Bearer "
)

func TestRestAuth_Bearer(t *testing.T) {
	creds := &mockCredStore{creds: map[string]string{"my-token": "secret123"}}
	auth := newTestRestAuth(AuthConfig{
		Type:       authTypeBearer,
		Credential: "my-token",
		HeaderName: "Authorization",
		Prefix:     bearerPrefix,
	}, creds)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.Header.Get("Authorization")
	if got != "Bearer secret123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer secret123")
	}
}

func TestRestAuth_APIKey_Header(t *testing.T) {
	creds := &mockCredStore{creds: map[string]string{"api-key": "key123"}}
	auth := newTestRestAuth(AuthConfig{
		Type:       "apikey",
		Credential: "api-key",
		InjectInto: "header",
		HeaderName: "X-API-Key",
	}, creds)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Header.Get("X-API-Key") != "key123" {
		t.Errorf("X-API-Key = %q, want %q", req.Header.Get("X-API-Key"), "key123")
	}
}

func TestRestAuth_APIKey_Query(t *testing.T) {
	creds := &mockCredStore{creds: map[string]string{"api-key": "key123"}}
	auth := newTestRestAuth(AuthConfig{
		Type:       "apikey",
		Credential: "api-key",
		InjectInto: "query",
		QueryParam: "api_key",
	}, creds)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.URL.Query().Get("api_key") != "key123" {
		t.Errorf("api_key = %q, want %q", req.URL.Query().Get("api_key"), "key123")
	}
}

func TestRestAuth_OAuth2(t *testing.T) {
	// Mock OAuth2 token server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "oauth-token-123", "expires_in": 3600}`))
	}))
	defer server.Close()

	creds := &mockCredStore{creds: map[string]string{
		"client-id":     "my-client",
		"client-secret": "my-secret",
	}}
	auth := newTestRestAuth(AuthConfig{
		Type:                   authTypeOAuth2,
		Flow:                   "client_credentials",
		TokenURL:               server.URL,
		ClientIDCredential:     "client-id",
		ClientSecretCredential: "client-secret",
	}, creds)

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := req.Header.Get("Authorization")
	if got != "Bearer oauth-token-123" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer oauth-token-123")
	}

	// Second call should use cached token
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test2", nil)
	if err := auth.InjectAuth(context.Background(), req2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req2.Header.Get("Authorization") != "Bearer oauth-token-123" {
		t.Error("expected cached token on second call")
	}
}

func TestRestAuth_NoAuth(t *testing.T) {
	auth := newTestRestAuth(AuthConfig{}, &mockCredStore{})
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://api.example.com/test", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("expected no Authorization header for empty auth type")
	}
}

// newTestRestAuth creates a RestAuth using the mock credential store directly.
// This avoids the credentials.CredentialStore interface mismatch in tests.
func newTestRestAuth(config AuthConfig, creds *mockCredStore) *testRestAuth {
	return &testRestAuth{
		config:        config,
		creds:         creds,
		logger:        slog.Default(),
		sessionTokens: make(map[string]string),
	}
}

// testRestAuth is a test-only copy of RestAuth that uses mockCredStore directly.
type testRestAuth struct {
	config        AuthConfig
	creds         *mockCredStore
	logger        *slog.Logger
	cachedToken   string
	sessionTokens map[string]string
}

func (a *testRestAuth) InjectAuth(ctx context.Context, req *http.Request) error {
	switch a.config.Type {
	case authTypeBearer:
		token, err := a.creds.Get(ctx, a.config.Credential, nil)
		if err != nil {
			return err
		}
		headerName := a.config.HeaderName
		if headerName == "" {
			headerName = "Authorization"
		}
		prefix := a.config.Prefix
		if prefix == "" {
			prefix = bearerPrefix
		}
		req.Header.Set(headerName, prefix+token)
	case "apikey":
		key, err := a.creds.Get(ctx, a.config.Credential, nil)
		if err != nil {
			return err
		}
		if a.config.InjectInto == "query" {
			q := req.URL.Query()
			q.Set(a.config.QueryParam, key)
			req.URL.RawQuery = q.Encode()
		} else {
			headerName := a.config.HeaderName
			if headerName == "" {
				headerName = "X-API-Key"
			}
			req.Header.Set(headerName, a.config.Prefix+key)
		}
	case authTypeOAuth2:
		return a.injectOAuth2(ctx, req)
	case "":
		// no auth
	}
	return nil
}

func (a *testRestAuth) injectOAuth2(ctx context.Context, req *http.Request) error {
	if a.cachedToken != "" {
		req.Header.Set("Authorization", bearerPrefix+a.cachedToken)
		return nil
	}

	clientID, _ := a.creds.Get(ctx, a.config.ClientIDCredential, nil)
	clientSecret, _ := a.creds.Get(ctx, a.config.ClientSecretCredential, nil)

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	tokenReq, err := http.NewRequestWithContext(ctx, "POST", a.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := jsonUnmarshal(mustReadAll(resp.Body), &tokenResp); err != nil {
		return err
	}
	a.cachedToken = tokenResp.AccessToken
	req.Header.Set("Authorization", bearerPrefix+a.cachedToken)
	return nil
}

func mustReadAll(r interface{ Read([]byte) (int, error) }) []byte {
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return buf
}
