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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// realMockCreds implements credentials.CredentialStore so we can exercise
// the production RestAuth type rather than the test-only mirror.
type realMockCreds struct {
	creds map[string]string
}

func (m *realMockCreds) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	v, ok := m.creds[name]
	if !ok {
		return "", credentials.ErrCredentialNotFound
	}
	return v, nil
}

func (m *realMockCreds) Healthy(_ context.Context) error { return nil }

func newQuietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRestAuth_InjectBearer(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{"API_TOKEN": "tok123"}}
	auth := NewRestAuth(AuthConfig{
		Type:       "bearer",
		Credential: "API_TOKEN",
	}, "https://example.com", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer tok123" {
		t.Errorf("Authorization = %q", got)
	}
}

func TestRestAuth_InjectBearer_MissingCredSkipped(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{}}
	auth := NewRestAuth(AuthConfig{
		Type:       "bearer",
		Credential: "MISSING",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("missing credential should be skipped without error, got %v", err)
	}
	if req.Header.Get("Authorization") != "" {
		t.Error("no auth header should be set when credential is missing")
	}
}

func TestRestAuth_InjectBasic(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{"U": "alice", "P": "pw"}}
	auth := NewRestAuth(AuthConfig{
		Type:               "basic",
		UsernameCredential: "U",
		PasswordCredential: "P",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(req.Header.Get("Authorization"), "Basic ") {
		t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
	}
}

func TestRestAuth_InjectBasic_MissingUsername(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{}}
	auth := NewRestAuth(AuthConfig{
		Type:               "basic",
		UsernameCredential: "MISSING",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("missing username should be skipped, got %v", err)
	}
}

func TestRestAuth_InjectAPIKey_Header(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{"K": "key-value"}}
	auth := NewRestAuth(AuthConfig{
		Type:       "apikey",
		Credential: "K",
		HeaderName: "X-Custom",
		Prefix:     "p-",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Custom"); got != "p-key-value" {
		t.Errorf("X-Custom = %q", got)
	}
}

func TestRestAuth_InjectAPIKey_Query(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{"K": "key-value"}}
	auth := NewRestAuth(AuthConfig{
		Type:       "apikey",
		Credential: "K",
		InjectInto: "query",
		QueryParam: "api_key",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/path", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("api_key"); got != "key-value" {
		t.Errorf("query api_key = %q", got)
	}
}

func TestRestAuth_InjectOAuth2(t *testing.T) {
	// Token endpoint that returns a valid token.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "o2-tok",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	creds := &realMockCreds{creds: map[string]string{"CID": "cid", "SEC": "sec"}}
	auth := NewRestAuth(AuthConfig{
		Type:                   "oauth2",
		ClientIDCredential:     "CID",
		ClientSecretCredential: "SEC",
		TokenURL:               srv.URL,
		Scopes:                 []string{"read", "write"},
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer o2-tok" {
		t.Errorf("Authorization = %q", got)
	}

	// Second call should use the cache.
	req2, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req2); err != nil {
		t.Fatal(err)
	}
	if got := req2.Header.Get("Authorization"); got != "Bearer o2-tok" {
		t.Errorf("cached Authorization = %q", got)
	}

	// HandleUnauthorized clears the token cache.
	if err := auth.HandleUnauthorized(context.Background()); err != nil {
		t.Errorf("HandleUnauthorized: %v", err)
	}
}

func TestRestAuth_InjectOAuth2_TokenEndpointFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad creds", http.StatusUnauthorized)
	}))
	defer srv.Close()

	creds := &realMockCreds{creds: map[string]string{"CID": "cid", "SEC": "sec"}}
	auth := NewRestAuth(AuthConfig{
		Type:                   "oauth2",
		ClientIDCredential:     "CID",
		ClientSecretCredential: "SEC",
		TokenURL:               srv.URL,
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected token endpoint failure")
	}
}

func TestRestAuth_InjectOAuth2_MissingClientID(t *testing.T) {
	creds := &realMockCreds{creds: map[string]string{}}
	auth := NewRestAuth(AuthConfig{ //nolint:gosec // test credentials, not real
		Type:                   "oauth2",
		ClientIDCredential:     "MISSING",
		ClientSecretCredential: "MISSING2",
		TokenURL:               "http://example.com/token",
	}, "", creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("missing client creds should be skipped, got %v", err)
	}
}

func TestRestAuth_InjectSession(t *testing.T) {
	// Login endpoint returns {"token": "s-tok"}.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": "s-tok"})
	}))
	defer srv.Close()

	creds := &realMockCreds{creds: map[string]string{"PW": "pw-value"}}
	auth := NewRestAuth(AuthConfig{
		Type: "session",
		Login: &SessionLogin{
			Path:    "/",
			Method:  "POST",
			Body:    map[string]string{"username": "alice", "password": "credential:PW"}, //nolint:gosec // test credential reference
			Extract: map[string]string{"tok": "$.token"},
		},
		Inject: []InjectRule{
			{Header: "X-Token", Value: "{{tok}}"},
		},
	}, srv.URL, creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Token"); got != "s-tok" {
		t.Errorf("X-Token = %q", got)
	}

	// HandleUnauthorized with re_login should succeed.
	auth.config.Refresh = &RefreshConfig{Action: "re_login"}
	if err := auth.HandleUnauthorized(context.Background()); err != nil {
		t.Errorf("HandleUnauthorized: %v", err)
	}
}

func TestRestAuth_InjectSession_LoginFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()

	creds := &realMockCreds{creds: map[string]string{}}
	auth := NewRestAuth(AuthConfig{
		Type: "session",
		Login: &SessionLogin{
			Path:   "/",
			Method: "POST",
			Body:   map[string]string{"u": "v"},
		},
		Inject: []InjectRule{{Header: "X-Token", Value: "{{tok}}"}},
	}, srv.URL, creds, newQuietLogger())

	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected login failure")
	}
}

func TestRestAuth_Unsupported(t *testing.T) {
	auth := NewRestAuth(AuthConfig{Type: "invalid"}, "", &realMockCreds{}, newQuietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Error("expected error for unsupported auth type")
	}
}

func TestRestAuth_NoAuth_Real(t *testing.T) {
	auth := NewRestAuth(AuthConfig{Type: ""}, "", &realMockCreds{}, newQuietLogger())
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://example.com/", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Errorf("no auth should succeed, got %v", err)
	}
}

func TestRestAuth_HandleUnauthorized_NoOp(t *testing.T) {
	auth := NewRestAuth(AuthConfig{Type: "bearer"}, "", &realMockCreds{}, newQuietLogger())
	if err := auth.HandleUnauthorized(context.Background()); err != nil {
		t.Errorf("bearer HandleUnauthorized: %v", err)
	}
}
