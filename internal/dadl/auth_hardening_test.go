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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const (
	hardeningSecret     = "client-secret-value" //nolint:gosec // test fixture, not a credential
	hardeningSecretName = "csecret"
	hardeningBase       = "https://api.example.com"
	hardeningLogin      = "/signin"
)

// mapCreds is a minimal CredentialStore backed by a map.
type mapCreds map[string]string

func (m mapCreds) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return "", credentials.ErrCredentialNotFound
}

func (m mapCreds) Healthy(context.Context) error { return nil }

// TestRestAuth_TokenRequestDoesNotFollowRedirects pins that a 307/308 from the
// token endpoint does not re-send the form body (client_secret) elsewhere.
func TestRestAuth_TokenRequestDoesNotFollowRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		var leaked atomic.Int32
		other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), hardeningSecret) {
				leaked.Add(1)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
		}))
		tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, other.URL+"/token", status)
		}))

		auth := NewRestAuth(AuthConfig{
			Type:                   authTypeOAuth2,
			TokenURL:               tokenSrv.URL + "/token",
			ClientIDCredential:     testOAuth2CID,
			ClientSecretCredential: hardeningSecretName,
		}, hardeningBase, mapCreds{testOAuth2CID: "id", hardeningSecretName: hardeningSecret}, slog.Default())

		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, hardeningBase+"/x", nil)
		err := auth.InjectAuth(context.Background(), req)
		if err == nil {
			t.Errorf("status %d: expected the token request to fail on the redirect", status)
		}
		if leaked.Load() != 0 {
			t.Errorf("status %d: client_secret was re-sent to the redirect target", status)
		}
		tokenSrv.Close()
		other.Close()
	}
}

// TestRestAuth_SetTransportIsUsed pins that token requests go through the
// transport the owner installs (the adapter's SSRF-safe one).
func TestRestAuth_SetTransportIsUsed(t *testing.T) {
	var used atomic.Int32
	auth := NewRestAuth(AuthConfig{ //nolint:gosec // test fixture with credential names, not credentials
		Type:                   authTypeOAuth2,
		TokenURL:               "https://token.example.com/token",
		ClientIDCredential:     testOAuth2CID,
		ClientSecretCredential: hardeningSecretName,
	}, hardeningBase, mapCreds{testOAuth2CID: "id", hardeningSecretName: hardeningSecret}, slog.Default())
	auth.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		used.Add(1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"access_token":"t","expires_in":3600}`)),
			Request:    r,
		}, nil
	}))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, hardeningBase+"/x", nil)
	if err := auth.InjectAuth(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if used.Load() != 1 {
		t.Errorf("installed transport used %d times, want 1", used.Load())
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSessionLoginURL(t *testing.T) {
	cases := []struct {
		base, path string
		want       string
		wantErr    bool
	}{
		{hardeningBase, "/api/login", "https://api.example.com/api/login", false},
		{"https://api.example.com/v2", hardeningLogin, "https://api.example.com/v2/signin", false},
		{"https://api.example.com:8443", hardeningLogin, "https://api.example.com:8443/signin", false},
		{hardeningBase, "@attacker.example/x", "", true},
		{hardeningBase, ".attacker.example/x", "", true},
		{hardeningBase, ":9999/x", "", true},
		{hardeningBase, "login", "", true},
		{"https://user@api.example.com", hardeningLogin, "https://user@api.example.com/signin", false},
	}
	for _, tc := range cases {
		got, err := sessionLoginURL(tc.base, tc.path)
		if tc.wantErr {
			if err == nil {
				t.Errorf("sessionLoginURL(%q, %q) = %q, want error", tc.base, tc.path, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("sessionLoginURL(%q, %q) = %q, %v; want %q", tc.base, tc.path, got, err, tc.want)
		}
	}
}

// TestRestAuth_SessionLoginStaysOnBaseHost pins that a login path which would
// change the host never sends the login request (and its credentials).
func TestRestAuth_SessionLoginStaysOnBaseHost(t *testing.T) {
	var hits atomic.Int32
	auth := NewRestAuth(AuthConfig{ //nolint:gosec // test fixture with credential names, not credentials
		Type: authTypeSession,
		Login: &SessionLogin{
			Method: http.MethodPost,
			Path:   "@attacker.example/signin",
			Body:   map[string]any{"password": "credential:pw"}, //nolint:gosec // credential reference, not a credential
		},
	}, hardeningBase, mapCreds{"pw": hardeningSecret}, slog.Default())
	auth.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		hits.Add(1)
		return nil, io.ErrUnexpectedEOF
	}))
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, hardeningBase+"/x", nil)
	if err := auth.InjectAuth(context.Background(), req); err == nil {
		t.Fatal("expected the login to be refused")
	}
	if hits.Load() != 0 {
		t.Errorf("login request was sent %d times, want 0", hits.Load())
	}
}

// TestSessionLoginURL_Forms pins the login URL rules across bypass attempts
// and the base_url forms that must keep working, userinfo included.
func TestSessionLoginURL_Forms(t *testing.T) {
	const formsLogin = "/login"
	cases := []struct {
		name, base, path string
		wantErr          bool
		wantURL          string
	}{
		// bypass attempts: all must be rejected or stay on the host
		{"at host", hardeningBase, "@evil.example/login", true, ""},
		{"dot host", hardeningBase, ".evil.example/login", true, ""},
		{"port change", hardeningBase, ":8443/login", true, ""},
		{"backslash host", hardeningBase, "\\evil.example/login", true, ""},
		{"encoded slashes", hardeningBase, "%2F%2Fevil.example/login", true, ""},
		{"encoded at", hardeningBase, "%40evil.example/login", true, ""},
		{"absolute url", hardeningBase, "https://evil.example/login", true, ""},
		{"double slash stays", hardeningBase, "//evil.example/login", false, "https://api.example.com//evil.example/login"},
		{"query only stays", hardeningBase, "?next=//evil.example", false, "https://api.example.com?next=//evil.example"},
		{"fullwidth dot host", hardeningBase, "\uff0eevil.example/login", true, ""},
		{"base with path, dot segments", "https://api.example.com/v1", "/../admin/login", false, "https://api.example.com/v1/../admin/login"},
		{"base with path, sibling prefix", "https://api.example.com/v1", "x/login", false, "https://api.example.com/v1x/login"},
		// regression candidates
		{"base with userinfo", "https://user:pw@api.example.com", formsLogin, false, "https://user:pw@api.example.com/login"},
		{"base upper host", "https://API.example.com", formsLogin, false, "https://API.example.com/login"},
		{"base with trailing slash", "https://api.example.com/", formsLogin, false, "https://api.example.com//login"},
		{"base with query", "https://api.example.com/?x=1", formsLogin, false, "https://api.example.com/?x=1/login"},
		{"empty base", "", "https://evil.example/login", true, ""},
	}
	for _, c := range cases {
		got, err := sessionLoginURL(c.base, c.path)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: sessionLoginURL(%q, %q) = %q, want error", c.name, c.base, c.path, got)
			}
			continue
		}
		if err != nil || got != c.wantURL {
			t.Errorf("%s: sessionLoginURL(%q, %q) = %q, %v; want %q", c.name, c.base, c.path, got, err, c.wantURL)
		}
	}
}
