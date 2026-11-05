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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

const consentEvilRedirect = "https://evil.example/cb"

// registerClient registers a client with one redirect URI and returns the
// response recorder.
func registerClient(t *testing.T, mux *http.ServeMux, name, redirectURI string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"client_name": name, "redirect_uris": []string{redirectURI}})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func registeredClientID(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode register response (status %d): %v", w.Code, err)
	}
	id, _ := resp[oauthClientID].(string)
	if id == "" {
		t.Fatalf("no client_id (status %d)", w.Code)
	}
	return id
}

// TestAuthorize_LoginPageNamesClientAndRedirectHost pins that the login page
// shows where the authorization goes and marks the client name as
// self-declared, escaped.
func TestAuthorize_LoginPageNamesClientAndRedirectHost(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	clientID := registeredClientID(t, registerClient(t, ts.mux, "<script>alert(1)</script>Claude", consentEvilRedirect))

	q := url.Values{
		oauthClientID:      {clientID},
		oauthRedirectURI:   {consentEvilRedirect},
		oauthCodeChallenge: {testLoginChallenge},
		oauthState:         {"s1"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`<p class="host">evil.example</p>`, "has not verified", `name="confirm_host" value="evil.example" required`} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Error("client name is not escaped")
	}
}

// TestAuthorize_RequiresRedirectConfirmation pins that the right password
// alone does not complete the authorization: the user must confirm the
// redirect host shown on the page.
func TestAuthorize_RequiresRedirectConfirmation(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	clientID := registeredClientID(t, registerClient(t, ts.mux, "x", consentEvilRedirect))

	post := func(confirm string) *httptest.ResponseRecorder {
		form := url.Values{
			testFormUsername:   {testLoginOwner},
			testFormPassword:   {testLoginSecret},
			oauthClientID:      {clientID},
			oauthRedirectURI:   {consentEvilRedirect},
			oauthState:         {"s1"},
			oauthCodeChallenge: {testLoginChallenge},
		}
		if confirm != "" {
			form.Set(oauthConfirmHost, confirm)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		return w
	}

	for _, confirm := range []string{"", "other.example"} {
		w := post(confirm)
		if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
			t.Errorf("confirm %q: status %d, Location %q; want 400 without redirect", confirm, w.Code, w.Header().Get("Location"))
		}
	}
	w := post("evil.example")
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), consentEvilRedirect+"?code=") {
		t.Errorf("confirmed login: status %d, Location %q; want 302 to the redirect URI", w.Code, w.Header().Get("Location"))
	}
}

func TestRegister_RedirectHostAllowlist(t *testing.T) {
	cfg := loginTestConfig()
	cfg.OAuthRedirectHosts = []string{"claude.ai", "*.example.org"}
	ts := newLoginTestServerNoClient(t, cfg)

	cases := []struct {
		uri  string
		want int
	}{
		{"https://claude.ai/api/mcp/auth_callback", http.StatusCreated},
		{"https://app.example.org/cb", http.StatusCreated},
		{"http://localhost:33418/callback", http.StatusCreated},
		{"http://127.0.0.1:8976/cb", http.StatusCreated},
		{consentEvilRedirect, http.StatusBadRequest},
		{"https://example.org/cb", http.StatusBadRequest},
		{"https://claude.ai.evil.example/cb", http.StatusBadRequest},
	}
	for _, tc := range cases {
		ts.redis.FlushAll() // keep the per-address registration limit out of the way
		if w := registerClient(t, ts.mux, "x", tc.uri); w.Code != tc.want {
			t.Errorf("register %s: status %d, want %d", tc.uri, w.Code, tc.want)
		}
	}
}

// TestAuthorize_RedirectHostAllowlistCoversOldClients pins that a client
// registered before the allowlist was set cannot use a host outside it.
func TestAuthorize_RedirectHostAllowlistCoversOldClients(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	clientID := registeredClientID(t, registerClient(t, ts.mux, "x", consentEvilRedirect))
	ts.srv.cfg.OAuthRedirectHosts = []string{"claude.ai"}

	q := url.Values{
		oauthClientID:      {clientID},
		oauthRedirectURI:   {consentEvilRedirect},
		oauthCodeChallenge: {testLoginChallenge},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 for a redirect host outside the allowlist", w.Code)
	}
}

// newLoginTestServerNoClient builds a login test server; the client it
// registers itself uses https://example.com, which an allowlist may refuse,
// so the server is built with the allowlist set afterwards.
func newLoginTestServerNoClient(t *testing.T, cfg *config.Config) *loginTestServer {
	t.Helper()
	hosts := cfg.OAuthRedirectHosts
	cfg.OAuthRedirectHosts = nil
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	ts.srv.cfg.OAuthRedirectHosts = hosts
	return ts
}

// TestAuthorize_ConsentNeverPreTicked pins that the confirmation is never
// rendered ticked, also not after a failed attempt. A cross-site POST could
// otherwise submit confirm_host with a wrong password, and the genuine page
// would come back with the box already ticked, leaving the victim only the
// password to type.
func TestAuthorize_ConsentNeverPreTicked(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	clientID := registeredClientID(t, registerClient(t, ts.mux, "x", consentEvilRedirect))
	form := url.Values{
		testFormUsername:   {testLoginOwner},
		testFormPassword:   {"wrong"},
		oauthClientID:      {clientID},
		oauthRedirectURI:   {consentEvilRedirect},
		oauthConfirmHost:   {"evil.example"},
		oauthState:         {"s1"},
		oauthCodeChallenge: {testLoginChallenge},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401 for the wrong password", w.Code)
	}
	if strings.Contains(w.Body.String(), "checked") {
		t.Error("the consent checkbox came back ticked")
	}
}
