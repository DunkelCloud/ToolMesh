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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	dcrTestPassword = "dcr-test-password" //nolint:gosec // test fixture
	dcrTestRedirect = "https://example.com/callback"
	dcrTestVerifier = "dcr-test-verifier-with-enough-entropy-0123456789"

	// dcrTestRegisterBody is the registration the tests send.
	dcrTestRegisterBody = `{"redirect_uris": ["` + dcrTestRedirect + `"], "client_name": "dcr-test"}`

	// dcrTestClientTTL and dcrTestIdleTTL are the lifetimes the tests
	// configure, in seconds: an hour for a client without a token, 90 days
	// after a token.
	dcrTestClientTTL = 3600
	dcrTestIdleTTL   = 90 * 24 * 3600
)

// dcrTestConfig returns a config with the password login and the given
// client lifetimes.
func dcrTestConfig(clientTTL, idleTTL int) *config.Config {
	return &config.Config{
		AuthPassword:     dcrTestPassword,
		Issuer:           testIssuerToolmesh,
		DCRClientTTL:     clientTTL,
		DCRClientIdleTTL: idleTTL,
	}
}

// dcrFlow drives registration, login and token requests against one server.
type dcrFlow struct {
	t   *testing.T
	mux *http.ServeMux
}

func (f dcrFlow) register() string {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(dcrTestRegisterBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		f.t.Fatalf("register: status %d, body %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	clientID, _ := resp[oauthClientID].(string)
	if clientID == "" {
		f.t.Fatal("register: no client_id")
	}
	return clientID
}

// login posts the login form and returns the response.
func (f dcrFlow) login(clientID string) *httptest.ResponseRecorder {
	f.t.Helper()
	sum := sha256.Sum256([]byte(dcrTestVerifier))
	form := url.Values{
		testFormPassword:   {dcrTestPassword},
		oauthClientID:      {clientID},
		oauthRedirectURI:   {dcrTestRedirect},
		oauthConfirmHost:   {confirmHostOf(dcrTestRedirect)},
		oauthState:         {"s1"},
		oauthCodeChallenge: {base64.RawURLEncoding.EncodeToString(sum[:])},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	return w
}

// token exchanges an authorization code (or a refresh token) and returns the
// refresh token of the answer.
func (f dcrFlow) token(form url.Values) string {
	f.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		f.t.Fatalf("token: status %d, body %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	refresh, _ := resp[oauthRefreshToken].(string)
	return refresh
}

// signIn logs in with clientID and exchanges the code; it returns the
// refresh token.
func (f dcrFlow) signIn(clientID string) string {
	f.t.Helper()
	w := f.login(clientID)
	if w.Code != http.StatusFound {
		f.t.Fatalf("login: status %d, body %s", w.Code, w.Body.String())
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		f.t.Fatal(err)
	}
	return f.token(url.Values{
		oauthGrantType:    {oauthGrantAuthCode},
		argNameCode:       {loc.Query().Get(argNameCode)},
		oauthCodeVerifier: {dcrTestVerifier},
		oauthClientID:     {clientID},
	})
}

func (f dcrFlow) refresh(clientID, refreshToken string) string {
	f.t.Helper()
	return f.token(url.Values{
		oauthGrantType:    {oauthRefreshToken},
		oauthRefreshToken: {refreshToken},
		oauthClientID:     {clientID},
	})
}

// clientTTL is the remaining lifetime of the client's key in Redis; 0 means
// the key does not expire.
func clientTTL(t *testing.T, mr *miniredis.Miniredis, clientID string) time.Duration {
	t.Helper()
	key := "oauth:client:" + clientID
	if !mr.Exists(key) {
		t.Fatalf("client %s is not stored", clientID)
	}
	return mr.TTL(key)
}

func assertAbout(t *testing.T, what string, got, want time.Duration) {
	t.Helper()
	if got > want || got < want-time.Minute {
		t.Errorf("%s = %v, want about %v", what, got, want)
	}
}

func TestDCRClient_UnusedClientExpires(t *testing.T) {
	_, mux, mr := newTestServerWithRedis(t, dcrTestConfig(dcrTestClientTTL, dcrTestIdleTTL))
	f := dcrFlow{t, mux}

	clientID := f.register()
	assertAbout(t, "TTL of a new client", clientTTL(t, mr, clientID), time.Hour)

	mr.FastForward(61 * time.Minute)
	w := f.login(clientID)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), descUnknownClient) {
		t.Errorf("login with an expired client: status %d, body %s; want 400 unknown client", w.Code, w.Body.String())
	}
}

func TestDCRClient_TokenExtendsLifetime(t *testing.T) {
	_, mux, mr := newTestServerWithRedis(t, dcrTestConfig(dcrTestClientTTL, dcrTestIdleTTL))
	f := dcrFlow{t, mux}

	clientID := f.register()
	refresh := f.signIn(clientID)
	assertAbout(t, "TTL after the first token", clientTTL(t, mr, clientID), 90*24*time.Hour)

	// Past the lifetime of an unused client, the client is still there.
	// (Within the 7 days the refresh token lives.)
	mr.FastForward(3 * 24 * time.Hour)
	assertAbout(t, "TTL after 3 days", clientTTL(t, mr, clientID), 87*24*time.Hour)
	// The access token has long expired; a refresh extends the client again.
	refresh = f.refresh(clientID, refresh)
	if refresh == "" {
		t.Fatal("no refresh token from the refresh grant")
	}
	assertAbout(t, "TTL after a refresh", clientTTL(t, mr, clientID), 90*24*time.Hour)

	// The record itself carries the new expiry as well, for the file store.
	var stored auth.OAuthClient
	if err := json.Unmarshal([]byte(mustGet(t, mr, "oauth:client:"+clientID)), &stored); err != nil {
		t.Fatal(err)
	}
	if until := time.Until(stored.ExpiresAt); until < 89*24*time.Hour {
		t.Errorf("stored ExpiresAt is %v away, want about 90 days", until)
	}
	if stored.ClientName != "dcr-test" || len(stored.RedirectURIs) != 1 {
		t.Errorf("extension lost client data: %+v", stored)
	}
}

func TestDCRClient_IdleTTLNeverBelowRefreshTokenLifetime(t *testing.T) {
	// A config that bypassed validation must not let a client go before
	// the refresh token it holds.
	_, mux, mr := newTestServerWithRedis(t, dcrTestConfig(dcrTestClientTTL, 3600))
	f := dcrFlow{t, mux}

	clientID := f.register()
	f.signIn(clientID)
	assertAbout(t, "TTL after the first token", clientTTL(t, mr, clientID), 7*24*time.Hour)
}

func TestDCRClient_LifetimesOff(t *testing.T) {
	_, mux, mr := newTestServerWithRedis(t, dcrTestConfig(0, 0))
	f := dcrFlow{t, mux}

	clientID := f.register()
	if ttl := clientTTL(t, mr, clientID); ttl != 0 {
		t.Errorf("TTL of a new client = %v, want none", ttl)
	}
	f.signIn(clientID)
	if ttl := clientTTL(t, mr, clientID); ttl != 0 {
		t.Errorf("TTL after a token = %v, want none", ttl)
	}
}

func mustGet(t *testing.T, mr *miniredis.Miniredis, key string) string {
	t.Helper()
	v, err := mr.Get(key)
	if err != nil {
		t.Fatalf("get %s: %v", key, err)
	}
	return v
}

// TestDCRRegister_LimitedWhileRedisIsDown checks that an outage of the
// limiter's Redis neither stops registration nor lifts its limit: the
// registrations are counted in process memory, which is logged, and the
// one over the limit is refused.
func TestDCRRegister_LimitedWhileRedisIsDown(t *testing.T) {
	logs := &loginLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The limiter's Redis is down; the clients themselves go to a file store.
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	mr.Close()
	tokenStore, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	srv := NewServer(handler, dcrTestConfig(dcrTestClientTTL, dcrTestIdleTTL), logger, tokenStore, nil, nil, auth.NewDCRRateLimiter(rdb), nil, nil)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	const limit = 5 // registrations per address and hour
	for range limit {
		dcrFlow{t, mux}.register()
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(dcrTestRegisterBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("registration %d with Redis down: status %d, want 429", limit+1, w.Code)
	}

	lines := logs.lines(t, "dcr rate limit: redis unavailable, registrations counted in process memory")
	if len(lines) != limit+1 {
		t.Fatalf("got %d log lines about the fallback, want %d; log:\n%s", len(lines), limit+1, logs.String())
	}
	if lines[0]["level"] != testLogLevelWarn || lines[0][outcomeError] == nil || lines[0]["remote"] == nil {
		t.Errorf("fallback log line = %v, want WARN with error and remote", lines[0])
	}
}

// TestDCRRegister_BoundsClientMetadata checks that a registration with an
// overlong client_name, too many redirect_uris or an overlong redirect_uri
// is refused and nothing is stored, and that one at the limits is accepted.
func TestDCRRegister_BoundsClientMetadata(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tokenStore, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)
	type registration struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
		Padding      string   `json:"padding,omitempty"`
	}
	post := func(t *testing.T, body registration) (int, map[string]any) {
		t.Helper()
		// A server of its own per request, so the rate limit stays out of it.
		srv := NewServer(handler, dcrTestConfig(dcrTestClientTTL, dcrTestIdleTTL), logger, tokenStore, nil, nil, auth.NewLocalDCRRateLimiter(), nil, nil)
		mux := http.NewServeMux()
		srv.SetupRoutes(mux)
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var resp map[string]any
		_ = json.NewDecoder(w.Body).Decode(&resp)
		return w.Code, resp
	}
	uris := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("https://client.example.com/cb/%d", i)
		}
		return out
	}
	longURI := "https://client.example.com/" + strings.Repeat("a", maxRedirectURIBytes)

	cases := []struct {
		name      string
		body      registration
		wantCode  int
		wantError string
	}{
		{"name at the limit", registration{ClientName: strings.Repeat("n", maxClientNameBytes), RedirectURIs: uris(1)}, http.StatusCreated, ""},
		{"name over the limit", registration{ClientName: strings.Repeat("n", maxClientNameBytes+1), RedirectURIs: uris(1)}, http.StatusBadRequest, oauthErrInvalidClientMetadata},
		{"redirect_uris at the limit", registration{ClientName: "c", RedirectURIs: uris(maxRedirectURIs)}, http.StatusCreated, ""},
		{"too many redirect_uris", registration{ClientName: "c", RedirectURIs: uris(maxRedirectURIs + 1)}, http.StatusBadRequest, oauthErrInvalidRedURI},
		{"overlong redirect_uri", registration{ClientName: "c", RedirectURIs: []string{longURI}}, http.StatusBadRequest, oauthErrInvalidRedURI},
		{"body over the limit", registration{ClientName: "c", RedirectURIs: uris(1), Padding: strings.Repeat("p", maxRegisterBodyBytes)}, http.StatusBadRequest, oauthErrInvalidReq},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, resp := post(t, c.body)
			if code != c.wantCode {
				t.Fatalf("status %d, want %d (%v)", code, c.wantCode, resp)
			}
			if c.wantError != "" && resp[outcomeError] != c.wantError {
				t.Errorf("error = %v, want %q", resp[outcomeError], c.wantError)
			}
			if c.wantError != "" && resp[oauthClientID] != nil {
				t.Errorf("a refused registration returned a client: %v", resp)
			}
		})
	}
}
