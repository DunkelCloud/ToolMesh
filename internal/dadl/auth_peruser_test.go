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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Fixtures of the per-user auth tests.
const (
	puBackend   = "mail"
	puAlice     = "alice"
	puBob       = "bob"
	puAccount   = "alice@example.com"
	puSecond    = "office@example.com"
	puBobAcct   = "bob@example.com"
	puLogin     = "mail_login"
	puAPIToken  = "mail_api_token"
	puInstance  = "instance-token" //nolint:gosec // test fixture, not a credential
	puDataPath  = "/data"
	puTokenPath = "/token"
	puBodyField = "pass"   // the login body's field for the secret
	puShared    = "shared" //nolint:gosec // test fixture, not a credential
	puClient    = "client"
)

// puStores returns an instance store that holds a token under the same
// name users store theirs, and the user store wrapped over it for backend
// "mail": mail_login comes from users, mail_api_token from the instance.
func puStores(t *testing.T) (*credentials.UserScopedStore, *credentials.FileUserStore) {
	t.Helper()
	users, err := credentials.NewFileUserStore(t.TempDir(), bytes.Repeat([]byte{9}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	instance := mapCreds{puLogin: puInstance, puAPIToken: "api-token"}
	return credentials.NewUserScopedStore(instance, users, puBackend, []string{puLogin}, ""), users
}

func puStore(t *testing.T, users *credentials.FileUserStore, user, account, value string) {
	t.Helper()
	slot := credentials.UserSlot{UserID: user, Backend: puBackend, Account: account, Name: puLogin}
	if err := users.PutUser(context.Background(), slot, value); err != nil {
		t.Fatal(err)
	}
}

// puCtx is the context of a call by user, optionally naming an account.
func puCtx(user, account string) context.Context {
	ctx := context.Background()
	if user != "" {
		ctx = userctx.WithUserContext(ctx, &userctx.UserContext{UserID: user, Authenticated: true})
	}
	if account != "" {
		ctx = credentials.WithAccount(ctx, account)
	}
	return ctx
}

// puInject runs InjectAuth for a GET of target and returns the request.
func puInject(t *testing.T, a *RestAuth, ctx context.Context, target string) (*http.Request, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	return req, a.InjectAuth(ctx, req)
}

func puUserErr(t *testing.T, err error, reason string) {
	t.Helper()
	var uce *credentials.UserCredentialError
	if !errors.As(err, &uce) {
		t.Fatalf("err = %v, want a *credentials.UserCredentialError", err)
	}
	if uce.Reason != reason {
		t.Fatalf("reason = %q, want %q (%v)", uce.Reason, reason, err)
	}
	if errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Fatal("the error wraps ErrCredentialNotFound: the request would go out without authentication")
	}
}

// TestRestAuth_PerUser_Bearer pins the rule for static credentials: every
// user is sent with their own value, a user without one is refused, and
// the instance's value under the same name is never used.
func TestRestAuth_PerUser_Bearer(t *testing.T) {
	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "alice-token")
	puStore(t, users, puBob, puBobAcct, "bob-token")

	a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: puLogin}, hardeningBase, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	if !a.PerUser() {
		t.Fatal("PerUser() = false for an auth block that reads a per-user credential")
	}

	for user, want := range map[string]string{puAlice: "Bearer alice-token", puBob: "Bearer bob-token"} {
		req, err := puInject(t, a, puCtx(user, ""), hardeningBase+puDataPath)
		if err != nil || req.Header.Get(headerAuthorization) != want {
			t.Errorf("%s: Authorization = %q, %v, want %q", user, req.Header.Get(headerAuthorization), err, want)
		}
	}
	req, err := puInject(t, a, puCtx("carol", ""), hardeningBase+puDataPath)
	puUserErr(t, err, credentials.UserCredentialMissing)
	if got := req.Header.Get(headerAuthorization); got != "" {
		t.Errorf("carol has stored nothing and was sent with %q", got)
	}
	_, err = puInject(t, a, puCtx("", ""), hardeningBase+puDataPath)
	puUserErr(t, err, credentials.UserCredentialNoUser)
}

// TestRestAuth_InstanceCredentialsStayShared pins that SetPerUser changes
// nothing for an auth block that reads no per-user name.
func TestRestAuth_InstanceCredentialsStayShared(t *testing.T) {
	store, _ := puStores(t)
	a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: puAPIToken}, hardeningBase, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	if a.PerUser() {
		t.Fatal("PerUser() = true although the auth block reads instance credentials only")
	}
	for _, ctx := range []context.Context{puCtx("", ""), puCtx(puAlice, "")} {
		req, err := puInject(t, a, ctx, hardeningBase+puDataPath)
		if err != nil || req.Header.Get(headerAuthorization) != "Bearer api-token" {
			t.Errorf("Authorization = %q, %v", req.Header.Get(headerAuthorization), err)
		}
	}
}

// sessionAPI is a session API: POST /login takes {"secret": ...} and
// answers a token and a cookie that both carry the secret, so a test sees
// whose session a request rides on.
type sessionAPI struct {
	srv    *httptest.Server
	logins atomic.Int32
	// entered counts the login requests that have arrived, also the ones
	// still held back by delay.
	entered atomic.Int32
	// delay holds every login back, so concurrent calls overlap it.
	delay time.Duration
	// mu guards secrets, the secret of each login in order.
	mu      sync.Mutex
	secrets []string
}

func newSessionAPI(t *testing.T) *sessionAPI {
	t.Helper()
	api := &sessionAPI{}
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != formsLogin {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Secret string `json:"pass"`
		}
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil || body.Secret == "" {
			http.Error(w, "bad login", http.StatusUnauthorized)
			return
		}
		api.entered.Add(1)
		if api.delay > 0 {
			time.Sleep(api.delay)
		}
		n := api.logins.Add(1)
		api.mu.Lock()
		api.secrets = append(api.secrets, body.Secret)
		api.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "cookie-" + body.Secret, Path: "/"}) //nolint:gosec // G124: cookie of a test API over plain http
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"session":"tok-%s-%d"}`, body.Secret, n)
	}))
	t.Cleanup(api.srv.Close)
	return api
}

// sessionConfig is the auth block of the session API.
func sessionConfig(credential string) AuthConfig {
	return AuthConfig{
		Type: authTypeSession,
		Login: &SessionLogin{
			Method:  http.MethodPost,
			Path:    formsLogin,
			Body:    map[string]any{puBodyField: credentialPrefix + credential},
			Extract: map[string]string{"st": "$.session"},
		},
		Inject:  []InjectRule{{Header: headerAuthorization, Value: "Bearer {{st}}"}},
		Refresh: &RefreshConfig{Trigger: "status_code_401", Action: sessionRefreshLogin},
	}
}

// TestRestAuth_PerUser_SessionsAreIsolated is the per-user session: each
// user logs in with their own credential, and tokens and cookies of one
// never ride on a request of the other.
func TestRestAuth_PerUser_SessionsAreIsolated(t *testing.T) {
	api := newSessionAPI(t)
	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "alice")
	puStore(t, users, puBob, puBobAcct, "bob")

	a := NewRestAuth(sessionConfig(puLogin), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	if a.CookieJar() != nil {
		t.Fatal("CookieJar() is not nil with per-user credentials: the adapter's clients would share one jar among all users")
	}

	check := func(user, wantSecret string) {
		t.Helper()
		req, err := puInject(t, a, puCtx(user, ""), api.srv.URL+puDataPath)
		if err != nil {
			t.Fatalf("%s: %v", user, err)
		}
		if got := req.Header.Get(headerAuthorization); !strings.HasPrefix(got, "Bearer tok-"+wantSecret+"-") {
			t.Errorf("%s: Authorization = %q", user, got)
		}
		if got := req.Header.Get("Cookie"); got != "sid=cookie-"+wantSecret {
			t.Errorf("%s: Cookie = %q", user, got)
		}
	}
	// Interleaved calls: one login each, and no mixing.
	for range 3 {
		check(puAlice, "alice")
		check(puBob, "bob")
	}
	if got := api.logins.Load(); got != 2 {
		t.Errorf("logins = %d, want one per user", got)
	}

	// A changed credential: forgetting alice makes her next call log in
	// with the new value; bob's session is untouched.
	puStore(t, users, puAlice, puAccount, "alice2")
	a.ForgetUser(puAlice)
	check(puAlice, "alice2")
	check(puBob, "bob")
	if got := api.logins.Load(); got != 3 {
		t.Errorf("logins after ForgetUser = %d, want 3", got)
	}

	// A 401 renews the session of the caller only.
	if err := a.HandleUnauthorized(puCtx(puBob, "")); err != nil {
		t.Fatal(err)
	}
	check(puBob, "bob")
	check(puAlice, "alice2")
	if got := api.logins.Load(); got != 4 {
		t.Errorf("logins after bob's 401 = %d, want 4", got)
	}

	// A user without a credential causes no login at all.
	_, err := puInject(t, a, puCtx("carol", ""), api.srv.URL+puDataPath)
	puUserErr(t, err, credentials.UserCredentialMissing)
	if got := api.logins.Load(); got != 4 {
		t.Errorf("a user without a credential caused a login (%d)", got)
	}
}

// TestRestAuth_PerUser_AccountsHaveTheirOwnSessions covers one user with
// several accounts: the call picks one, each has its own session, and a
// call that names none is refused before anything is sent.
func TestRestAuth_PerUser_AccountsHaveTheirOwnSessions(t *testing.T) {
	api := newSessionAPI(t)
	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "first")

	a := NewRestAuth(sessionConfig(puLogin), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	token := func(account string) string {
		t.Helper()
		req, err := puInject(t, a, puCtx(puAlice, account), api.srv.URL+puDataPath)
		if err != nil {
			t.Fatalf("account %q: %v", account, err)
		}
		return req.Header.Get(headerAuthorization)
	}
	// One account: naming it or not is the same session.
	implicit := token("")
	if named := token(puAccount); named != implicit || !strings.Contains(implicit, "tok-first-") {
		t.Fatalf("one account: implicit %q, named %q", implicit, named)
	}

	puStore(t, users, puAlice, puSecond, "second")
	// The session kept for the single account must not answer a call that
	// names none once there are two.
	_, err := puInject(t, a, puCtx(puAlice, ""), api.srv.URL+puDataPath)
	puUserErr(t, err, credentials.UserCredentialAmbiguous)

	if got := token(puSecond); !strings.Contains(got, "tok-second-") {
		t.Errorf("second account: %q", got)
	}
	if got := token(puAccount); got != implicit {
		t.Errorf("first account: %q, want its session %q", got, implicit)
	}
	_, err = puInject(t, a, puCtx(puAlice, "unknown@example.com"), api.srv.URL+puDataPath)
	puUserErr(t, err, credentials.UserCredentialUnknownAccount)
	// Bob cannot ride on alice's account by naming it.
	_, err = puInject(t, a, puCtx(puBob, puAccount), api.srv.URL+puDataPath)
	puUserErr(t, err, credentials.UserCredentialUnknownAccount)
	if got := api.logins.Load(); got != 2 {
		t.Errorf("logins = %d, want one per account", got)
	}
}

// TestRestAuth_SessionLoginIsSingleFlight pins that calls arriving while a
// login runs wait for it instead of logging in themselves, for the shared
// session of a backend with instance credentials.
func TestRestAuth_SessionLoginIsSingleFlight(t *testing.T) {
	api := newSessionAPI(t)
	api.delay = 100 * time.Millisecond
	a := NewRestAuth(sessionConfig(puAPIToken), api.srv.URL, mapCreds{puAPIToken: puShared}, newQuietLogger())

	const callers = 20
	headers := make([]string, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, api.srv.URL+puDataPath, http.NoBody)
			if err != nil {
				return
			}
			if err := a.InjectAuth(context.Background(), req); err == nil {
				headers[i] = req.Header.Get(headerAuthorization)
			}
		}()
	}
	wg.Wait()
	if got := api.logins.Load(); got != 1 {
		t.Errorf("logins = %d, want 1 for %d concurrent first calls", got, callers)
	}
	for i, h := range headers {
		if h != "Bearer tok-shared-1" {
			t.Errorf("caller %d: Authorization = %q", i, h)
		}
	}
}

// TestRestAuth_ConcurrentReloginNeverSendsAPlaceholder runs calls against
// re-logins after a 401. A request must never carry the unresolved
// placeholder of the inject rule: that happened when a re-login cleared the
// tokens between another call's login check and its injection.
func TestRestAuth_ConcurrentReloginNeverSendsAPlaceholder(t *testing.T) {
	api := newSessionAPI(t)
	a := NewRestAuth(sessionConfig(puAPIToken), api.srv.URL, mapCreds{puAPIToken: puShared}, newQuietLogger())

	stop := make(chan struct{})
	var bad atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, api.srv.URL+puDataPath, http.NoBody)
				if err != nil {
					return
				}
				if err := a.InjectAuth(context.Background(), req); err != nil {
					bad.Add(1)
					continue
				}
				if h := req.Header.Get(headerAuthorization); !strings.HasPrefix(h, "Bearer tok-shared-") {
					bad.Add(1)
				}
			}
		}()
	}
	for range 50 {
		if err := a.HandleUnauthorized(context.Background()); err != nil {
			t.Errorf("HandleUnauthorized: %v", err)
		}
	}
	close(stop)
	wg.Wait()
	if n := bad.Load(); n != 0 {
		t.Errorf("%d requests went out without a resolved session token", n)
	}
}

// TestRestAuth_PerUser_OAuth2TokensArePerUser pins that the token cache of
// an OAuth2 backend is the caller's own when the refresh token is.
func TestRestAuth_PerUser_OAuth2TokensArePerUser(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != puTokenPath {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"access-%s","expires_in":3600}`, form.Get("refresh_token"))
	}))
	defer srv.Close()

	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "alice-refresh")
	puStore(t, users, puBob, puBobAcct, "bob-refresh")
	instance := mapCreds{"mail_client_id": puClient}
	scoped := credentials.NewUserScopedStore(instance, users, puBackend, []string{puLogin}, "")
	_ = store

	a := NewRestAuth(AuthConfig{
		Type:                   authTypeOAuth2,
		Flow:                   oauth2FlowRefreshToken,
		TokenURL:               srv.URL + puTokenPath,
		ClientIDCredential:     "mail_client_id",
		RefreshTokenCredential: puLogin,
	}, srv.URL, scoped, newQuietLogger())
	a.SetPerUser(puBackend, scoped)

	for range 2 {
		for user, want := range map[string]string{puAlice: "Bearer access-alice-refresh", puBob: "Bearer access-bob-refresh"} {
			req, err := puInject(t, a, puCtx(user, ""), srv.URL+puDataPath)
			if err != nil || req.Header.Get(headerAuthorization) != want {
				t.Errorf("%s: Authorization = %q, %v, want %q", user, req.Header.Get(headerAuthorization), err, want)
			}
		}
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("token requests = %d, want one per user", got)
	}
}

// TestRestAuth_RefusedLoginIsTyped pins the error of a login the API
// refuses: the credentials page tells a refusal from an outage by it.
func TestRestAuth_RefusedLoginIsTyped(t *testing.T) {
	api := newSessionAPI(t)
	// An empty secret makes the test API answer 401.
	cfg := sessionConfig(puAPIToken)
	cfg.Login.Body = map[string]any{puBodyField: ""}
	a := NewRestAuth(cfg, api.srv.URL, mapCreds{}, newQuietLogger())
	_, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath)
	var exchange *AuthExchangeError
	if !errors.As(err, &exchange) || exchange.Status != http.StatusUnauthorized || !exchange.Refused() {
		t.Fatalf("err = %v, want a refused *AuthExchangeError with status 401", err)
	}
	if !strings.Contains(err.Error(), "session login failed: HTTP 401") {
		t.Errorf("message = %q", err.Error())
	}
	if (&AuthExchangeError{Status: http.StatusBadGateway}).Refused() {
		t.Error("a 502 counts as refused credentials")
	}
}

func TestAuthConfig_CredentialNames(t *testing.T) {
	cfg := sessionConfig(puLogin)
	cfg.Login.Body["nested"] = map[string]any{"token": credentialPrefix + puAPIToken}
	names := cfg.CredentialNames()
	slices.Sort(names)
	if !slices.Equal(names, []string{puAPIToken, puLogin}) {
		t.Fatalf("CredentialNames = %v, want the names of the login body at any depth", names)
	}
	if got := (AuthConfig{Type: authTypeBearer, Credential: NoCredential}).CredentialNames(); len(got) != 0 {
		t.Errorf("the no-secret placeholder is listed: %v", got)
	}
}
