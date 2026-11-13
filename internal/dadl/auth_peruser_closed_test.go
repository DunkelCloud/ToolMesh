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

const (
	pcClientID  = "mail_client_id"
	pcUsername  = "mail_username"
	pcDataURL   = hardeningBase + puDataPath
	pcTokenJSON = "application/json"
	// Credential names of an oauth2 block that sets every field.
	pcSecret  = "csec"
	pcRefresh = "refresh"
)

// pcScoped wraps instance over the user store of puStores, so a test picks
// which instance credentials exist.
func pcScoped(t *testing.T, instance mapCreds) (*credentials.UserScopedStore, *credentials.FileUserStore) {
	t.Helper()
	_, users := puStores(t)
	return credentials.NewUserScopedStore(instance, users, puBackend, []string{puLogin}, ""), users
}

// TestRestAuth_PerUser_NeverSendsWithoutAuth covers auth blocks that read a
// credential of the user and one of the instance. For a backend with
// instance credentials a missing credential means "send without
// authentication"; a backend that authenticates as the calling user must
// never do that, whichever of its credentials is the missing one.
func TestRestAuth_PerUser_NeverSendsWithoutAuth(t *testing.T) {
	t.Run("basic, the instance's username is missing", func(t *testing.T) {
		store, users := pcScoped(t, mapCreds{})
		puStore(t, users, puAlice, puAccount, "alice-password")
		a := NewRestAuth(AuthConfig{Type: authTypeBasic, UsernameCredential: pcUsername, PasswordCredential: puLogin}, hardeningBase, store, newQuietLogger())
		a.SetPerUser(puBackend, store)
		req, err := puInject(t, a, puCtx(puAlice, ""), pcDataURL)
		if err == nil || req.Header.Get(headerAuthorization) != "" {
			t.Fatalf("err = %v, Authorization = %q; want the call refused", err, req.Header.Get(headerAuthorization))
		}
	})

	t.Run("oauth2, the instance's client id is missing", func(t *testing.T) {
		var requests atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
		defer srv.Close()
		store, users := pcScoped(t, mapCreds{})
		puStore(t, users, puAlice, puAccount, "alice-refresh")
		a := NewRestAuth(AuthConfig{
			Type: authTypeOAuth2, Flow: oauth2FlowRefreshToken, TokenURL: srv.URL + puTokenPath,
			ClientIDCredential: pcClientID, RefreshTokenCredential: puLogin,
		}, srv.URL, store, newQuietLogger())
		a.SetPerUser(puBackend, store)
		req, err := puInject(t, a, puCtx(puAlice, ""), srv.URL+puDataPath)
		if err == nil || req.Header.Get(headerAuthorization) != "" || requests.Load() != 0 {
			t.Fatalf("err = %v, Authorization = %q, token requests %d; want the call refused before anything is sent", err, req.Header.Get(headerAuthorization), requests.Load())
		}
	})

	t.Run("oauth2, the token endpoint answers without a token", func(t *testing.T) {
		var requests atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			w.Header().Set("Content-Type", pcTokenJSON)
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_refresh_token"}`))
		}))
		defer srv.Close()
		store, users := pcScoped(t, mapCreds{pcClientID: puClient})
		puStore(t, users, puAlice, puAccount, "alice-refresh")
		a := NewRestAuth(AuthConfig{
			Type: authTypeOAuth2, Flow: oauth2FlowRefreshToken, TokenURL: srv.URL + puTokenPath,
			ClientIDCredential: pcClientID, RefreshTokenCredential: puLogin,
		}, srv.URL, store, newQuietLogger())
		a.SetPerUser(puBackend, store)
		for range 2 {
			req, err := puInject(t, a, puCtx(puAlice, ""), srv.URL+puDataPath)
			if err == nil || req.Header.Get(headerAuthorization) != "" {
				t.Fatalf("err = %v, Authorization = %q; want the call refused", err, req.Header.Get(headerAuthorization))
			}
		}
		if requests.Load() != 2 {
			t.Errorf("token requests = %d: an answer without a token must not be kept", requests.Load())
		}
	})

	// The same block on instance credentials keeps its old meaning: the
	// call goes out without a header, as for a public endpoint.
	t.Run("instance credentials keep skipping", func(t *testing.T) {
		a := NewRestAuth(AuthConfig{Type: authTypeBasic, UsernameCredential: pcUsername, PasswordCredential: puLogin}, hardeningBase, mapCreds{}, newQuietLogger())
		req, err := puInject(t, a, context.Background(), pcDataURL)
		if err != nil || req.Header.Get(headerAuthorization) != "" {
			t.Errorf("err = %v, Authorization = %q; want no error and no header", err, req.Header.Get(headerAuthorization))
		}
	})
}

// TestRestAuth_PerUser_TokenHostOfAUsersKey pins who may choose the host a
// jwt_bearer assertion is sent to. The token_uri inside a service-account
// key is the operator's word when the operator stored the key. A key a
// user stored is not: its token_uri has to be one of the backend's hosts.
func TestRestAuth_PerUser_TokenHostOfAUsersKey(t *testing.T) {
	var requests atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", pcTokenJSON)
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":60}`))
	}))
	defer elsewhere.Close()
	key, _ := testServiceAccountJSON(t, elsewhere.URL+puTokenPath)
	hosts, err := NewHostScope(hardeningBase, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := AuthConfig{Type: authTypeOAuth2, Flow: oauth2FlowJWTBearer, ServiceAccountCredential: puLogin}

	store, users := pcScoped(t, mapCreds{})
	puStore(t, users, puAlice, puAccount, key)
	a := NewRestAuth(cfg, hardeningBase, store, newQuietLogger())
	a.SetScope(nil, hosts)
	a.SetPerUser(puBackend, store)
	req, err := puInject(t, a, puCtx(puAlice, ""), pcDataURL)
	if err == nil || req.Header.Get(headerAuthorization) != "" || requests.Load() != 0 {
		t.Fatalf("a user's key: err = %v, Authorization = %q, requests to its token_uri %d; want it refused", err, req.Header.Get(headerAuthorization), requests.Load())
	}

	// The operator's own key may name its token host.
	operator := NewRestAuth(cfg, hardeningBase, mapCreds{puLogin: key}, newQuietLogger())
	operator.SetScope(nil, hosts)
	req, err = puInject(t, operator, context.Background(), pcDataURL)
	if err != nil || req.Header.Get(headerAuthorization) != "Bearer t" || requests.Load() != 1 {
		t.Errorf("the operator's key: err = %v, Authorization = %q, requests %d", err, req.Header.Get(headerAuthorization), requests.Load())
	}
}

// TestRestAuth_PerUser_AnonymousIsNoUser pins that only an authenticated
// caller has accounts, whatever user id an unauthenticated one carries.
func TestRestAuth_PerUser_AnonymousIsNoUser(t *testing.T) {
	store, users := puStores(t)
	puStore(t, users, "anonymous", "anon@example.com", "anon-token")
	a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: puLogin}, hardeningBase, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "anonymous"})
	req, err := puInject(t, a, ctx, pcDataURL)
	puUserErr(t, err, credentials.UserCredentialNoUser)
	if req.Header.Get(headerAuthorization) != "" {
		t.Error("an unauthenticated caller was sent with a stored credential")
	}
}

// TestRestAuth_WaitingCallerCanGiveUp pins that a call waiting for another
// call's login is not held past its own deadline.
func TestRestAuth_WaitingCallerCanGiveUp(t *testing.T) {
	api := newSessionAPI(t)
	api.delay = 700 * time.Millisecond
	a := NewRestAuth(sessionConfig(puAPIToken), api.srv.URL, mapCreds{puAPIToken: puShared}, newQuietLogger())

	first := make(chan error, 1)
	go func() {
		_, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath)
		first <- err
	}()
	// Let the first call take the lock and start its login.
	for api.entered.Load() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := puInject(t, a, ctx, api.srv.URL+puDataPath)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiting call: err = %v, want its deadline", err)
	}
	if waited := time.Since(start); waited > 400*time.Millisecond {
		t.Errorf("the waiting call was held for %v, past its 60 ms deadline", waited)
	}
	if err := <-first; err != nil {
		t.Errorf("the call that logged in: %v", err)
	}
}

// TestRestAuth_ManyFailuresOneRelogin pins that calls which fail together
// on one expired session cause one re-login: each says which session it
// was refused with, and only the first finds that session still current.
func TestRestAuth_ManyFailuresOneRelogin(t *testing.T) {
	api := newSessionAPI(t)
	a := NewRestAuth(sessionConfig(puAPIToken), api.srv.URL, mapCreds{puAPIToken: puShared}, newQuietLogger())
	const callers = 10
	refused := make([]*http.Request, callers)
	for i := range refused {
		req, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath)
		if err != nil {
			t.Fatal(err)
		}
		refused[i] = req
	}
	if api.logins.Load() != 1 {
		t.Fatalf("logins before the failures = %d", api.logins.Load())
	}
	var wg sync.WaitGroup
	for _, req := range refused {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := a.HandleUnauthorizedFor(context.Background(), req); err != nil {
				t.Errorf("HandleUnauthorizedFor: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := api.logins.Load(); got != 2 {
		t.Errorf("logins after %d failures on one session = %d, want one re-login", callers, got)
	}
	req, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath)
	if err != nil || req.Header.Get(headerAuthorization) != "Bearer tok-shared-2" {
		t.Errorf("after the re-login: Authorization = %q, %v", req.Header.Get(headerAuthorization), err)
	}
	// Without the refused request there is nothing to compare: the session
	// is renewed.
	if err := a.HandleUnauthorized(context.Background()); err != nil || api.logins.Load() != 3 {
		t.Errorf("HandleUnauthorized: %v, logins %d, want 3", err, api.logins.Load())
	}
}

// TestRestAuth_PerUser_IdleStatesAreDropped pins that the states of users
// who stopped calling do not stay forever, and that a state in use is not
// dropped to make room.
func TestRestAuth_PerUser_IdleStatesAreDropped(t *testing.T) {
	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "alice-token")
	a := NewRestAuth(AuthConfig{Type: authTypeBearer, Credential: puLogin}, hardeningBase, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	fill := func(lastUsed time.Time) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.users = map[userStateKey]*authState{}
		for i := range maxUserAuthStates {
			st := newAuthState()
			st.lastUsed = lastUsed
			a.users[userStateKey{user: fmt.Sprintf("user%d", i), account: "a"}] = st
		}
	}
	count := func() int {
		a.mu.Lock()
		defer a.mu.Unlock()
		return len(a.users)
	}

	fill(time.Now().Add(-userAuthStateIdle - time.Minute))
	if _, err := puInject(t, a, puCtx(puAlice, ""), pcDataURL); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Errorf("states after a call with %d idle ones = %d, want only the caller's", maxUserAuthStates, got)
	}
	fill(time.Now())
	if _, err := puInject(t, a, puCtx(puAlice, ""), pcDataURL); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != maxUserAuthStates+1 {
		t.Errorf("states in use were dropped: %d left of %d", got, maxUserAuthStates+1)
	}
}

// TestRestAuth_PerUser_ConcurrentUsersNeverMix runs many users at once
// against one session backend, with sessions being forgotten and renewed
// in between. Every request must ride on its own user's session.
func TestRestAuth_PerUser_ConcurrentUsersNeverMix(t *testing.T) {
	api := newSessionAPI(t)
	store, users := puStores(t)
	const people, workers, calls = 12, 4, 15
	for i := range people {
		puStore(t, users, fmt.Sprintf("user%d", i), fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("secret%d", i))
	}
	a := NewRestAuth(sessionConfig(puLogin), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	var mixed atomic.Int32
	var wg sync.WaitGroup
	for i := range people {
		user, secret := fmt.Sprintf("user%d", i), fmt.Sprintf("secret%d", i)
		account := fmt.Sprintf("u%d@example.com", i)
		for w := range workers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for c := range calls {
					req, err := http.NewRequestWithContext(puCtx(user, ""), http.MethodGet, api.srv.URL+puDataPath, http.NoBody)
					if err != nil {
						return
					}
					if err := a.InjectAuth(req.Context(), req); err != nil {
						mixed.Add(1)
						continue
					}
					if !strings.HasPrefix(req.Header.Get(headerAuthorization), "Bearer tok-"+secret+"-") || req.Header.Get("Cookie") != "sid=cookie-"+secret {
						mixed.Add(1)
					}
					switch (c + w) % 5 {
					case 0:
						a.ForgetAccount(user, account)
					case 1:
						_ = a.HandleUnauthorizedFor(req.Context(), req)
					}
				}
			}()
		}
	}
	wg.Wait()
	if n := mixed.Load(); n != 0 {
		t.Errorf("%d requests failed or carried another user's session", n)
	}
}

// TestAuthConfig_CredentialNamesFollowTheFlow pins that only the names the
// runtime reads count. A refresh_token_credential next to the default
// client_credentials flow is never read; declared as a user's, it would
// leave the backend on the instance's client for every caller.
func TestAuthConfig_CredentialNamesFollowTheFlow(t *testing.T) {
	all := AuthConfig{
		Type:                     authTypeOAuth2,
		ClientIDCredential:       testOAuth2CID,
		ClientSecretCredential:   pcSecret,
		RefreshTokenCredential:   pcRefresh,
		ServiceAccountCredential: "sa",
	}
	for flow, want := range map[string][]string{
		"":                          {testOAuth2CID, pcSecret},
		oauth2FlowClientCredentials: {testOAuth2CID, pcSecret},
		oauth2FlowRefreshToken:      {testOAuth2CID, pcSecret, pcRefresh},
		oauth2FlowAuthorizationCode: {testOAuth2CID, pcSecret, pcRefresh},
		oauth2FlowJWTBearer:         {"sa"},
	} {
		cfg := all
		cfg.Flow = flow
		got := cfg.CredentialNames()
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("flow %q: names = %v, want %v", flow, got, want)
		}
	}
	// A request for a per-user name outside the flow leaves the auth block
	// with instance credentials, which the adapter then refuses to load.
	store, _ := pcScoped(t, mapCreds{})
	unread := all
	unread.RefreshTokenCredential = puLogin
	a := NewRestAuth(unread, hardeningBase, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	if a.PerUser() {
		t.Error("a credential the flow never reads made the backend per user")
	}
}

// pcEcho answers a token request with the refresh token it was sent.
func pcEcho(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(raw))
	w.Header().Set("Content-Type", pcTokenJSON)
	_, _ = fmt.Fprintf(w, `{"access_token":"access-%s","expires_in":3600}`, form.Get("refresh_token"))
}

// TestRestAuth_PerUser_OAuth2RenewsOnlyTheCaller pins the 401 path of an
// OAuth2 backend with per-user refresh tokens: the token of the caller is
// dropped, the tokens of others stay.
func TestRestAuth_PerUser_OAuth2RenewsOnlyTheCaller(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		pcEcho(w, r)
	}))
	defer srv.Close()
	store, users := pcScoped(t, mapCreds{pcClientID: puClient})
	puStore(t, users, puAlice, puAccount, "alice-refresh")
	puStore(t, users, puBob, puBobAcct, "bob-refresh")
	a := NewRestAuth(AuthConfig{
		Type: authTypeOAuth2, Flow: oauth2FlowRefreshToken, TokenURL: srv.URL + puTokenPath,
		ClientIDCredential: pcClientID, RefreshTokenCredential: puLogin,
	}, srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	for _, user := range []string{puAlice, puBob} {
		if _, err := puInject(t, a, puCtx(user, ""), srv.URL+puDataPath); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.HandleUnauthorized(puCtx(puAlice, "")); err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{puAlice, puBob} {
		if _, err := puInject(t, a, puCtx(user, ""), srv.URL+puDataPath); err != nil {
			t.Fatal(err)
		}
	}
	if got := requests.Load(); got != 3 {
		t.Errorf("token requests = %d, want 3: one each, and one more for the caller whose token was refused", got)
	}
}
