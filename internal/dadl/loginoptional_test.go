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
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Fixtures of the tests of optional login fields.
const (
	loScope      = "mail_scope"
	loScopeField = "scope"
	loInbox      = `{"mailboxes":["INBOX"]}`
	loProjects   = `{"mailboxes":["Projects/*"],"send":false}`
)

// loginRecorder is an API whose login answers a token and keeps the body
// of every login it got.
type loginRecorder struct {
	srv *httptest.Server
	mu  sync.Mutex
	// bodies are the login bodies in order, as sent.
	bodies []string
}

func newLoginRecorder(t *testing.T) *loginRecorder {
	t.Helper()
	api := &loginRecorder{}
	api.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != formsLogin {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		api.mu.Lock()
		api.bodies = append(api.bodies, string(raw))
		n := len(api.bodies)
		api.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"session":"tok-%d"}`, n)
	}))
	t.Cleanup(api.srv.Close)
	return api
}

// logins returns the bodies of the logins so far.
func (api *loginRecorder) logins() []string {
	api.mu.Lock()
	defer api.mu.Unlock()
	return append([]string(nil), api.bodies...)
}

// last returns the fields of the latest login body.
func (api *loginRecorder) last(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	bodies := api.logins()
	if len(bodies) == 0 {
		t.Fatal("no login arrived")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(bodies[len(bodies)-1]), &fields); err != nil {
		t.Fatalf("login body %q: %v", bodies[len(bodies)-1], err)
	}
	return fields
}

// scopeLoginConfig is a session login whose body carries the secret and,
// as an optional field, a scope.
func scopeLoginConfig() AuthConfig {
	cfg := sessionConfig(puLogin)
	cfg.Login.Body[loScopeField] = credentialPrefix + loScope
	cfg.Login.Optional = []string{loScopeField}
	return cfg
}

// loStores returns the user store over dir with key, and the scoped store
// of backend "mail" in which users hold mail_login and mail_scope; setup
// marks names as optional or as JSON values.
func loStores(t *testing.T, dir string, key byte, setup func(*credentials.UserScopedStore)) (*credentials.UserScopedStore, *credentials.FileUserStore) {
	t.Helper()
	users, err := credentials.NewFileUserStore(dir, bytes.Repeat([]byte{key}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	scoped := credentials.NewUserScopedStore(mapCreds{}, users, puBackend, []string{puLogin, loScope}, "")
	if setup != nil {
		setup(scoped)
	}
	return scoped, users
}

// loOptionalJSON is the usual setup: the scope may be absent and is a JSON
// object.
func loOptionalJSON(s *credentials.UserScopedStore) {
	s.WithOptional(loScope).WithJSONValues(loScope)
}

func loPut(t *testing.T, users *credentials.FileUserStore, user, account, name, value string) {
	t.Helper()
	slot := credentials.UserSlot{UserID: user, Backend: puBackend, Account: account, Name: name}
	if err := users.PutUser(context.Background(), slot, value); err != nil {
		t.Fatal(err)
	}
}

// TestParse_LoginOptional pins what auth.login.optional may name: fields of
// the login body's top level that carry one credential reference, each
// once, in a session login.
func TestParse_LoginOptional(t *testing.T) {
	const session = "    type: session\n    login:\n      method: POST\n      path: /login\n      body:\n        user: \"credential:names_user\"\n        scope: \"credential:names_scope\"\n        plain: fixed\n        nested:\n          inner: \"credential:names_inner\"\n"
	cases := []struct {
		name string
		auth string
		want string // part of the error, "" for a DADL that loads
	}{
		{"one optional field", session + "      optional: [scope]", ""},
		{"no optional field", session, ""},
		{"an empty list", session + "      optional: []", ""},
		{"not a field of the body", session + "      optional: [limit]", "not a field of auth.login.body"},
		{"a fixed value", session + "      optional: [plain]", "not a credential reference"},
		{"an object", session + "      optional: [nested]", "not a credential reference"},
		{"a field below the top level", session + "      optional: [inner]", "not a field of auth.login.body"},
		{"named twice", session + "      optional: [scope, scope]", "twice"},
		{"another auth type", "    type: bearer\n    credential: names_token\n    login:\n      method: POST\n      path: /login\n      body:\n        scope: \"credential:names_scope\"\n      optional: [scope]", "is for auth.type session"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec, err := ParseBytes(namesDADL(c.auth))
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("ParseBytes = %v, want an error with %q", err, c.want)
			case c.want == "" && strings.Contains(c.auth, "optional: [scope]"):
				if got := spec.Backend.Auth.Login.Optional; len(got) != 1 || got[0] != loScopeField {
					t.Fatalf("Optional = %v, want [scope]", got)
				}
			}
		})
	}
}

// TestAuthConfig_CanOmitCredential pins when a login goes without a
// credential: every place that reads the name is an optional field.
func TestAuthConfig_CanOmitCredential(t *testing.T) {
	login := func(body map[string]any, optional ...string) AuthConfig {
		return AuthConfig{Type: authTypeSession, Login: &SessionLogin{Method: http.MethodPost, Path: formsLogin, Body: body, Optional: optional}}
	}
	ref := func(name string) string { return credentialPrefix + name }
	cases := []struct {
		name string
		auth AuthConfig
		cred string
		want bool
	}{
		{"an optional field", login(map[string]any{puBodyField: ref(puLogin), loScopeField: ref(loScope)}, loScopeField), loScope, true},
		{"another spelling of the name", login(map[string]any{loScopeField: ref(loScope)}, loScopeField), "MAIL_SCOPE", true},
		{"a field that is not optional", login(map[string]any{puBodyField: ref(puLogin), loScopeField: ref(loScope)}, loScopeField), puLogin, false},
		{"no optional fields at all", login(map[string]any{loScopeField: ref(loScope)}), loScope, false},
		{"read in a second field that is not optional", login(map[string]any{loScopeField: ref(loScope), "again": ref(loScope)}, loScopeField), loScope, false},
		{"read below the top level as well", login(map[string]any{loScopeField: ref(loScope), "more": map[string]any{"x": ref(loScope)}}, loScopeField), loScope, false},
		{"read in a list as well", login(map[string]any{loScopeField: ref(loScope), "more": []any{ref(loScope)}}, loScopeField), loScope, false},
		{"two optional fields", login(map[string]any{loScopeField: ref(loScope), "again": ref(loScope)}, loScopeField, "again"), loScope, true},
		{"a name the login does not read", login(map[string]any{loScopeField: ref(loScope)}, loScopeField), "other", false},
		{"no session login", AuthConfig{Type: authTypeBearer, Credential: loScope}, loScope, false},
		{"session without a login", AuthConfig{Type: authTypeSession}, loScope, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.auth.CanOmitCredential(c.cred); got != c.want {
				t.Fatalf("CanOmitCredential(%q) = %v, want %v", c.cred, got, c.want)
			}
		})
	}
	if !login(map[string]any{}).IsSessionLogin() || (AuthConfig{Type: authTypeSession}).IsSessionLogin() || (AuthConfig{Type: authTypeBearer, Login: &SessionLogin{}}).IsSessionLogin() {
		t.Fatal("IsSessionLogin: a session auth block with a login is one, nothing else")
	}
}

// TestRestAuth_OptionalLoginField_Instance is the optional field of a
// backend whose credentials belong to the instance: without the credential
// the login goes without the field, with one it carries it, as a string.
func TestRestAuth_OptionalLoginField_Instance(t *testing.T) {
	cases := []struct {
		name  string
		creds mapCreds
		want  string // the scope field as sent, "" when it must be absent
	}{
		{"no such credential", mapCreds{puLogin: "pw"}, ""},
		{"an empty credential", mapCreds{puLogin: "pw", loScope: ""}, ""},
		{"a credential", mapCreds{puLogin: "pw", loScope: "narrow"}, `"narrow"`},
		// Only a credential of users can be a JSON value.
		{"a credential that looks like JSON", mapCreds{puLogin: "pw", loScope: loInbox}, `"{\"mailboxes\":[\"INBOX\"]}"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			api := newLoginRecorder(t)
			a := NewRestAuth(scopeLoginConfig(), api.srv.URL, c.creds, newQuietLogger())
			if _, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath); err != nil {
				t.Fatalf("InjectAuth: %v", err)
			}
			fields := api.last(t)
			if string(fields[puBodyField]) != `"pw"` {
				t.Fatalf("the secret was sent as %s", fields[puBodyField])
			}
			got, sent := fields[loScopeField]
			if (c.want == "") == sent || string(got) != c.want {
				t.Fatalf("scope sent = %v as %s, want %q", sent, got, c.want)
			}
		})
	}

	t.Run("a field that is not optional is never left out", func(t *testing.T) {
		api := newLoginRecorder(t)
		cfg := scopeLoginConfig()
		cfg.Login.Optional = nil
		a := NewRestAuth(cfg, api.srv.URL, mapCreds{puLogin: "pw"}, newQuietLogger())
		if _, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath); err == nil {
			t.Fatal("the login went out without a credential its body names")
		}
		if n := len(api.logins()); n != 0 {
			t.Fatalf("%d logins were sent", n)
		}
	})

	t.Run("the secret is not optional because another field is", func(t *testing.T) {
		api := newLoginRecorder(t)
		a := NewRestAuth(scopeLoginConfig(), api.srv.URL, mapCreds{loScope: "narrow"}, newQuietLogger())
		if _, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath); err == nil {
			t.Fatal("the login went out without its secret")
		}
		if n := len(api.logins()); n != 0 {
			t.Fatalf("%d logins were sent", n)
		}
	})
}

// TestRestAuth_OptionalLoginField_PerUser is the limit a user stores with an
// account: the login of an account without one is the plain login, the
// login of an account with one carries it as the object it is, and each
// account logs in with its own.
func TestRestAuth_OptionalLoginField_PerUser(t *testing.T) {
	api := newLoginRecorder(t)
	store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
	loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
	loPut(t, users, puAlice, puSecond, puLogin, "office-pw")
	loPut(t, users, puAlice, puSecond, loScope, loInbox)
	loPut(t, users, puBob, puBobAcct, puLogin, "bob-pw")
	loPut(t, users, puBob, puBobAcct, loScope, loProjects)

	a := NewRestAuth(scopeLoginConfig(), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	check := func(user, account, secret, scope string) {
		t.Helper()
		if _, err := puInject(t, a, puCtx(user, account), api.srv.URL+puDataPath); err != nil {
			t.Fatalf("%s/%s: InjectAuth: %v", user, account, err)
		}
		fields := api.last(t)
		if string(fields[puBodyField]) != `"`+secret+`"` {
			t.Fatalf("%s/%s: the secret was sent as %s", user, account, fields[puBodyField])
		}
		got, sent := fields[loScopeField]
		if (scope == "") == sent || string(got) != scope {
			t.Fatalf("%s/%s: scope sent = %v as %s, want %q", user, account, sent, got, scope)
		}
	}
	check(puAlice, puAccount, "alice-pw", "")
	check(puAlice, puSecond, "office-pw", loInbox)
	check(puBob, puBobAcct, "bob-pw", loProjects)
	if n := len(api.logins()); n != 3 {
		t.Fatalf("%d logins, want one per account", n)
	}

	// A changed limit applies from the next login of that account on, and
	// to no other account.
	loPut(t, users, puAlice, puSecond, loScope, loProjects)
	a.ForgetAccount(puAlice, puSecond)
	check(puAlice, puSecond, "office-pw", loProjects)
	if _, err := puInject(t, a, puCtx(puBob, puBobAcct), api.srv.URL+puDataPath); err != nil {
		t.Fatal(err)
	}
	if n := len(api.logins()); n != 4 {
		t.Fatalf("%d logins, want 4: the other account keeps its session", n)
	}

	// A removed limit: the next login is the plain one.
	if _, err := users.DeleteUser(context.Background(), credentials.UserSlot{UserID: puAlice, Backend: puBackend, Account: puSecond, Name: loScope}); err != nil {
		t.Fatal(err)
	}
	a.ForgetAccount(puAlice, puSecond)
	check(puAlice, puSecond, "office-pw", "")
}

// TestRestAuth_OptionalLoginField_FailsClosed pins that a limit is left out
// only when the account holds none and may go without one. In every other
// case the login is not sent at all: no limit must never be the result of
// a limit that could not be supplied.
func TestRestAuth_OptionalLoginField_FailsClosed(t *testing.T) {
	inject := func(t *testing.T, store *credentials.UserScopedStore) (*loginRecorder, error) {
		t.Helper()
		api := newLoginRecorder(t)
		a := NewRestAuth(scopeLoginConfig(), api.srv.URL, store, newQuietLogger())
		a.SetPerUser(puBackend, store)
		_, err := puInject(t, a, puCtx(puAlice, ""), api.srv.URL+puDataPath)
		return api, err
	}
	nothingSent := func(t *testing.T, api *loginRecorder, err error) {
		t.Helper()
		if err == nil {
			t.Fatalf("the login went out: %v", api.logins())
		}
		if n := len(api.logins()); n != 0 {
			t.Fatalf("%d logins were sent: %v", n, api.logins())
		}
	}

	t.Run("the operator requires the limit", func(t *testing.T) {
		store, users := loStores(t, t.TempDir(), 7, func(s *credentials.UserScopedStore) { s.WithJSONValues(loScope) })
		loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
		api, err := inject(t, store)
		nothingSent(t, api, err)
		puUserErr(t, err, credentials.UserCredentialIncomplete)
	})

	t.Run("the limit cannot be read", func(t *testing.T) {
		dir := t.TempDir()
		_, written := loStores(t, dir, 7, nil)
		loPut(t, written, puAlice, puAccount, loScope, loInbox)
		// The same file under another key: the secret is stored anew, the
		// limit stays sealed under the key that is gone.
		store, users := loStores(t, dir, 8, loOptionalJSON)
		loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
		api, err := inject(t, store)
		nothingSent(t, api, err)
		puUserErr(t, err, credentials.UserCredentialUnreadable)
	})

	t.Run("the stored limit is no JSON object", func(t *testing.T) {
		for _, value := range []string{`["INBOX"]`, `"INBOX"`, `{"mailboxes":`, `secret-text`, `{} trailing`} {
			store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
			loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
			loPut(t, users, puAlice, puAccount, loScope, value)
			api, err := inject(t, store)
			nothingSent(t, api, err)
			if strings.Contains(err.Error(), value) {
				t.Fatalf("the error repeats the stored value: %v", err)
			}
			// The value is refused for what it is, before anything is
			// built from it: an encoder's complaint could quote part of
			// it.
			if !strings.Contains(err.Error(), "is not a JSON object") {
				t.Fatalf("value %q: err = %v, want the refusal of a value that is no JSON object", value, err)
			}
		}
	})

	t.Run("the user has no account", func(t *testing.T) {
		store, _ := loStores(t, t.TempDir(), 7, loOptionalJSON)
		api, err := inject(t, store)
		nothingSent(t, api, err)
		puUserErr(t, err, credentials.UserCredentialMissing)
	})

	t.Run("the account holds only the limit", func(t *testing.T) {
		store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
		loPut(t, users, puAlice, puAccount, loScope, loInbox)
		api, err := inject(t, store)
		nothingSent(t, api, err)
		puUserErr(t, err, credentials.UserCredentialIncomplete)
	})

	t.Run("several accounts and none named", func(t *testing.T) {
		store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
		loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
		loPut(t, users, puAlice, puSecond, puLogin, "office-pw")
		api, err := inject(t, store)
		nothingSent(t, api, err)
		var uce *credentials.UserCredentialError
		if !errors.As(err, &uce) || uce.Reason != credentials.UserCredentialAmbiguous {
			t.Fatalf("err = %v, want the ambiguous account error", err)
		}
	})
}

// TestRestAuth_OptionalLoginField_Relogin pins that a login after a 401
// carries the limit like the first one: a session that is renewed is not a
// wider one.
func TestRestAuth_OptionalLoginField_Relogin(t *testing.T) {
	api := newLoginRecorder(t)
	store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
	loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
	loPut(t, users, puAlice, puAccount, loScope, loInbox)
	a := NewRestAuth(scopeLoginConfig(), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	ctx := puCtx(puAlice, "")
	if _, err := puInject(t, a, ctx, api.srv.URL+puDataPath); err != nil {
		t.Fatal(err)
	}
	if err := a.HandleUnauthorized(ctx); err != nil {
		t.Fatalf("HandleUnauthorized: %v", err)
	}
	bodies := api.logins()
	if len(bodies) != 2 {
		t.Fatalf("%d logins, want the first and the one after the 401", len(bodies))
	}
	if got := string(api.last(t)[loScopeField]); got != loInbox {
		t.Fatalf("the login after a 401 carries the scope %q, want %s", got, loInbox)
	}

	// The limit became unreadable in between: the renewal fails, and no
	// login goes out without it.
	loPut(t, users, puAlice, puAccount, loScope, `not an object`)
	if err := a.HandleUnauthorized(ctx); err == nil {
		t.Fatal("the session was renewed although its limit is no JSON object")
	}
	if n := len(api.logins()); n != 2 {
		t.Fatalf("%d logins, want no login without the limit", n)
	}
}

// TestRestAuth_OptionalFieldOfASpecBuiltInCode pins the second line behind
// the load-time check: a spec that never went through the parser may list
// as optional a field that holds more than one credential reference. Such
// a field is never left out.
func TestRestAuth_OptionalFieldOfASpecBuiltInCode(t *testing.T) {
	api := newLoginRecorder(t)
	cfg := sessionConfig(puLogin)
	cfg.Login.Body["limits"] = map[string]any{"scope": credentialPrefix + loScope, "fixed": "x"}
	cfg.Login.Optional = []string{"limits", puBodyField}
	a := NewRestAuth(cfg, api.srv.URL, mapCreds{puLogin: "pw"}, newQuietLogger())
	if _, err := puInject(t, a, context.Background(), api.srv.URL+puDataPath); err == nil {
		t.Fatalf("the login went out without the object that holds a credential it lacks: %v", api.logins())
	}
	if n := len(api.logins()); n != 0 {
		t.Fatalf("%d logins were sent", n)
	}
}

// TestRestAuth_JSONValueIsSentAsStored pins that the object reaches the API
// as the JSON that is stored: its members keep their order and its numbers
// their digits, which a decoded copy would not.
func TestRestAuth_JSONValueIsSentAsStored(t *testing.T) {
	const value = `{"z":1.50,"a":[3,2,1],"big":12345678901234567890}`
	api := newLoginRecorder(t)
	store, users := loStores(t, t.TempDir(), 7, loOptionalJSON)
	loPut(t, users, puAlice, puAccount, puLogin, "alice-pw")
	loPut(t, users, puAlice, puAccount, loScope, "  "+value+"\n")
	a := NewRestAuth(scopeLoginConfig(), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)
	if _, err := puInject(t, a, puCtx(puAlice, ""), api.srv.URL+puDataPath); err != nil {
		t.Fatal(err)
	}
	if got := string(api.last(t)[loScopeField]); got != value {
		t.Fatalf("scope sent as %s, want %s", got, value)
	}
}
