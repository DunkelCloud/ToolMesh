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

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Fixtures of the tests of a limit a user stores with an account.
const (
	aclScope       = "mail_scope"
	aclInboxOnly   = `{"mailboxes":["INBOX"]}`
	aclArchive     = "Archive"
	aclParamFolder = "folder"
)

// aclDADL is a mail API behind a session login that takes the user's
// secret and, when optional is set, an optional scope.
func aclDADL(baseURL string, optional bool) string {
	opt := ""
	if optional {
		opt = "\n      optional: [scope]"
	}
	return fmt.Sprintf(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: %s
  description: "A mail API whose login takes a scope"
  auth:
    type: session
    login:
      method: POST
      path: %s
      body:
        pass: "credential:mail_login"
        scope: "credential:mail_scope"
      extract:
        token: "$.token"%s
    inject:
      - header: Authorization
        value: "Bearer {{token}}"
    refresh:
      trigger: status_code_401
      action: re_login
  health:
    path: /status
  tools:
    list_messages:
      method: GET
      path: /messages
      access: read
      params:
        folder: { type: string, in: query }
`, baseURL, ucsLoginPath, opt)
}

// aclServer is an API that enforces the scope of a session: a login may
// carry {"mailboxes": [...]}, and a session with one reaches only those
// mailboxes. It refuses a scope with another property (400) and one that
// names every mailbox (403), as an API with a ceiling per gateway does.
type aclServer struct {
	mu sync.Mutex
	// scopes holds the mailboxes of each session, nil for a session
	// without a scope.
	scopes map[string][]string
	// logins are the login bodies in order.
	logins []string
}

func (s *aclServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set(testHeaderContentType, testContentTypeJSON)
	fail := func(status int, code string) {
		w.WriteHeader(status)
		_, _ = fmt.Fprintf(w, `{"error":%q}`, code)
	}
	if r.URL.Path == ucsLoginPath {
		var raw json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&raw)
		s.logins = append(s.logins, string(raw))
		var body struct {
			Pass  string                     `json:"pass"`
			Scope map[string]json.RawMessage `json:"scope"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.Pass == "" {
			fail(http.StatusBadRequest, "invalid_request")
			return
		}
		var mailboxes []string
		for key, value := range body.Scope {
			if key != "mailboxes" || json.Unmarshal(value, &mailboxes) != nil {
				fail(http.StatusBadRequest, "invalid_request")
				return
			}
		}
		for _, m := range mailboxes {
			if m == "*" {
				fail(http.StatusForbidden, "scope_too_wide")
				return
			}
		}
		token := fmt.Sprintf("session-%d", len(s.logins))
		if s.scopes == nil {
			s.scopes = map[string][]string{}
		}
		if body.Scope != nil && mailboxes == nil {
			mailboxes = []string{} // a scope that names no mailbox reaches none
		}
		s.scopes[token] = mailboxes
		_, _ = fmt.Fprintf(w, `{"token":%q}`, token)
		return
	}
	token := strings.TrimPrefix(r.Header.Get(testHeaderAuth), "Bearer ")
	mailboxes, known := s.scopes[token]
	if !known {
		fail(http.StatusUnauthorized, "unauthorized")
		return
	}
	if folder := r.URL.Query().Get(aclParamFolder); folder != "" && mailboxes != nil {
		reached := false
		for _, m := range mailboxes {
			reached = reached || m == folder
		}
		if !reached {
			fail(http.StatusNotFound, "not_found")
			return
		}
	}
	_, _ = fmt.Fprint(w, `{"ok":true}`)
}

func (s *aclServer) loginBodies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.logins...)
}

// aclUserCredentials are the usual entries: the secret, and the limit as
// an optional value that is no secret.
func aclUserCredentials() []UserCredential {
	return []UserCredential{
		{Name: ucCredential, Format: UserCredentialFormatSecret},
		{Name: aclScope, Label: "ACL", Format: UserCredentialFormatACL, Optional: true},
	}
}

// newACLAdapter loads the DADL text with user credentials declared.
func newACLAdapter(t *testing.T, dadlText string, users credentials.UserStore, declared []UserCredential) (*RESTAdapter, error) {
	t.Helper()
	spec, err := dadl.ParseBytes([]byte(dadlText))
	if err != nil {
		t.Fatalf("parse dadl: %v", err)
	}
	return NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Scope:           &BackendScope{EntryName: ucBackend, Owners: dadl.NewCredentialOwners(ucBackend)},
		UserCredentials: &UserCredentialBinding{Credentials: declared, Store: users, EnrollURL: ucEnrollURL},
	})
}

func aclPut(t *testing.T, users *credentials.FileUserStore, account, name, value string) {
	t.Helper()
	slot := credentials.UserSlot{UserID: ucAlice, Backend: ucBackend, Account: account, Name: name}
	if err := users.PutUser(context.Background(), slot, value); err != nil {
		t.Fatal(err)
	}
}

// TestUnmarshalBackendConfig_UserCredentialOptionalAndACL pins the two keys
// an entry of user_credentials takes for a limit: format acl and optional.
func TestUnmarshalBackendConfig_UserCredentialOptionalAndACL(t *testing.T) {
	entry := "backends:\n  - name: mail\n    transport: rest\n    dadl: mail.dadl\n    user_credentials:\n      - name: mail_login\n        format: basic\n"
	var cfg BackendConfig
	err := UnmarshalBackendConfig([]byte(entry+"      - name: mail_scope\n        label: ACL\n        format: ACL\n        optional: true\n"), &cfg)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	got := cfg.Backends[0].UserCredentials
	want := UserCredential{Name: aclScope, Label: "ACL", Format: UserCredentialFormatACL, Optional: true}
	if len(got) != 2 || got[1] != want || got[0].Optional {
		t.Fatalf("user credentials = %+v, want the second as %+v and the first not optional", got, want)
	}
	if got[0].Secret() != true || got[1].Secret() != false {
		t.Fatalf("Secret(): basic %v, acl %v; want true, false", got[0].Secret(), got[1].Secret())
	}

	for name, tail := range map[string]string{
		"a word":     "      - name: mail_scope\n        optional: maybe\n",
		"a sequence": "      - name: mail_scope\n        optional: [true]\n",
		"a number":   "      - name: mail_scope\n        optional: 2\n",
		"no value":   "      - name: mail_scope\n        optional:\n",
		"a text":     "      - name: mail_scope\n        optional: \"true\"\n",
	} {
		var bad BackendConfig
		if err := UnmarshalBackendConfig([]byte(entry+tail), &bad); err == nil {
			t.Errorf("optional as %s: accepted as %+v", name, bad.Backends[0].UserCredentials)
		}
	}
	var off BackendConfig
	if err := UnmarshalBackendConfig([]byte(entry+"      - name: mail_scope\n        optional: false\n"), &off); err != nil || off.Backends[0].UserCredentials[1].Optional {
		t.Errorf("optional: false: %v, %+v", err, off.Backends)
	}
}

// TestNormalizeACL pins what the page stores for a limit: one JSON object,
// compact, bounded, and an error that does not repeat what was entered.
func TestNormalizeACL(t *testing.T) {
	ok := map[string]string{
		aclInboxOnly: aclInboxOnly,
		" {\n  \"mailboxes\": [ \"INBOX\", \"Projects/*\" ],\n  \"send\": false\n}\n": `{"mailboxes":["INBOX","Projects/*"],"send":false}`,
		`{}`: `{}`,
	}
	for in, want := range ok {
		got, err := NormalizeACL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeACL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", `["Sent"]`, `"Sent"`, `12`, `1.5`, `{"calendars":`, `{"a":1} {"b":2}`, `{'a':1}`, `calendars: Work`} {
		got, err := NormalizeACL(in)
		if err == nil {
			t.Errorf("NormalizeACL(%q) = %q, want an error", in, got)
			continue
		}
		if strings.TrimSpace(in) != "" && strings.Contains(err.Error(), strings.TrimSpace(in)) {
			t.Errorf("the error repeats the value: %v", err)
		}
	}
	long := `{"mailboxes":["` + strings.Repeat("x", MaxUserACLBytes) + `"]}`
	if _, err := NormalizeACL(long); err == nil {
		t.Error("a value over the bound was accepted")
	}
	fits := `{"m":"` + strings.Repeat("x", MaxUserACLBytes-len(`{"m":""}`)) + `"}`
	if got, err := NormalizeACL(fits); err != nil || len(got) != MaxUserACLBytes {
		t.Errorf("a value of exactly the bound: %d bytes, %v", len(got), err)
	}
}

// TestNewRESTAdapter_ACLAndOptionalNeedTheDADL pins when a backend with a
// limit loads: the DADL has to be able to carry the value as an object and
// to leave an optional one out. A backend that cannot is refused; it would
// otherwise fail every call of an account without a limit, or send the
// limit as text.
func TestNewRESTAdapter_ACLAndOptionalNeedTheDADL(t *testing.T) {
	const base = testBaseURLExample
	secret := UserCredential{Name: ucCredential, Format: UserCredentialFormatSecret}
	limit := UserCredential{Name: aclScope, Format: UserCredentialFormatACL, Optional: true}
	required := UserCredential{Name: aclScope, Format: UserCredentialFormatACL}
	cases := []struct {
		name     string
		dadlText string
		declared []UserCredential
		want     string // part of the error, "" for a backend that loads
	}{
		{"an optional limit", aclDADL(base, true), []UserCredential{secret, limit}, ""},
		{"a limit every account must hold", aclDADL(base, true), []UserCredential{secret, required}, ""},
		{"a required limit in a DADL without optional fields", aclDADL(base, false), []UserCredential{secret, required}, ""},
		{"only the secret is per user", aclDADL(base, true), []UserCredential{secret}, ""},
		{"optional, and the DADL cannot leave it out", aclDADL(base, false), []UserCredential{secret, limit}, "cannot leave it out"},
		{"the secret declared optional", aclDADL(base, true), []UserCredential{{Name: ucCredential, Optional: true, Format: UserCredentialFormatSecret}, required}, "which needs format acl"},
		{"a secret in an optional field declared optional", aclDADL(base, true), []UserCredential{secret, {Name: aclScope, Optional: true, Format: UserCredentialFormatSecret}}, "which needs format acl"},
		{"every credential optional", aclDADL(base, true), []UserCredential{limit}, "every credential is optional"},
		{"a limit for a DADL without a login", ucDADL(base, ""), []UserCredential{{Name: ucCredential, Format: UserCredentialFormatACL}}, "auth.type session"},
		{"an unknown format", aclDADL(base, true), []UserCredential{secret, {Name: aclScope, Format: "json"}}, "is not known"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			adapter, err := newACLAdapter(t, c.dadlText, ucUserStore(t), c.declared)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Fatalf("NewRESTAdapter = %v, want an error with %q", err, c.want)
			case c.want == "" && len(adapter.UserCredentials()) != len(c.declared):
				t.Fatalf("UserCredentials() = %+v, want the %d declared", adapter.UserCredentials(), len(c.declared))
			}
		})
	}
}

// TestRESTAdapter_ACL_TheAPIEnforcesWhatTheUserStored is the limit end to
// end: an account without one reaches every mailbox, an account with one
// reaches what it names and nothing else, the agent picks the account and
// cannot change what it reaches, and a limit the API refuses is reported
// as refused by the check.
func TestRESTAdapter_ACL_TheAPIEnforcesWhatTheUserStored(t *testing.T) {
	api := &aclServer{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	users := ucUserStore(t)
	adapter, err := newACLAdapter(t, aclDADL(srv.URL, true), users, aclUserCredentials())
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	aclPut(t, users, ucAccount, ucCredential, "alice-pw")
	aclPut(t, users, ucSecond, ucCredential, "office-pw")
	aclPut(t, users, ucSecond, aclScope, aclInboxOnly)

	call := func(account, folder string) *ToolResult {
		t.Helper()
		res, err := adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{credentials.AccountParam: account, aclParamFolder: folder})
		if err != nil {
			t.Fatalf("call as %s for %s: %v", account, folder, err)
		}
		return res
	}
	if res := call(ucAccount, aclArchive); res.IsError {
		t.Fatalf("the account without a limit does not reach %s: %s", aclArchive, ucText(res))
	}
	if res := call(ucSecond, ucInbox); res.IsError {
		t.Fatalf("the limited account does not reach %s: %s", ucInbox, ucText(res))
	}
	if res := call(ucSecond, aclArchive); !res.IsError {
		t.Fatalf("the limited account reached %s: %s", aclArchive, ucText(res))
	}

	bodies := api.loginBodies()
	if len(bodies) != 2 {
		t.Fatalf("%d logins, want one per account: %v", len(bodies), bodies)
	}
	if strings.Contains(bodies[0], `"scope"`) {
		t.Errorf("the login of the account without a limit carries a scope: %s", bodies[0])
	}
	if !strings.Contains(bodies[1], `"scope":`+aclInboxOnly) {
		t.Errorf("the login of the limited account = %s, want the scope as the object %s", bodies[1], aclInboxOnly)
	}

	// The limit is not a parameter: a call that passes one is refused for
	// that parameter, before anything is sent.
	sent := len(api.loginBodies())
	res, err := adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{credentials.AccountParam: ucSecond, aclParamFolder: aclArchive, "scope": map[string]any{"mailboxes": []any{aclArchive}}})
	refusal := ""
	switch {
	case err != nil:
		refusal = err.Error()
	case res != nil && res.IsError:
		refusal = ucText(res)
	default:
		t.Fatalf("a call that passes a scope of its own reached %s", aclArchive)
	}
	if !strings.Contains(refusal, `unknown parameter "scope"`) {
		t.Errorf("the call with a scope of its own was refused with %q, want the refusal of the parameter", refusal)
	}
	if len(api.loginBodies()) != sent {
		t.Error("the call with a scope of its own led to a login")
	}

	// The check after a save logs in with the limit: one the API refuses
	// counts as refused, so the page puts the earlier state back.
	for name, scope := range map[string]string{
		"not well-formed for the API": `{"folders":["INBOX"]}`,
		"wider than the API allows":   `{"mailboxes":["*"]}`,
	} {
		aclPut(t, users, ucSecond, aclScope, scope)
		if got := adapter.CheckUserCredentials(ucCtx(ucAlice), ucSecond); got.Outcome != UserCheckRefused {
			t.Errorf("check of a limit that is %s = %q (%s), want %q", name, got.Outcome, got.Detail, UserCheckRefused)
		} else if strings.Contains(got.Detail, "INBOX") || strings.Contains(got.Detail, "scope_too_wide") || strings.Contains(got.Detail, "invalid_request") {
			t.Errorf("the detail carries content of the request or the answer: %q", got.Detail)
		}
	}
	aclPut(t, users, ucSecond, aclScope, aclInboxOnly)
	if got := adapter.CheckUserCredentials(ucCtx(ucAlice), ucSecond); got.Outcome != UserCheckAccepted {
		t.Errorf("check of a limit the API takes = %q (%s), want %q", got.Outcome, got.Detail, UserCheckAccepted)
	}
	// The other account kept its session through all of that.
	before := len(api.loginBodies())
	if res := call(ucAccount, aclArchive); res.IsError {
		t.Fatalf("the other account: %s", ucText(res))
	}
	if after := len(api.loginBodies()); after != before {
		t.Errorf("the other account logged in again (%d logins, were %d)", after, before)
	}
}

// TestRESTAdapter_ACL_RequiredByTheOperator pins the entry without
// optional: an account without the limit is not usable, and nothing is
// sent for it.
func TestRESTAdapter_ACL_RequiredByTheOperator(t *testing.T) {
	api := &aclServer{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	users := ucUserStore(t)
	declared := aclUserCredentials()
	declared[1].Optional = false
	adapter, err := newACLAdapter(t, aclDADL(srv.URL, true), users, declared)
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	aclPut(t, users, ucAccount, ucCredential, "alice-pw")

	res, err := adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("an account without the required limit: result %+v, err %v; want an error result", res, err)
	}
	if code, _ := res.Metadata[metadataKeyErrorCode].(string); code != "user_credential_"+credentials.UserCredentialIncomplete {
		t.Errorf("error code = %q, want user_credential_%s", code, credentials.UserCredentialIncomplete)
	}
	if n := len(api.loginBodies()); n != 0 {
		t.Fatalf("%d logins were sent without the limit", n)
	}

	aclPut(t, users, ucAccount, aclScope, aclInboxOnly)
	if res, err := adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{aclParamFolder: ucInbox}); err != nil || res.IsError {
		t.Fatalf("with the limit stored: %v, %s", err, ucText(res))
	}
}
