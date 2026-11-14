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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Fixtures of the user credential tests.
const (
	ucBackend    = "mail"
	ucCredential = "mail_login"
	ucAlice      = "alice"
	ucBob        = "bob"
	ucAccount    = "alice@example.com"
	ucSecond     = "office@example.com"
	ucEnrollURL  = "https://toolmesh.example.com/credentials"
	ucInstance   = "instance-token" //nolint:gosec // test fixture, not a credential
	ucToolList   = "list_messages"
	ucAliceToken = "alice-token"  //nolint:gosec // test fixture, not a credential
	ucOffice     = "office-token" //nolint:gosec // test fixture, not a credential
	ucOfficeAuth = "Bearer " + ucOffice
	ucInbox      = "INBOX"
)

// ucDADL is a bearer-auth mail API with two tools, a composite and a health
// check; extra is appended to the tools.
func ucDADL(baseURL, extra string) string {
	return fmt.Sprintf(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: %s
  description: "A mail API"
  auth:
    type: bearer
    credential: mail_login
  health:
    path: /status
  tools:
    list_messages:
      method: GET
      path: /messages
      access: read
      params:
        folder: { type: string, in: query }
    get_message:
      method: GET
      path: /messages/{id}
      access: read
      params:
        id: { type: string, in: path, required: true }
%s
  composites:
    inbox:
      description: "List the inbox"
      access: read
      code: "return api.list_messages({folder: 'INBOX'});"
`, baseURL, extra)
}

// ucServer records every request it gets and answers with the status set.
type ucServer struct {
	mu     sync.Mutex
	status int
	auths  []string
	urls   []string
}

func (s *ucServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.auths = append(s.auths, r.Header.Get(testHeaderAuth))
	s.urls = append(s.urls, r.URL.String())
	status := s.status
	s.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	w.Header().Set(testHeaderContentType, testContentTypeJSON)
	w.WriteHeader(status)
	// The answer repeats the credential, as some APIs do in an error: what
	// is built from the answer must not pass it on.
	_, _ = fmt.Fprintf(w, `{"ok":true,"message":"seen %s"}`, r.Header.Get(testHeaderAuth)) //nolint:gosec // G705: a JSON answer of a test API, not a page
}

func (s *ucServer) hits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.auths)
}

func (s *ucServer) last() (auth, url string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.auths) == 0 {
		return "", ""
	}
	return s.auths[len(s.auths)-1], s.urls[len(s.urls)-1]
}

// ucFixture is a backend "mail" whose mail_login every user stores for
// themselves, over an instance store that also holds a mail_login.
type ucFixture struct {
	adapter *RESTAdapter
	users   *credentials.FileUserStore
	api     *ucServer
}

func ucUserStore(t *testing.T) *credentials.FileUserStore {
	t.Helper()
	users, err := credentials.NewFileUserStore(t.TempDir(), bytes.Repeat([]byte{5}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	return users
}

func newUCFixture(t *testing.T) *ucFixture {
	t.Helper()
	api := &ucServer{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	spec, err := dadl.ParseBytes([]byte(ucDADL(srv.URL, "")))
	if err != nil {
		t.Fatalf("parse dadl: %v", err)
	}
	users := ucUserStore(t)
	instance := &testCredStore{creds: map[string]string{ucCredential: ucInstance}}
	adapter, err := NewRESTAdapter(spec, instance, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Scope:           &BackendScope{EntryName: ucBackend, Owners: dadl.NewCredentialOwners(ucBackend)},
		UserCredentials: &UserCredentialBinding{
			Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}},
			Store:       users,
			EnrollURL:   ucEnrollURL,
		},
	})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	adapter.SetChildGuard(AllowAllChildGuard{})
	return &ucFixture{adapter: adapter, users: users, api: api}
}

func (f *ucFixture) store(t *testing.T, user, account, value string) {
	t.Helper()
	slot := credentials.UserSlot{UserID: user, Backend: ucBackend, Account: account, Name: ucCredential}
	if err := f.users.PutUser(context.Background(), slot, value); err != nil {
		t.Fatal(err)
	}
}

func ucCtx(user string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: user, Authenticated: true})
}

func ucText(r *ToolResult) string {
	if r == nil || len(r.Content) == 0 {
		return ""
	}
	m, _ := r.Content[0].(map[string]any)
	s, _ := m["text"].(string)
	return s
}

// TestRESTAdapter_UserCredentials_PerUserAndNeverTheInstance is the rule
// end to end: a call is sent with its user's credential, a user without
// one gets told where to add it and nothing is sent, and the instance's
// credential of the same name is never used.
func TestRESTAdapter_UserCredentials_PerUserAndNeverTheInstance(t *testing.T) {
	f := newUCFixture(t)

	// Nothing stored: an error result with the remedy, not a failed call,
	// and no request to the API.
	res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || res == nil || !res.IsError {
		t.Fatalf("no credential: result %+v, err %v; want an error result", res, err)
	}
	text := ucText(res)
	if !strings.Contains(text, ucEnrollURL) || !strings.Contains(text, ucAlice) || strings.Contains(text, ucInstance) {
		t.Errorf("message = %q, want the user and the page's address", text)
	}
	if code := res.Metadata[metadataKeyErrorCode]; code != "user_credential_"+credentials.UserCredentialMissing {
		t.Errorf("error code = %v", code)
	}
	if f.api.hits() != 0 {
		t.Fatalf("a call without the user's credential reached the API (%d requests)", f.api.hits())
	}

	f.store(t, ucAlice, ucAccount, ucAliceToken)
	f.store(t, ucBob, "bob@example.com", "bob-token")
	for user, want := range map[string]string{ucAlice: "Bearer " + ucAliceToken, ucBob: "Bearer bob-token"} {
		res, err := f.adapter.Execute(ucCtx(user), ucToolList, map[string]any{"folder": ucInbox})
		if err != nil || res.IsError {
			t.Fatalf("%s: %+v, %v", user, res, err)
		}
		if got, _ := f.api.last(); got != want {
			t.Errorf("%s: Authorization = %q, want %q", user, got, want)
		}
	}

	// A call without a user is refused, also for the health check.
	before := f.api.hits()
	res, err = f.adapter.Execute(context.Background(), ucToolList, map[string]any{})
	if err != nil || !res.IsError || res.Metadata[metadataKeyErrorCode] != "user_credential_"+credentials.UserCredentialNoUser {
		t.Errorf("no user: %+v, %v", res, err)
	}
	if health := f.adapter.CheckHealth(context.Background()); health.OK {
		t.Error("the health check passed without a user")
	}
	if f.api.hits() != before {
		t.Error("a call without a user reached the API")
	}
}

// TestRESTAdapter_UserCredentials_AccountParam covers the account a call
// selects: the parameter picks one of the user's accounts and never reaches
// the API.
func TestRESTAdapter_UserCredentials_AccountParam(t *testing.T) {
	f := newUCFixture(t)
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	f.store(t, ucAlice, ucSecond, ucOffice)

	// Two accounts and none named: the result lists them, nothing is sent.
	res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || !res.IsError {
		t.Fatalf("ambiguous: %+v, %v", res, err)
	}
	if text := ucText(res); !strings.Contains(text, ucAccount) || !strings.Contains(text, ucSecond) || !strings.Contains(text, credentials.AccountParam) {
		t.Errorf("message = %q, want both labels and the parameter", text)
	}
	if f.api.hits() != 0 {
		t.Fatal("an ambiguous call reached the API")
	}

	for account, want := range map[string]string{ucAccount: "Bearer " + ucAliceToken, "Office@Example.com": ucOfficeAuth} {
		res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{credentials.AccountParam: account, "folder": ucInbox})
		if err != nil || res.IsError {
			t.Fatalf("account %s: %+v, %v", account, res, err)
		}
		auth, url := f.api.last()
		if auth != want {
			t.Errorf("account %s: Authorization = %q, want %q", account, auth, want)
		}
		if strings.Contains(url, credentials.AccountParam) || !strings.Contains(url, "folder="+ucInbox) {
			t.Errorf("account %s: request URL = %q, the account must not reach the API", account, url)
		}
	}

	// A composite's child calls use the account the composite was called with.
	res, err = f.adapter.Execute(ucCtx(ucAlice), "inbox", map[string]any{credentials.AccountParam: ucSecond})
	if err != nil || res.IsError {
		t.Fatalf("composite: %+v, %v", res, err)
	}
	if auth, _ := f.api.last(); auth != ucOfficeAuth {
		t.Errorf("composite child: Authorization = %q", auth)
	}

	before := f.api.hits()
	for name, params := range map[string]map[string]any{
		"unknown account": {credentials.AccountParam: "nobody@example.com"},
		"not a label":     {credentials.AccountParam: "two words"},
	} {
		res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, params)
		if err != nil || !res.IsError {
			t.Errorf("%s: %+v, %v; want an error result", name, res, err)
		}
	}
	// Bob cannot use alice's account by naming it.
	res, err = f.adapter.Execute(ucCtx(ucBob), ucToolList, map[string]any{credentials.AccountParam: ucAccount})
	if err != nil || !res.IsError || strings.Contains(ucText(res), ucSecond) {
		t.Errorf("bob naming alice's account: %+v, %v", res, err)
	}
	if f.api.hits() != before {
		t.Error("a refused account reached the API")
	}
}

// TestRESTAdapter_UserCredentials_Schema pins that every tool declares the
// account parameter, so schemas and the argument check know it.
func TestRESTAdapter_UserCredentials_Schema(t *testing.T) {
	f := newUCFixture(t)
	tools, err := f.adapter.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 4 { // two tools, the composite, the health tool
		t.Fatalf("tools = %d", len(tools))
	}
	for _, tool := range tools {
		props, _ := tool.InputSchema[schemaKeyProperties].(map[string]any)
		if _, ok := props[credentials.AccountParam]; !ok {
			t.Errorf("tool %s does not declare %q: %v", tool.Name, credentials.AccountParam, props)
		}
		if req, _ := tool.InputSchema[schemaKeyRequired].([]string); len(req) > 0 {
			for _, r := range req {
				if r == credentials.AccountParam {
					t.Errorf("tool %s requires the account", tool.Name)
				}
			}
		}
	}
	if _, err := f.adapter.ValidateToolParams(ucToolList, map[string]any{credentials.AccountParam: ucAccount}); err != nil {
		t.Errorf("the argument check refuses the account: %v", err)
	}
	if _, err := f.adapter.ValidateToolParams(ucToolList, map[string]any{"acount": ucAccount}); err == nil {
		t.Error("the argument check accepts an undeclared parameter")
	}
	if got := f.adapter.UserCredentials(); len(got) != 1 || got[0].Name != ucCredential {
		t.Errorf("UserCredentials = %+v", got)
	}
	// The catalog says that calls are made as the caller, and the backend
	// is not collapsed with one that uses the instance's credentials.
	info := f.adapter.BackendSummaries()[0]
	if !strings.Contains(info.Description, "A mail API") || !strings.Contains(info.Description, credentials.AccountParam) || f.adapter.Description() != "A mail API" {
		t.Errorf("summary description = %q, Description() = %q", info.Description, f.adapter.Description())
	}
	if info.SpecID == f.adapter.spec.ContentHash {
		t.Error("the SpecID equals that of an instance without user credentials")
	}

	// The health tool takes the account as well and runs as the caller.
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	var observed int
	f.adapter.SetHealthObserver(func(string, HealthResult) { observed++ })
	res, err := f.adapter.Execute(ucCtx(ucAlice), dadl.HealthToolName, map[string]any{credentials.AccountParam: ucAccount})
	if err != nil || res.IsError || !strings.Contains(ucText(res), `"ok":true`) {
		t.Errorf("health tool: %+v, %v", res, err)
	}
	if auth, _ := f.api.last(); auth != "Bearer "+ucAliceToken {
		t.Errorf("health tool: Authorization = %q", auth)
	}
	if observed != 0 {
		t.Error("a user's own check result was reported to monitoring")
	}
}

func TestRESTAdapter_CheckUserCredentials(t *testing.T) {
	f := newUCFixture(t)
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	for status, want := range map[int]string{
		http.StatusOK:                  UserCheckAccepted,
		http.StatusUnauthorized:        UserCheckRefused,
		http.StatusForbidden:           UserCheckRefused,
		http.StatusInternalServerError: UserCheckUnknown,
	} {
		f.api.mu.Lock()
		f.api.status = status
		f.api.mu.Unlock()
		got := f.adapter.CheckUserCredentials(ucCtx(ucAlice), ucAccount)
		if got.Outcome != want {
			t.Errorf("status %d: outcome = %q (%s), want %q", status, got.Outcome, got.Detail, want)
		}
		if strings.Contains(got.Detail, ucAliceToken) {
			t.Errorf("status %d: the detail carries the credential: %q", status, got.Detail)
		}
	}
	before := f.api.hits()
	if got := f.adapter.CheckUserCredentials(ucCtx(ucBob), "bob@example.com"); got.Outcome != UserCheckUnknown {
		t.Errorf("no stored account: %+v", got)
	}
	if f.api.hits() != before {
		t.Error("a check without stored credentials reached the API")
	}

	// Without a declared health check there is nothing to check with.
	spec := bindingSpec(ucBackend, testBaseURLExample, bindingPath, ucCredential)
	plain, err := NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Unbound:         true,
		UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: f.users},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plain.CheckUserCredentials(ucCtx(ucAlice), ucAccount); got.Outcome != UserCheckUnavailable {
		t.Errorf("no health check: %+v", got)
	}
}

// TestRESTAdapter_UserCredentials_Refused covers the declarations a backend
// is refused for. Each of them would otherwise run with one credential for
// all callers where the operator asked for one per user.
func TestRESTAdapter_UserCredentials_Refused(t *testing.T) {
	users := ucUserStore(t)
	secret := func(name string) UserCredential {
		return UserCredential{Name: name, Format: UserCredentialFormatSecret}
	}
	cases := map[string]struct {
		binding *UserCredentialBinding
		env     map[string]string
		extra   string
		want    string
	}{
		"no store":       {binding: &UserCredentialBinding{Credentials: []UserCredential{secret(ucCredential)}}, want: "TOOLMESH_USER_CREDENTIALS_KEY"},
		"name not read":  {binding: &UserCredentialBinding{Credentials: []UserCredential{secret("mail_logn")}, Store: users}, want: "does not read"},
		"listed twice":   {binding: &UserCredentialBinding{Credentials: []UserCredential{secret(ucCredential), secret("MAIL_LOGIN")}, Store: users}, want: "twice"},
		"not a name":     {binding: &UserCredentialBinding{Credentials: []UserCredential{secret("mail login")}, Store: users}, want: "not a credential name"},
		"unknown format": {binding: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: "oauth"}}, Store: users}, want: "format"},
		"also remapped": {binding: &UserCredentialBinding{Credentials: []UserCredential{secret(ucCredential)}, Store: users},
			env: map[string]string{"CREDENTIAL_MAIL_LOGIN": "SOME_ENV"}, want: "remapped"},
		"account param taken": {binding: &UserCredentialBinding{Credentials: []UserCredential{secret(ucCredential)}, Store: users},
			extra: "    move:\n      method: POST\n      path: /move\n      params:\n        account: { type: string, in: body }\n", want: "account"},
	}
	for name, c := range cases {
		spec, err := dadl.ParseBytes([]byte(ucDADL(testBaseURLExample, c.extra)))
		if err != nil {
			t.Fatalf("%s: parse dadl: %v", name, err)
		}
		_, err = NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
			AllowPrivateURL: true,
			Scope:           &BackendScope{EntryName: ucBackend, Env: c.env, Owners: dadl.NewCredentialOwners(ucBackend)},
			UserCredentials: c.binding,
		})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one that mentions %q", name, err, c.want)
		}
	}
}

// TestRESTAdapter_UserCredentials_TwoEntriesOfOneDADL pins that two
// backends.yaml entries of the same DADL keep their users' credentials
// apart: an account stored for one is not used for the other.
func TestRESTAdapter_UserCredentials_TwoEntriesOfOneDADL(t *testing.T) {
	api := &ucServer{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	users := ucUserStore(t)
	owners := dadl.NewCredentialOwners("mail-a", "mail-b")
	build := func(entry string) *RESTAdapter {
		t.Helper()
		spec, err := dadl.ParseBytes([]byte(ucDADL(srv.URL, "")))
		if err != nil {
			t.Fatal(err)
		}
		spec.Backend.Name = entry
		a, err := NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
			AllowPrivateURL: true,
			// The DADL's name lies outside both namespaces; each entry
			// lists it.
			Scope:           &BackendScope{EntryName: entry, Credentials: []string{ucCredential}, Owners: owners},
			UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: users},
		})
		if err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		return a
	}
	a, b := build("mail-a"), build("mail-b")
	slot := credentials.UserSlot{UserID: ucAlice, Backend: "mail-a", Account: ucAccount, Name: ucCredential}
	if err := users.PutUser(context.Background(), slot, "token-a"); err != nil {
		t.Fatal(err)
	}

	res, err := a.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || res.IsError {
		t.Fatalf("mail-a: %+v, %v", res, err)
	}
	if auth, _ := api.last(); auth != "Bearer token-a" {
		t.Errorf("mail-a: Authorization = %q", auth)
	}
	before := api.hits()
	res, err = b.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || !res.IsError {
		t.Fatalf("mail-b: %+v, %v; want an error result, nothing is stored for it", res, err)
	}
	if api.hits() != before {
		t.Error("mail-b was called with the account stored for mail-a")
	}
}

func TestBackendEntry_UserCredentialsYAML(t *testing.T) {
	var cfg BackendConfig
	err := UnmarshalBackendConfig([]byte(`backends:
  - name: mail
    transport: rest
    dadl: mail.dadl
    user_credentials:
      - mail_token
      - name: mail_login
        label: Mailbox login
        hint: Your mail address and an app password.
        format: Basic
`), &cfg)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := cfg.Backends[0].UserCredentials
	if len(got) != 2 {
		t.Fatalf("user_credentials = %+v", got)
	}
	if got[0].Name != "mail_token" || got[0].Format != UserCredentialFormatSecret || got[0].Label != "" {
		t.Errorf("bare name: %+v", got[0])
	}
	if got[1].Name != ucCredential || got[1].Label != "Mailbox login" || got[1].Format != UserCredentialFormatBasic || got[1].Hint == "" {
		t.Errorf("mapping: %+v", got[1])
	}

	for name, doc := range map[string]string{
		"unknown field": "backends:\n  - name: mail\n    user_credentials:\n      - name: x\n        lable: y\n",
		"nested value":  "backends:\n  - name: mail\n    user_credentials:\n      - name: [x]\n",
		"a list":        "backends:\n  - name: mail\n    user_credentials:\n      - [x, y]\n",
	} {
		var bad BackendConfig
		if err := UnmarshalBackendConfig([]byte(doc), &bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestMCPAdapter_RefusesUserCredentials pins that an MCP backend that asks
// for user credentials is not registered: it could only run with one
// credential for all callers.
func TestMCPAdapter_RefusesUserCredentials(t *testing.T) {
	entries := []BackendEntry{
		{Name: "instance", Transport: transportTypeHTTP, URL: testMCPURLExample},
		{Name: "peruser", Transport: transportTypeHTTP, URL: testMCPURLExample, UserCredentials: []UserCredential{{Name: "x"}}},
	}
	a := NewMCPAdapterFromEntries(entries, &testCredStore{}, quietLogger())
	if a.BackendCount() != 1 {
		t.Errorf("registered %d backends, want only the one without user_credentials", a.BackendCount())
	}
}
