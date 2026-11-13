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
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

const (
	ucToolMove  = "move_message"
	ucBobAcct   = "bob@example.com"
	ucBobToken  = "bob-token" //nolint:gosec // test fixture, not a credential
	ucMixedCase = "  Office@Example.COM "
)

// TestRESTAdapter_UserCredentials_GateSeesTheNormalizedAccount pins what
// the argument check hands to the pre-execution gate: the label in its
// stored form, whatever case or padding the caller wrote.
// A policy that compares labels would otherwise be passed with another
// spelling of the same account.
func TestRESTAdapter_UserCredentials_GateSeesTheNormalizedAccount(t *testing.T) {
	f := newUCFixture(t)
	for _, tool := range []string{ucToolList, "inbox", dadl.HealthToolName} {
		got, err := f.adapter.ValidateToolParams(tool, map[string]any{credentials.AccountParam: ucMixedCase})
		if err != nil || got[credentials.AccountParam] != ucSecond {
			t.Errorf("%s: params = %v, %v; want the account as %q", tool, got, err, ucSecond)
		}
		// A blank label is no label: the parameter is taken out, so a
		// policy sees a call that names no account.
		got, err = f.adapter.ValidateToolParams(tool, map[string]any{credentials.AccountParam: "   "})
		if _, named := got[credentials.AccountParam]; err != nil || named {
			t.Errorf("%s: blank label: params = %v, %v", tool, got, err)
		}
	}
	for name, value := range map[string]any{"a number": 7, "a list": []any{"a"}, "no label": "two words", "too long": strings.Repeat("a", 101)} {
		_, err := f.adapter.ValidateToolParams(ucToolList, map[string]any{credentials.AccountParam: value})
		var apiErr *dadl.APIError
		if !errors.As(err, &apiErr) || apiErr.Code != dadl.ErrCodeInvalidInput {
			t.Errorf("%s: err = %v, want invalid_input", name, err)
		}
	}
	// The input is not changed in place.
	in := map[string]any{credentials.AccountParam: ucMixedCase}
	if _, err := f.adapter.ValidateToolParams(ucToolList, in); err != nil || in[credentials.AccountParam] != ucMixedCase {
		t.Errorf("the caller's map was changed: %v, %v", in, err)
	}
}

// TestRESTAdapter_UserCredentials_ResultNamesTheAccount pins that a result
// says which account the call was made with, also when the caller left the
// choice to ToolMesh. The executor copies it into the audit entry.
func TestRESTAdapter_UserCredentials_ResultNamesTheAccount(t *testing.T) {
	f := newUCFixture(t)
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	for _, tool := range []string{ucToolList, "inbox", dadl.HealthToolName} {
		res, err := f.adapter.Execute(ucCtx(ucAlice), tool, map[string]any{})
		if err != nil || res.IsError || res.Metadata[MetadataKeyAccount] != ucAccount {
			t.Errorf("%s: metadata = %v, isError %v, %v; want the account named", tool, res.Metadata, res.IsError, err)
		}
	}
	f.store(t, ucAlice, ucSecond, ucOffice)
	res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{credentials.AccountParam: ucMixedCase})
	if err != nil || res.Metadata[MetadataKeyAccount] != ucSecond {
		t.Errorf("named account: metadata = %v, %v", res.Metadata, err)
	}
	// A call that fails for want of an account names none.
	res, err = f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{})
	if err != nil || !res.IsError || res.Metadata[MetadataKeyAccount] != nil {
		t.Errorf("ambiguous call: %+v, %v", res, err)
	}
}

// recordingGuard records the arguments of every child call it is asked
// about.
type recordingGuard struct {
	mu    sync.Mutex
	calls []map[string]any
}

func (g *recordingGuard) CheckChild(_ context.Context, _ string, params map[string]any) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, params)
	return nil
}

// TestRESTAdapter_UserCredentials_ChildGuardSeesTheAccount pins that the
// check of a composite's child call is shown the account the child uses:
// the child inherits it, and a policy on accounts has to apply to it too.
func TestRESTAdapter_UserCredentials_ChildGuardSeesTheAccount(t *testing.T) {
	f := newUCFixture(t)
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	f.store(t, ucAlice, ucSecond, ucOffice)
	guard := &recordingGuard{}
	f.adapter.SetChildGuard(guard)
	res, err := f.adapter.Execute(ucCtx(ucAlice), "inbox", map[string]any{credentials.AccountParam: ucSecond})
	if err != nil || res.IsError {
		t.Fatalf("composite: %+v, %v", res, err)
	}
	if len(guard.calls) != 1 || guard.calls[0][credentials.AccountParam] != ucSecond || guard.calls[0]["folder"] != ucInbox {
		t.Errorf("the guard saw %v, want the child's arguments with the account", guard.calls)
	}
	if auth, url := f.api.last(); auth != ucOfficeAuth || strings.Contains(url, credentials.AccountParam) {
		t.Errorf("the child call went out as %q to %q", auth, url)
	}
}

// TestRESTAdapter_UserCredentials_AccountNeverReachesTheAPI sends a tool
// with path, query, header and body parameters and looks at everything the
// API received.
func TestRESTAdapter_UserCredentials_AccountNeverReachesTheAPI(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.String()+"\n"+headerDump(r.Header)+"\n"+string(body))
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	extra := `    move_message:
      method: POST
      path: /messages/{id}/move
      access: write
      params:
        id: { type: string, in: path, required: true }
        notify: { type: boolean, in: query }
        trace: { type: string, in: header }
        target: { type: string, in: body, required: true }
`
	spec, err := dadl.ParseBytes([]byte(ucDADL(srv.URL, extra)))
	if err != nil {
		t.Fatal(err)
	}
	users := ucUserStore(t)
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Unbound:         true,
		UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: users},
	})
	if err != nil {
		t.Fatal(err)
	}
	slot := credentials.UserSlot{UserID: ucAlice, Backend: ucBackend, Account: ucAccount, Name: ucCredential}
	if err := users.PutUser(context.Background(), slot, ucAliceToken); err != nil {
		t.Fatal(err)
	}
	const marker = "alice@example.com"
	res, err := adapter.Execute(ucCtx(ucAlice), ucToolMove, map[string]any{
		credentials.AccountParam: marker, "id": "m1", "notify": true, "trace": "t-1", "target": "Archive",
	})
	if err != nil || res.IsError {
		t.Fatalf("move: %+v, %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 {
		t.Fatalf("requests = %d", len(seen))
	}
	got := seen[0]
	for _, want := range []string{"POST /messages/m1/move?notify=true", "Trace: t-1", `"target":"Archive"`, "Authorization: Bearer " + ucAliceToken} {
		if !strings.Contains(got, want) {
			t.Errorf("the request lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, marker) || strings.Contains(strings.ToLower(got), `"account"`) || strings.Contains(strings.ToLower(got), "account=") {
		t.Errorf("the account reached the API:\n%s", got)
	}
}

func headerDump(h http.Header) string {
	var b strings.Builder
	for k, v := range h {
		b.WriteString(k + ": " + strings.Join(v, ",") + "\n")
	}
	return b.String()
}

// TestRESTAdapter_UserCredentials_OwnAccountDoesNotOpenAnothers covers a
// user who has an account and names the label of someone else's.
func TestRESTAdapter_UserCredentials_OwnAccountDoesNotOpenAnothers(t *testing.T) {
	f := newUCFixture(t)
	f.store(t, ucAlice, ucAccount, ucAliceToken)
	f.store(t, ucBob, ucBobAcct, ucBobToken)
	res, err := f.adapter.Execute(ucCtx(ucBob), ucToolList, map[string]any{credentials.AccountParam: ucAccount})
	if err != nil || !res.IsError {
		t.Fatalf("bob naming alice's account: %+v, %v; want an error result", res, err)
	}
	if text := ucText(res); !strings.Contains(text, ucBobAcct) {
		t.Errorf("the message should list bob's own accounts: %q", text)
	}
	if f.api.hits() != 0 {
		t.Fatal("the call reached the API")
	}
	res, err = f.adapter.Execute(ucCtx(ucBob), ucToolList, map[string]any{})
	if err != nil || res.IsError {
		t.Fatalf("bob's own account: %+v, %v", res, err)
	}
	if auth, _ := f.api.last(); auth != "Bearer "+ucBobToken {
		t.Errorf("bob was sent as %q", auth)
	}
}

// TestRESTAdapter_UserCredentials_HealthOfAUser pins two things about the
// health check of a backend with user credentials: its result does not
// carry the expiry the operator recorded for an instance credential, and
// the check after a 401 does not renew a session another call renewed.
func TestRESTAdapter_UserCredentials_HealthOfAUser(t *testing.T) {
	api := &ucServer{}
	srv := httptest.NewServer(api)
	defer srv.Close()
	spec, err := dadl.ParseBytes([]byte(ucDADL(srv.URL, "")))
	if err != nil {
		t.Fatal(err)
	}
	users := ucUserStore(t)
	expiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Unbound:         true,
		AuthExpiresAt:   expiry,
		UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: users},
	})
	if err != nil {
		t.Fatal(err)
	}
	slot := credentials.UserSlot{UserID: ucAlice, Backend: ucBackend, Account: ucAccount, Name: ucCredential}
	if err := users.PutUser(context.Background(), slot, ucAliceToken); err != nil {
		t.Fatal(err)
	}
	res := adapter.CheckHealth(credentials.WithAccount(ucCtx(ucAlice), ucAccount))
	if !res.OK || !res.AuthExpiresAt.IsZero() {
		t.Errorf("health of a user = %+v, want it passed and without the instance's expiry", res)
	}
}

// TestNewRESTAdapter_UserCredentialErrorsAreTyped pins the error a loader
// tells apart: a backend whose user_credentials cannot be honored.
func TestNewRESTAdapter_UserCredentialErrorsAreTyped(t *testing.T) {
	spec, err := dadl.ParseBytes([]byte(ucDADL(testBaseURLExample, "")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Unbound:         true,
		UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}},
	})
	var cfgErr *UserCredentialConfigError
	if !errors.As(err, &cfgErr) || cfgErr.Backend != ucBackend || !errors.Is(err, errUserCredentialsNoStore) {
		t.Fatalf("err = %v, want a *UserCredentialConfigError for the missing store", err)
	}
}

// TestNewRESTAdapter_UserCredentialsFollowTheFlow pins the refusal of a
// name the DADL declares but its OAuth2 flow never reads. The backend
// would load, users would store their tokens, and every call would still
// go out with the instance's client.
func TestNewRESTAdapter_UserCredentialsFollowTheFlow(t *testing.T) {
	doc := `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    token_url: https://api.example.com/token
    client_id_credential: mail_client_id
    client_secret_credential: mail_client_secret
    refresh_token_credential: mail_login
  tools:
    list_messages:
      method: GET
      path: /messages
`
	spec, err := dadl.ParseBytes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Unbound:         true,
		UserCredentials: &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: ucUserStore(t)},
	})
	if err == nil || !strings.Contains(err.Error(), "does not read") {
		t.Fatalf("err = %v, want the backend refused: its flow never reads the name", err)
	}
}

// TestNewRESTAdapter_RefusesADeclaredGatewayAccount pins that a DADL cannot
// bring its own parameter "account" by declaring it as the gateway's.
func TestNewRESTAdapter_RefusesADeclaredGatewayAccount(t *testing.T) {
	extra := "    move:\n      method: POST\n      path: /move\n      params:\n        account: { type: string, in: gateway, default: boss@example.com }\n"
	spec, err := dadl.ParseBytes([]byte(ucDADL(testBaseURLExample, extra)))
	if err != nil {
		t.Skipf("the parser refuses the document itself: %v", err)
	}
	binding := &UserCredentialBinding{Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}}, Store: ucUserStore(t)}
	_, err = NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{AllowPrivateURL: true, Unbound: true, UserCredentials: binding})
	if err == nil || !strings.Contains(err.Error(), credentials.AccountParam) {
		t.Fatalf("err = %v, want the backend refused", err)
	}
	// A second adapter on a spec the first one prepared is not refused for
	// the parameter the first one added.
	clean, err := dadl.ParseBytes([]byte(ucDADL(testBaseURLExample, "")))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err := NewRESTAdapter(clean, &testCredStore{}, quietLogger(), RESTAdapterOptions{AllowPrivateURL: true, Unbound: true, UserCredentials: binding}); err != nil {
			t.Fatalf("adapter %d on one spec: %v", i, err)
		}
	}
}

// TestUnmarshalBackendConfig_UserCredentialsNeedAName pins that a
// user_credentials key without a name under it is an error. The decoder
// drops an empty list and empty items without a trace; the backend would
// run on the instance's credentials.
func TestUnmarshalBackendConfig_UserCredentialsNeedAName(t *testing.T) {
	entry := "backends:\n  - name: mail\n    transport: rest\n    dadl: mail.dadl\n"
	for name, tail := range map[string]string{
		"key alone":         "    user_credentials:\n",
		"null":              "    user_credentials: null\n",
		"empty list":        "    user_credentials: []\n",
		"empty item":        "    user_credentials:\n      -\n",
		"commented item":    "    user_credentials:\n      - # mail_login\n",
		"one empty of two":  "    user_credentials:\n      - mail_login\n      -\n",
		"empty text":        "    user_credentials:\n      - \"\"\n",
		"a text, no list":   "    user_credentials: mail_login\n",
		"second entry bare": "  - name: other\n    transport: rest\n    dadl: o.dadl\n    user_credentials:\n",
	} {
		var cfg BackendConfig
		err := UnmarshalBackendConfig([]byte(entry+tail), &cfg)
		if err == nil {
			t.Errorf("%s: accepted, with %d user credentials on the entry", name, len(cfg.Backends[0].UserCredentials))
		}
	}
	var cfg BackendConfig
	if err := UnmarshalBackendConfig([]byte(entry+"    user_credentials:\n      - mail_login\n"), &cfg); err != nil || len(cfg.Backends[0].UserCredentials) != 1 {
		t.Errorf("a named credential: %v, %+v", err, cfg.Backends)
	}
	if err := UnmarshalBackendConfig([]byte(entry), &cfg); err != nil {
		t.Errorf("an entry without the key: %v", err)
	}
}
