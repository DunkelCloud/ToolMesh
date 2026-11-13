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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

const (
	ucsLoginPath = "/session"
	ucsGood      = "good-login"   //nolint:gosec // test fixture, not a credential
	ucsOffice    = "office-login" //nolint:gosec // test fixture, not a credential
	ucsWrong     = "wrong-login"  //nolint:gosec // test fixture, not a credential
)

// ucsDADL is a mail API behind a session login that takes the user's
// credential, with a health check.
func ucsDADL(baseURL string) string {
	return fmt.Sprintf(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: %s
  description: "A mail API behind a session login"
  auth:
    type: session
    login:
      method: POST
      path: %s
      body:
        pass: "credential:mail_login"
      extract:
        token: "$.token"
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
`, baseURL, ucsLoginPath)
}

// ucsServer is the session API: it accepts the logins in good, hands out a
// session per login and counts both.
type ucsServer struct {
	mu     sync.Mutex
	good   map[string]bool
	logins []string // the secret of every login attempt
	calls  []string // the session of every other request
}

func (s *ucsServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w.Header().Set(testHeaderContentType, testContentTypeJSON)
	if r.URL.Path == ucsLoginPath {
		var body struct {
			Pass string `json:"pass"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.logins = append(s.logins, body.Pass)
		if !s.good[body.Pass] {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":"no such login"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"token":"session-of-%s"}`, body.Pass) //nolint:gosec // G705: a JSON answer of a test API, not a page
		return
	}
	session := strings.TrimPrefix(r.Header.Get(testHeaderAuth), "Bearer session-of-")
	s.calls = append(s.calls, session)
	if !s.good[session] {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_, _ = fmt.Fprint(w, `{"ok":true}`)
}

func (s *ucsServer) loginCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.logins)
}

func (s *ucsServer) lastLogin() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.logins) == 0 {
		return ""
	}
	return s.logins[len(s.logins)-1]
}

// TestRESTAdapter_CheckUserCredentials_UsesWhatIsStoredNow pins what the
// check of a stored account is for. It has to authenticate with the
// credentials stored now, not ride on the session an earlier call of the
// account opened: otherwise credentials the API would refuse are reported
// as accepted. And it has to leave the user's other accounts alone: their
// sessions are still good.
func TestRESTAdapter_CheckUserCredentials_UsesWhatIsStoredNow(t *testing.T) {
	api := &ucsServer{good: map[string]bool{ucsGood: true, ucsOffice: true}}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)
	spec, err := dadl.ParseBytes([]byte(ucsDADL(srv.URL)))
	if err != nil {
		t.Fatalf("parse dadl: %v", err)
	}
	f := &ucFixture{users: ucUserStore(t)}
	f.adapter, err = NewRESTAdapter(spec, &testCredStore{}, quietLogger(), RESTAdapterOptions{
		AllowPrivateURL: true,
		Scope:           &BackendScope{EntryName: ucBackend, Owners: dadl.NewCredentialOwners(ucBackend)},
		UserCredentials: &UserCredentialBinding{
			Credentials: []UserCredential{{Name: ucCredential, Format: UserCredentialFormatSecret}},
			Store:       f.users,
			EnrollURL:   ucEnrollURL,
		},
	})
	if err != nil {
		t.Fatalf("new adapter: %v", err)
	}
	f.store(t, ucAlice, ucAccount, ucsGood)
	f.store(t, ucAlice, ucSecond, ucsOffice)

	call := func(account string) {
		t.Helper()
		res, err := f.adapter.Execute(ucCtx(ucAlice), ucToolList, map[string]any{"account": account})
		if err != nil || res.IsError {
			t.Fatalf("call as %s: %v, %s", account, err, ucText(res))
		}
	}
	call(ucAccount)
	call(ucSecond)
	if logins := api.loginCount(); logins != 2 {
		t.Fatalf("logins after the first call of each account = %d, want 2", logins)
	}

	// The first account gets credentials the API does not accept. Its
	// session from the call above would still pass.
	f.store(t, ucAlice, ucAccount, ucsWrong)
	got := f.adapter.CheckUserCredentials(ucCtx(ucAlice), ucAccount)
	if got.Outcome != UserCheckRefused {
		t.Errorf("check of credentials the API refuses = %q (%s), want %q: the check rode on the account's earlier session", got.Outcome, got.Detail, UserCheckRefused)
	}
	if last := api.lastLogin(); last != ucsWrong {
		t.Errorf("the check logged in with %q, want the credentials stored now", last)
	}
	if strings.Contains(got.Detail, ucsWrong) {
		t.Errorf("the detail carries the credential: %q", got.Detail)
	}

	// The other account kept its session: its next call needs no login.
	loginsBefore := api.loginCount()
	call(ucSecond)
	if logins := api.loginCount(); logins != loginsBefore {
		t.Errorf("the other account logged in again after the check: %d logins, want %d", logins, loginsBefore)
	}

	// With accepted credentials stored again, the check passes and the
	// account's next call uses the session the check opened.
	f.store(t, ucAlice, ucAccount, ucsGood)
	if got := f.adapter.CheckUserCredentials(ucCtx(ucAlice), ucAccount); got.Outcome != UserCheckAccepted {
		t.Errorf("check of accepted credentials = %q (%s)", got.Outcome, got.Detail)
	}
	loginsBefore = api.loginCount()
	call(ucAccount)
	if logins := api.loginCount(); logins != loginsBefore {
		t.Errorf("the call after an accepted check logged in again: %d logins, want %d", logins, loginsBefore)
	}
}
