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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/enroll"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	forgetTool    = "list_messages"
	forgetName    = "mail_login"
	forgetFirst   = "first@example.com"
	forgetSecond  = "second@example.com"
	forgetOld     = "first-login"   //nolint:gosec // test fixture, not a credential
	forgetOther   = "second-login"  //nolint:gosec // test fixture, not a credential
	forgetChanged = "changed-login" //nolint:gosec // test fixture, not a credential
)

// forgetAPI is a mail API behind a session login: it hands out a session
// per login and remembers the secret of every login.
type forgetAPI struct {
	mu     sync.Mutex
	logins []string
}

func (a *forgetAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/session" {
		var body struct {
			Pass string `json:"pass"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		a.logins = append(a.logins, body.Pass)
		_, _ = fmt.Fprintf(w, `{"token":"session-of-%s"}`, body.Pass) //nolint:gosec // G705: a JSON answer of a test API, not a page
		return
	}
	_, _ = fmt.Fprintf(w, `{"session":%q}`, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) //nolint:gosec // G705: a JSON answer of a test API, not a page
}

func (a *forgetAPI) seen() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.logins...)
}

var forgetTokenRe = regexp.MustCompile(`name="token" value="([^"]+)"`)

// TestCredentialsPage_SaveForgetsTheSessionOfThatAccount pins the wiring
// between the page and the backend: after a user replaced the credentials
// of one account on the page, the next call of that account logs in with
// the new ones, and the user's other account keeps its session. The
// backend declares no health check, so nothing but the page's own word
// makes the backend drop the session.
func TestCredentialsPage_SaveForgetsTheSessionOfThatAccount(t *testing.T) {
	api := &forgetAPI{}
	srv := httptest.NewServer(api)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	dadlText := fmt.Sprintf(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mail
  type: rest
  base_url: %q
  description: "A mail API behind a session login"
  auth:
    type: session
    login:
      method: POST
      path: /session
      body:
        pass: "credential:%s"
      extract:
        token: "$.token"
    inject:
      - header: Authorization
        value: "Bearer {{token}}"
    refresh:
      trigger: status_code_401
      action: re_login
  tools:
    %s:
      method: GET
      path: /messages
`, srv.URL, forgetName, forgetTool)
	if err := os.WriteFile(filepath.Join(dir, "mail.dadl"), []byte(dadlText), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	backendsText := "backends:\n  - name: " + pageBackend + "\n    transport: rest\n    dadl: mail.dadl\n    user_credentials:\n      - " + forgetName + "\n"
	if err := os.WriteFile(backendsPath, []byte(backendsText), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(testUserKeyEnv, testUserKey())
	t.Setenv("TOOLMESH_DATA_DIR", t.TempDir())
	t.Setenv("TOOLMESH_ISSUER", pageOrigin+"/")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	setup, err := newUserCredentialSetup(cfg, quietLogger())
	if err != nil || setup == nil {
		t.Fatalf("newUserCredentialSetup = %v, %v", setup, err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, quietLogger(), nil, nil, nil, setup)
	reg := &userBackendRegistry{}
	reg.set(named)
	rest, ok := reg.get(pageBackend)
	if !ok {
		t.Fatalf("the per-user backend was not loaded: %v", named)
	}

	ctx := context.Background()
	for account, secret := range map[string]string{forgetFirst: forgetOld, forgetSecond: forgetOther} {
		slot := credentials.UserSlot{UserID: pageUserAlice, Backend: pageBackend, Account: account, Name: forgetName}
		if err := setup.store.PutUser(ctx, slot, secret); err != nil {
			t.Fatal(err)
		}
	}
	asAlice := userctx.WithUserContext(ctx, &userctx.UserContext{UserID: pageUserAlice, Authenticated: true})
	call := func(account, wantSession string) {
		t.Helper()
		res, err := rest.Execute(asAlice, forgetTool, map[string]any{"account": account})
		if err != nil || res == nil || res.IsError {
			t.Fatalf("call as %s: %v, %+v", account, err, res)
		}
		out, err := json.Marshal(res.Content)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(out), "session-of-"+wantSession) {
			t.Errorf("call as %s rode on %s, want the session of %q", account, out, wantSession)
		}
	}
	call(forgetFirst, forgetOld)
	call(forgetSecond, forgetOther)
	if got := api.seen(); len(got) != 2 {
		t.Fatalf("logins after the first call of each account = %v", got)
	}

	// Alice replaces the credentials of her first account on the page.
	page, err := newCredentialsPage(cfg, setup, reg, pageUsers{pageUserAlice: true}, &toolGrants{off: true}, nil, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	var cookies []*http.Cookie
	send := func(method, path string, form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		var req *http.Request
		if form == nil {
			req = httptest.NewRequestWithContext(ctx, method, pageOrigin+path, http.NoBody)
		} else {
			req = httptest.NewRequestWithContext(ctx, method, pageOrigin+path, strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set(pageFetchSite, pageSameOrigin)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		page.ServeHTTP(rec, req)
		for _, c := range rec.Result().Cookies() {
			if c.MaxAge >= 0 && c.Value != "" {
				cookies = append(cookies, c)
			}
		}
		return rec
	}
	if rec := send(http.MethodPost, pageLoginPath, url.Values{pageFieldUser: {pageUserAlice}, pageFieldPass: {pageUserPass}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in: %d\n%s", rec.Code, rec.Body.String())
	}
	m := forgetTokenRe.FindStringSubmatch(send(http.MethodGet, enroll.Path, nil).Body.String())
	if m == nil {
		t.Fatal("the page of a signed-in user carries no form token")
	}
	save := url.Values{
		"token":                            {m[1]},
		"backend":                          {pageBackend},
		"label":                            {strings.ToUpper(forgetFirst)}, // as a user may type it
		"s." + strings.ToUpper(forgetName): {forgetChanged},
	}
	if rec := send(http.MethodPost, enroll.Path+"/save", save); rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d\n%s", rec.Code, rec.Body.String())
	}

	// The other account first: it must not have lost its session.
	call(forgetSecond, forgetOther)
	if got := api.seen(); len(got) != 2 {
		t.Errorf("the other account logged in again after the save: logins %v", got)
	}
	// The changed account logs in anew, with what is stored now.
	call(forgetFirst, forgetChanged)
	if got := api.seen(); len(got) != 3 || got[2] != forgetChanged {
		t.Errorf("logins after the changed account's next call = %v, want a third one with the new credentials", got)
	}
}
