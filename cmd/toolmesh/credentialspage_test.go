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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/enroll"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	pageUserAlice  = "alice"
	pageUserBob    = "bob"
	pageUserPass   = "page-test-password" //nolint:gosec // test fixture, not a credential
	pageBackend    = "mail"
	pageOrigin     = "https://toolmesh.example.com"
	pageLoginPath  = enroll.Path + "/login"
	pageFetchSite  = "Sec-Fetch-Site"
	pageSameOrigin = "same-origin"
)

// pageUsers is the identity side of a credentials page under test: the
// users who can sign in, all with the same password.
type pageUsers map[string]bool

func (u pageUsers) PasswordLoginEnabled() bool { return true }

func (u pageUsers) PasswordLogin(_ *http.Request, username, password string) auth.PasswordCheck {
	if !u[username] || password != pageUserPass {
		return auth.PasswordCheck{Outcome: auth.PasswordInvalid}
	}
	return auth.PasswordCheck{Outcome: auth.PasswordOK, UserID: username, Fingerprint: "fp"}
}

func (u pageUsers) PasswordFingerprint(userID string) (string, bool) {
	return "fp", u[userID]
}

func (u pageUsers) UserIdentity(userID string) (*userctx.UserContext, bool) {
	if !u[userID] {
		return nil, false
	}
	return &userctx.UserContext{UserID: userID, Plan: "pro", Roles: []string{"member"}, Authenticated: true}, true
}

// toolGrants is an authorizer that lets each user call the tools listed
// for them, by full name; off turns authorization off.
type toolGrants struct {
	off    bool
	tools  map[string][]string
	asked  []string // "user/caller: tool,tool" of every question
	callID string
}

func (g *toolGrants) Authorizes() bool { return !g.off }

func (g *toolGrants) FilterAuthorizedTools(_ context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor) []backend.ToolDescriptor {
	names := make([]string, 0, len(tools))
	var out []backend.ToolDescriptor
	for _, t := range tools {
		names = append(names, t.Name)
		for _, allowed := range g.tools[uc.UserID] {
			if allowed == t.Name {
				out = append(out, t)
			}
		}
	}
	g.callID = uc.CallerID
	g.asked = append(g.asked, uc.UserID+": "+strings.Join(names, ","))
	return out
}

// loadUserBackend loads the two entries of testUserBackends with the user
// credential store on and returns the registry of the per-user ones.
func loadUserBackend(t *testing.T) (*userCredentialSetup, *userBackendRegistry, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mail.dadl"), []byte(testUserDADL), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	if err := os.WriteFile(backendsPath, []byte(testUserBackends), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(testUserKeyEnv, testUserKey())
	t.Setenv("TOOLMESH_DATA_DIR", t.TempDir())
	t.Setenv("TOOLMESH_ISSUER", pageOrigin+"/")
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	users, err := newUserCredentialSetup(cfg, quietLogger())
	if err != nil || users == nil {
		t.Fatalf("newUserCredentialSetup = %v, %v", users, err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, quietLogger(), nil, nil, nil, users)
	reg := &userBackendRegistry{}
	reg.set(named)
	if _, ok := reg.get(pageBackend); !ok {
		t.Fatalf("the per-user backend was not loaded: %v", named)
	}
	return users, reg, cfg
}

// TestNewUserCredentialSetup_TakesTheKeyOutOfTheEnvironment pins that the
// key is not left where stdio backends, started later, would inherit it.
func TestNewUserCredentialSetup_TakesTheKeyOutOfTheEnvironment(t *testing.T) {
	loadUserBackend(t)
	if v, set := os.LookupEnv(testUserKeyEnv); set {
		t.Errorf("%s is still in the environment (%d bytes) after the store was opened", testUserKeyEnv, len(v))
	}
}

// TestLoadRESTBackends_UserCredentialRefusalIsReported pins how a backend
// whose user_credentials cannot be honored shows: a "backend refused" line
// with the reason, and its name in the list the startup summary reports.
func TestLoadRESTBackends_UserCredentialRefusalIsReported(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mail.dadl"), []byte(testUserDADL), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	if err := os.WriteFile(backendsPath, []byte(testUserBackends), 0o600); err != nil {
		t.Fatal(err)
	}
	buf := &capturedWriter{}
	named := make(map[string]backend.ToolBackend)
	_, refused := loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, slog.New(slog.NewTextHandler(buf, nil)), nil, nil, nil, nil)
	if len(refused) != 1 || refused[0] != pageBackend {
		t.Errorf("refused = %v, want the backend with user_credentials", refused)
	}
	if log := string(buf.data); !strings.Contains(log, "backend refused") || !strings.Contains(log, "user_credentials") {
		t.Errorf("the log has no 'backend refused' line for it:\n%s", log)
	}
}

// TestMayUseBackend pins the question the credentials page asks before it
// offers a backend: may this user call any of its tools, by the names and
// the identity a tool call would be checked with.
func TestMayUseBackend(t *testing.T) {
	_, reg, _ := loadUserBackend(t)
	users := pageUsers{pageUserAlice: true, pageUserBob: true}
	grants := &toolGrants{tools: map[string][]string{pageUserAlice: {"mail_list_messages"}, pageUserBob: {"other_tool"}}}
	ctx := context.Background()

	if !mayUseBackend(ctx, grants, users, reg, pageUserAlice, pageBackend) {
		t.Error("alice may call a tool of the backend and is not offered it")
	}
	if mayUseBackend(ctx, grants, users, reg, pageUserBob, pageBackend) {
		t.Error("bob may call no tool of the backend and is offered it")
	}
	// The tools are asked about under the names callers use, and as the
	// page, not as a client of the user.
	if len(grants.asked) == 0 || !strings.Contains(grants.asked[0], "mail_list_messages") || !strings.Contains(grants.asked[0], "mail_health") {
		t.Errorf("the authorizer was asked about %v, want the prefixed tool names", grants.asked)
	}
	if grants.callID != credentialsPageCaller {
		t.Errorf("caller id of the question = %q", grants.callID)
	}
	if mayUseBackend(ctx, grants, users, reg, "carol", pageBackend) {
		t.Error("a user who cannot sign in is offered the backend")
	}
	if mayUseBackend(ctx, grants, users, reg, pageUserAlice, "shared") || mayUseBackend(ctx, grants, users, reg, pageUserAlice, "nope") {
		t.Error("a backend without user credentials is offered")
	}
	// Without authorization every user is offered every such backend.
	if !mayUseBackend(ctx, &toolGrants{off: true}, users, reg, pageUserBob, pageBackend) {
		t.Error("with authorization off, bob is not offered the backend")
	}
}

// TestWarnOrphanedAccounts pins the warning about accounts whose user can
// no longer sign in: they would be used again by whoever gets the id.
func TestWarnOrphanedAccounts(t *testing.T) {
	setup, _, _ := loadUserBackend(t)
	for _, user := range []string{pageUserAlice, "former"} {
		slot := credentials.UserSlot{UserID: user, Backend: pageBackend, Account: user + "@example.com", Name: "mail_login"}
		if err := setup.store.PutUser(context.Background(), slot, "v"); err != nil {
			t.Fatal(err)
		}
	}
	buf := &capturedWriter{}
	warnOrphanedAccounts(setup, pageUsers{pageUserAlice: true}, slog.New(slog.NewTextHandler(buf, nil)))
	log := string(buf.data)
	if !strings.Contains(log, "former") || strings.Contains(log, pageUserAlice) || !strings.Contains(log, "user-credentials.json") {
		t.Errorf("warning = %q, want the former user named and alice not", log)
	}
	quiet := &capturedWriter{}
	warnOrphanedAccounts(setup, pageUsers{pageUserAlice: true, "former": true}, slog.New(slog.NewTextHandler(quiet, nil)))
	if len(quiet.data) != 0 {
		t.Errorf("a warning without orphaned accounts: %s", quiet.data)
	}
}

// TestNewCredentialsPage wires the page as main does and walks it once:
// the login form, a login, and the backends offered by authorization.
func TestNewCredentialsPage(t *testing.T) {
	setup, reg, cfg := loadUserBackend(t)
	users := pageUsers{pageUserAlice: true, pageUserBob: true}
	grants := &toolGrants{tools: map[string][]string{pageUserAlice: {"mail_list_messages"}}}
	page, err := newCredentialsPage(cfg, setup, reg, users, grants, nil, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(enroll.Path, page)
	mux.Handle(enroll.Path+"/", page)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, pageOrigin+enroll.Path, http.NoBody))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), pageLoginPath) || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("GET %s: %d\n%s", enroll.Path, rec.Code, rec.Body.String())
	}

	signedIn := func(user string) string {
		t.Helper()
		form := url.Values{"username": {user}, "password": {pageUserPass}}
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pageOrigin+pageLoginPath, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set(pageFetchSite, pageSameOrigin)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("login of %s: %d\n%s", user, rec.Code, rec.Body.String())
		}
		get := httptest.NewRequestWithContext(context.Background(), http.MethodGet, pageOrigin+enroll.Path, http.NoBody)
		for _, c := range rec.Result().Cookies() {
			get.AddCookie(c)
		}
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, get)
		return out.Body.String()
	}
	if body := signedIn(pageUserAlice); !strings.Contains(body, "Mailbox login") || !strings.Contains(body, "A mail API") {
		t.Errorf("alice's page does not offer the backend:\n%s", body)
	}
	if body := signedIn(pageUserBob); !strings.Contains(body, "Signed in as") || strings.Contains(body, "Mailbox login") {
		t.Errorf("bob's page offers a backend he may not call:\n%s", body)
	}
}
