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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

const (
	pageLoginUser   = "alice"
	pageLoginSecret = "alice-page-password" //nolint:gosec // test fixture
	pageLoginRemote = "203.0.113.9:4711"
	pageLoginPlan   = "pro" // the plan the test users are written with
)

// pageRequest is a request as a page of ToolMesh other than /authorize
// hands it to PasswordLogin.
func pageRequest() *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/credentials/login", http.NoBody)
	req.RemoteAddr = pageLoginRemote
	return req
}

// TestPasswordLogin_SharesTheLimitsOfAuthorize pins that a page signing
// users in through PasswordLogin is no second way to guess passwords: its
// failures count against the same limits as those of /authorize, and the
// other way round.
func TestPasswordLogin_SharesTheLimitsOfAuthorize(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{users: map[string]string{pageLoginUser: pageLoginSecret}})

	// Two failures on the page, one at /authorize: the account is at its
	// limit of three from one address.
	for range 2 {
		if got := ts.srv.PasswordLogin(pageRequest(), pageLoginUser, "wrong"); got.Outcome != auth.PasswordInvalid || got.UserID != "" {
			t.Fatalf("wrong password = %+v", got)
		}
	}
	if rec := ts.login(pageLoginUser, "wrong", pageLoginRemote); rec.Code != http.StatusUnauthorized {
		t.Fatalf("/authorize with a wrong password: %d", rec.Code)
	}
	got := ts.srv.PasswordLogin(pageRequest(), pageLoginUser, pageLoginSecret)
	if got.Outcome != auth.PasswordThrottled || got.RetryAfter <= 0 {
		t.Fatalf("after three failures the right password gave %+v, want it throttled", got)
	}
	if rec := ts.login(pageLoginUser, pageLoginSecret, pageLoginRemote); rec.Code != http.StatusTooManyRequests {
		t.Errorf("/authorize after the page's failures: %d, want 429", rec.Code)
	}
	if n := ts.loginCount(t, loginMethodPassword, "failure"); n < 3 {
		t.Errorf("failed logins counted = %v, want the page's among them", n)
	}
	if len(ts.logs.lines(t, testMsgLoginFailed)) < 3 {
		t.Errorf("the page's failed logins are not in the log:\n%s", ts.logs.String())
	}
}

func TestPasswordLogin_IdentityAndFingerprint(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{users: map[string]string{pageLoginUser: pageLoginSecret}})
	if !ts.srv.PasswordLoginEnabled() {
		t.Fatal("PasswordLoginEnabled = false with users.yaml loaded")
	}
	got := ts.srv.PasswordLogin(pageRequest(), pageLoginUser, pageLoginSecret)
	if got.Outcome != auth.PasswordOK || got.UserID != pageLoginUser || got.CompanyID != "example" || got.Plan != pageLoginPlan || got.Fingerprint == "" {
		t.Fatalf("login = %+v", got)
	}
	if n := ts.loginCount(t, loginMethodPassword, "success"); n != 1 {
		t.Errorf("successful logins counted = %v", n)
	}
	// The fingerprint of the login is the one the user has now: a session
	// that compares them ends when the password changes.
	fp, ok := ts.srv.PasswordFingerprint(pageLoginUser)
	if !ok || fp != got.Fingerprint {
		t.Errorf("PasswordFingerprint = %q, %v, want that of the login", fp, ok)
	}
	if _, ok := ts.srv.PasswordFingerprint("nobody"); ok {
		t.Error("PasswordFingerprint knows a user who does not exist")
	}

	uc, ok := ts.srv.UserIdentity(pageLoginUser)
	if !ok || uc.UserID != pageLoginUser || uc.CompanyID != "example" || uc.Plan != pageLoginPlan || len(uc.Roles) != 1 || uc.Roles[0] != "admin" || !uc.Authenticated {
		t.Errorf("UserIdentity = %+v, %v", uc, ok)
	}
	if _, ok := ts.srv.UserIdentity("nobody"); ok {
		t.Error("UserIdentity knows a user who does not exist")
	}
}

func TestPasswordLogin_SinglePasswordAndDisabled(t *testing.T) {
	// One configured password: the name typed does not matter, the identity
	// is the configured one.
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	got := ts.srv.PasswordLogin(pageRequest(), "anything", testLoginSecret)
	if got.Outcome != auth.PasswordOK || got.UserID != testLoginOwner {
		t.Fatalf("single password = %+v", got)
	}
	if fp, ok := ts.srv.PasswordFingerprint(testLoginOwner); !ok || fp != got.Fingerprint {
		t.Errorf("PasswordFingerprint of the owner = %q, %v", fp, ok)
	}
	if _, ok := ts.srv.PasswordFingerprint("anything"); ok {
		t.Error("in single-password mode only the configured user exists")
	}

	// No password login at all: nothing is compared.
	cfg := loginTestConfig()
	cfg.AuthPassword = ""
	off := newLoginTestServer(t, cfg, loginTestOptions{apiKeys: []string{"some-api-key"}})
	if off.srv.PasswordLoginEnabled() {
		t.Fatal("PasswordLoginEnabled = true without users.yaml and without a password")
	}
	if got := off.srv.PasswordLogin(pageRequest(), testLoginOwner, ""); got.Outcome != auth.PasswordDisabled {
		t.Errorf("login without a password login = %+v", got)
	}
	if _, ok := off.srv.UserIdentity(testLoginOwner); ok {
		t.Error("UserIdentity knows a user although nobody can sign in")
	}
}
