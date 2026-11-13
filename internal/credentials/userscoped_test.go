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

package credentials

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// instanceCreds is a CredentialStore of the instance, backed by a map.
type instanceCreds map[string]string

func (m instanceCreds) Get(_ context.Context, name string, _ TenantInfo) (string, error) {
	if v, ok := m[strings.ToUpper(name)]; ok {
		return v, nil
	}
	return "", ErrCredentialNotFound
}

func (m instanceCreds) ListByPrefix(_ context.Context, prefix string, _ TenantInfo) (map[string]string, error) {
	out := map[string]string{}
	for k, v := range m {
		if strings.HasPrefix(k, strings.ToUpper(prefix)) {
			out[k] = v
		}
	}
	return out, nil
}

func (m instanceCreds) Healthy(context.Context) error { return nil }

const (
	scopedInstanceValue = "instance-value" //nolint:gosec // test fixture, not a credential
	scopedSecond        = "second@example.com"
	scopedURL           = "https://toolmesh.example.com/credentials"
	scopedAPIToken      = "MAIL_API_TOKEN" //nolint:gosec // credential name, not a credential
	scopedAPIValue      = "api-token"      //nolint:gosec // test fixture, not a credential
)

// scopedFixture returns a store for backend "mail" whose MAIL_LOGIN comes
// from users, over an instance store that also holds a MAIL_LOGIN.
func scopedFixture(t *testing.T) (*UserScopedStore, *FileUserStore) {
	t.Helper()
	users := usOpen(t, t.TempDir(), usKey(1))
	instance := instanceCreds{usName: scopedInstanceValue, scopedAPIToken: scopedAPIValue}
	return NewUserScopedStore(instance, users, usBackend, []string{usLower}, scopedURL), users
}

func userErr(t *testing.T, err error) *UserCredentialError {
	t.Helper()
	var uce *UserCredentialError
	if !errors.As(err, &uce) {
		t.Fatalf("err = %v, want a *UserCredentialError", err)
	}
	if errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("the error wraps ErrCredentialNotFound: a caller would send the request without authentication")
	}
	return uce
}

// TestUserScopedStore_NeverFallsBackToTheInstance is the core rule: a name
// declared per user is read from the user's namespace only, even though
// the instance store holds a value under the same name.
func TestUserScopedStore_NeverFallsBackToTheInstance(t *testing.T) {
	ctx := context.Background()
	s, users := scopedFixture(t)

	_, err := s.Get(ctx, usLower, TenantInfo{UserID: usAlice})
	uce := userErr(t, err)
	if uce.Reason != UserCredentialMissing || uce.UserID != usAlice || uce.Backend != usBackend {
		t.Errorf("error = %+v", uce)
	}
	if msg := err.Error(); !strings.Contains(msg, scopedURL) || strings.Contains(msg, scopedInstanceValue) {
		t.Errorf("message = %q, want the page's address and no value", msg)
	}

	if err := users.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, usLower, TenantInfo{UserID: usAlice}); err != nil || got != usSecret {
		t.Errorf("alice: %q, %v", got, err)
	}
	// Bob has stored nothing and gets neither alice's nor the instance's.
	_, err = s.Get(ctx, usLower, TenantInfo{UserID: usBob})
	if uce := userErr(t, err); uce.Reason != UserCredentialMissing {
		t.Errorf("bob: %+v", uce)
	}
	// A call without a user is refused.
	_, err = s.Get(ctx, usLower, TenantInfo{})
	if uce := userErr(t, err); uce.Reason != UserCredentialNoUser {
		t.Errorf("no user: %+v", uce)
	}
	// Names that are not per user come from the instance as before.
	if got, err := s.Get(ctx, "mail_api_token", TenantInfo{UserID: usBob}); err != nil || got != scopedAPIValue {
		t.Errorf("instance name: %q, %v", got, err)
	}
}

func TestUserScopedStore_Accounts(t *testing.T) {
	ctx := context.Background()
	s, users := scopedFixture(t)
	put := func(account, value string) {
		t.Helper()
		if err := users.PutUser(ctx, UserSlot{UserID: usAlice, Backend: usBackend, Account: account, Name: usName}, value); err != nil {
			t.Fatal(err)
		}
	}
	put(usAccount, usSecret)

	// One account: a call that names none uses it.
	if got, err := s.Get(ctx, usName, TenantInfo{UserID: usAlice}); err != nil || got != usSecret {
		t.Fatalf("single account: %q, %v", got, err)
	}

	put(scopedSecond, "second-secret")
	// Several accounts: the call has to name one, and the error lists them.
	_, err := s.Get(ctx, usName, TenantInfo{UserID: usAlice})
	uce := userErr(t, err)
	if uce.Reason != UserCredentialAmbiguous || len(uce.Accounts) != 2 {
		t.Fatalf("several accounts, none named: %+v", uce)
	}
	if msg := err.Error(); !strings.Contains(msg, usAccount) || !strings.Contains(msg, scopedSecond) || !strings.Contains(msg, AccountParam) {
		t.Errorf("message = %q, want both labels and the parameter name", msg)
	}
	if got, err := s.Get(ctx, usName, TenantInfo{UserID: usAlice, Account: "Second@Example.com"}); err != nil || got != "second-secret" {
		t.Errorf("named account: %q, %v", got, err)
	}
	if got, err := s.Get(ctx, usName, TenantInfo{UserID: usAlice, Account: usAccount}); err != nil || got != usSecret {
		t.Errorf("first account: %q, %v", got, err)
	}

	// An account the user has not stored, or a label that is none.
	for _, account := range []string{"third@example.com", "not a label"} {
		_, err = s.Get(ctx, usName, TenantInfo{UserID: usAlice, Account: account})
		if uce := userErr(t, err); uce.Reason != UserCredentialUnknownAccount || len(uce.Accounts) != 2 {
			t.Errorf("account %q: %+v", account, uce)
		}
	}
	// Bob cannot use alice's account by naming it.
	_, err = s.Get(ctx, usName, TenantInfo{UserID: usBob, Account: usAccount})
	if uce := userErr(t, err); uce.Reason != UserCredentialUnknownAccount || len(uce.Accounts) != 0 {
		t.Errorf("bob naming alice's account: %+v", uce)
	}

	accounts, err := s.Accounts(ctx, usAlice)
	if err != nil || len(accounts) != 2 || accounts[0] != usAccount || accounts[1] != scopedSecond {
		t.Errorf("Accounts = %v, %v", accounts, err)
	}
}

func TestUserScopedStore_IncompleteAndUnreadable(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	users := usOpen(t, dir, usKey(1))
	s := NewUserScopedStore(instanceCreds{}, users, usBackend, []string{usLower, "mail_pin"}, "")
	if err := users.PutUser(ctx, usSlot(usAlice), usSecret); err != nil {
		t.Fatal(err)
	}
	// The account exists but lacks the second credential.
	_, err := s.Get(ctx, "mail_pin", TenantInfo{UserID: usAlice})
	uce := userErr(t, err)
	if uce.Reason != UserCredentialIncomplete || uce.Account != usAccount {
		t.Errorf("incomplete: %+v", uce)
	}
	if !strings.Contains(err.Error(), EnrollPath) {
		t.Errorf("without a public address the message should name the path: %q", err.Error())
	}

	// The same file under another key: stored, but unreadable.
	other := NewUserScopedStore(instanceCreds{}, usOpen(t, dir, usKey(2)), usBackend, []string{usLower}, "")
	_, err = other.Get(ctx, usName, TenantInfo{UserID: usAlice})
	if uce := userErr(t, err); uce.Reason != UserCredentialUnreadable {
		t.Errorf("other key: %+v", uce)
	}
}

func TestUserScopedStore_ListByPrefixHidesUserNames(t *testing.T) {
	s, _ := scopedFixture(t)
	got, err := s.ListByPrefix(context.Background(), "MAIL_", TenantInfo{UserID: usAlice})
	if err != nil {
		t.Fatal(err)
	}
	if _, listed := got[usName]; listed {
		t.Errorf("the per-user name is listed with the instance's value: %v", got)
	}
	if got[scopedAPIToken] != scopedAPIValue {
		t.Errorf("instance names should stay listed: %v", got)
	}
	if !s.PerUser("Mail_Login") || s.PerUser("mail_api_token") {
		t.Error("PerUser")
	}
	if names := s.PerUserNames(); len(names) != 1 || names[0] != usName {
		t.Errorf("PerUserNames = %v", names)
	}
}

func TestAccountContext(t *testing.T) {
	ctx := context.Background()
	if got := AccountFromContext(ctx); got != "" {
		t.Errorf("empty context: %q", got)
	}
	if got := AccountFromContext(WithAccount(ctx, usAccount)); got != usAccount {
		t.Errorf("AccountFromContext = %q", got)
	}
}
