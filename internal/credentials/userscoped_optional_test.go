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
	"testing"
)

// Fixtures of the tests of optional per-user names.
const (
	optScope      = "MAIL_SCOPE"
	optScopeLower = "mail_scope"
	optValue      = `{"mailboxes":["INBOX"]}`
)

// optFixture is a store for backend "mail" whose MAIL_LOGIN and MAIL_SCOPE
// come from users, the scope as an optional JSON value, over an instance
// store that holds values under both names.
func optFixture(t *testing.T, dir string, key byte) (*UserScopedStore, *FileUserStore) {
	t.Helper()
	users := usOpen(t, dir, usKey(key))
	instance := instanceCreds{usName: scopedInstanceValue, optScope: scopedInstanceValue}
	scoped := NewUserScopedStore(instance, users, usBackend, []string{usLower, optScopeLower}, scopedURL).
		WithOptional(optScopeLower, scopedAPIToken).WithJSONValues(optScope, scopedAPIToken)
	return scoped, users
}

func optSlot(name string) UserSlot {
	return UserSlot{UserID: usAlice, Backend: usBackend, Account: usAccount, Name: name}
}

// TestUserScopedStore_OptionalName pins what a reader gets for a per-user
// name an account may go without. Only "the account holds none" is
// answered as not found, which lets a reader leave the value out. Every
// other case stays the error it is for any per-user name, and the
// instance's value of the same name is never used.
func TestUserScopedStore_OptionalName(t *testing.T) {
	ctx := context.Background()
	tenant := TenantInfo{UserID: usAlice}
	s, users := optFixture(t, t.TempDir(), 1)

	if !s.Optional(optScopeLower) || !s.Optional(optScope) || s.Optional(usLower) || s.Optional(scopedAPIToken) {
		t.Fatal("Optional: only the per-user name that was marked is optional, in any spelling")
	}
	if !s.JSONValue(optScopeLower) || s.JSONValue(usLower) || s.JSONValue(scopedAPIToken) {
		t.Fatal("JSONValue: only the per-user name that was marked is a JSON value")
	}

	// No account at all: the user credential error, also for the optional
	// name.
	_, err := s.Get(ctx, optScopeLower, tenant)
	if uce := userErr(t, err); uce.Reason != UserCredentialMissing {
		t.Fatalf("no account: reason %q, want %q", uce.Reason, UserCredentialMissing)
	}

	// An account without the optional value: not found, and not the
	// instance's value.
	if err := users.PutUser(ctx, optSlot(usName), usSecret); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, optScopeLower, tenant)
	if !errors.Is(err, ErrCredentialNotFound) || got != "" {
		t.Fatalf("an account without the optional value: %q, %v; want ErrCredentialNotFound", got, err)
	}
	var uce *UserCredentialError
	if errors.As(err, &uce) {
		t.Fatalf("the absence of an optional value is reported as a user credential error: %v", err)
	}

	// The name that is not optional stays a user credential error when
	// the account lacks it.
	required := NewUserScopedStore(instanceCreds{}, users, usBackend, []string{usLower, optScopeLower}, scopedURL)
	_, err = required.Get(ctx, optScopeLower, tenant)
	if uce := userErr(t, err); uce.Reason != UserCredentialIncomplete {
		t.Fatalf("a required value the account lacks: reason %q, want %q", uce.Reason, UserCredentialIncomplete)
	}

	// With a value: the value.
	if err := users.PutUser(ctx, optSlot(optScope), optValue); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Get(ctx, optScopeLower, tenant); err != nil || got != optValue {
		t.Fatalf("the stored optional value: %q, %v", got, err)
	}

	// An account the call names and the user has not stored.
	_, err = s.Get(ctx, optScopeLower, TenantInfo{UserID: usAlice, Account: scopedSecond})
	if uce := userErr(t, err); uce.Reason != UserCredentialUnknownAccount {
		t.Fatalf("an unknown account: reason %q, want %q", uce.Reason, UserCredentialUnknownAccount)
	}
}

// TestUserScopedStore_OptionalValueThatCannotBeRead pins that an optional
// value which is stored and cannot be read is an error and never taken for
// an absent one: a reader would otherwise leave out a limit that exists.
func TestUserScopedStore_OptionalValueThatCannotBeRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_, written := optFixture(t, dir, 1)
	if err := written.PutUser(ctx, optSlot(optScope), optValue); err != nil {
		t.Fatal(err)
	}
	s, users := optFixture(t, dir, 2)
	if err := users.PutUser(ctx, optSlot(usName), usSecret); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get(ctx, optScopeLower, TenantInfo{UserID: usAlice})
	if uce := userErr(t, err); uce.Reason != UserCredentialUnreadable {
		t.Fatalf("an optional value that cannot be read: reason %q, want %q", uce.Reason, UserCredentialUnreadable)
	}
}
