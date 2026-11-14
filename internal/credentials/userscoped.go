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
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Reasons a user credential cannot be supplied (UserCredentialError.Reason).
const (
	// UserCredentialMissing: the calling user has stored no account for
	// the backend.
	UserCredentialMissing = "missing"
	// UserCredentialUnknownAccount: the call names an account the user has
	// not stored.
	UserCredentialUnknownAccount = "unknown_account"
	// UserCredentialAmbiguous: the user has several accounts and the call
	// names none.
	UserCredentialAmbiguous = "ambiguous_account"
	// UserCredentialIncomplete: the account lacks one of the backend's
	// credentials.
	UserCredentialIncomplete = "incomplete"
	// UserCredentialUnreadable: one is stored but cannot be decrypted.
	UserCredentialUnreadable = "unreadable"
	// UserCredentialNoUser: the call carries no user, as a background check
	// does.
	UserCredentialNoUser = "no_user"
	// UserCredentialStoreFailed: the user store failed.
	UserCredentialStoreFailed = "store_failed"
)

// AccountParam is the parameter every tool of a backend with user
// credentials takes besides its own: the label of the calling user's
// account to use.
const AccountParam = "account"

// UserCredentialError is returned when a backend needs a credential of the
// calling user and there is none to send. It does not wrap
// ErrCredentialNotFound: a call that lacks its user's credential fails and
// is never sent without authentication, and it never falls back to a
// credential of the instance.
//
// The message is written for the caller of the tool, an agent or its user,
// and says what to do: which accounts there are to choose from, or where
// the user adds one.
type UserCredentialError struct {
	Backend string
	Name    string
	UserID  string
	// Account is the account the call asked for or resolved to, "" when
	// none.
	Account string
	// Accounts are the labels of the accounts the user has stored for the
	// backend.
	Accounts []string
	Reason   string
	// EnrollURL is the page where the user stores the credential, "" when
	// this ToolMesh has no public address configured.
	EnrollURL string
	// Err is the store's error for UserCredentialStoreFailed, for logs. It
	// is not part of the error chain: errors.Is must never find
	// ErrCredentialNotFound through this error, whatever a store wraps.
	Err error
}

// neverThroughTools closes the messages that send the user to the page.
const neverThroughTools = "Credentials are never passed through a tool call."

// Error implements error.
func (e *UserCredentialError) Error() string {
	where := "the credentials page of this ToolMesh (path " + EnrollPath + ")"
	if e.EnrollURL != "" {
		where = e.EnrollURL
	}
	stored := strings.Join(e.Accounts, ", ")
	switch e.Reason {
	case UserCredentialNoUser:
		return fmt.Sprintf("backend %q uses credentials of the calling user, and this call has no user", e.Backend)
	case UserCredentialUnknownAccount:
		if len(e.Accounts) == 0 {
			return fmt.Sprintf("user %q has no account %q stored for backend %q, and no other one either. "+
				"The user has to add it at %s; then repeat the call. %s", e.UserID, e.Account, e.Backend, where, neverThroughTools)
		}
		return fmt.Sprintf("user %q has no account %q stored for backend %q. Stored accounts: %s. "+
			"Pass one of them as %q, or the user adds the account at %s. %s",
			e.UserID, e.Account, e.Backend, stored, AccountParam, where, neverThroughTools)
	case UserCredentialAmbiguous:
		return fmt.Sprintf("user %q has several accounts stored for backend %q: %s. Pass the one to use as %q.",
			e.UserID, e.Backend, stored, AccountParam)
	case UserCredentialIncomplete:
		return fmt.Sprintf("the account %q of user %q for backend %q lacks a credential (%s). "+
			"The user has to complete it at %s; then repeat the call. %s",
			e.Account, e.UserID, e.Backend, strings.ToLower(e.Name), where, neverThroughTools)
	case UserCredentialUnreadable:
		return fmt.Sprintf("the credentials of account %q that user %q stored for backend %q can no longer be read. "+
			"The user has to store them again at %s; then repeat the call. %s",
			e.Account, e.UserID, e.Backend, where, neverThroughTools)
	case UserCredentialStoreFailed:
		return fmt.Sprintf("the credentials of user %q for backend %q could not be read from the user credential store", e.UserID, e.Backend)
	default:
		return fmt.Sprintf("backend %q needs credentials of its own for every user, and user %q has stored none. "+
			"The user has to add them at %s; then repeat the call. %s",
			e.Backend, e.UserID, where, neverThroughTools)
	}
}

// EnrollPath is the path of the page where users store their credentials.
const EnrollPath = "/credentials"

// accountKey carries the account a call selected through its context.
type accountKey struct{}

// WithAccount returns ctx with the label of the user's account the call
// selected.
func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

// AccountFromContext returns the account label a call selected, "" when it
// named none.
func AccountFromContext(ctx context.Context) string {
	a, _ := ctx.Value(accountKey{}).(string)
	return a
}

// UserScopedStore answers the credential names an operator declared as
// per user from a UserStore, in the namespace of the calling user, one of
// the user's accounts and one backend, and every other name from the
// delegate. A per-user name is never read from the delegate, whether or
// not the user has stored a value.
type UserScopedStore struct {
	delegate  CredentialStore
	users     UserStore
	backend   string
	names     map[string]bool
	enrollURL string
}

// NewUserScopedStore wraps delegate for the backend entry named backend:
// the credential names in names come from users. enrollURL is the address
// of the credentials page for messages, "" when unknown.
func NewUserScopedStore(delegate CredentialStore, users UserStore, backend string, names []string, enrollURL string) *UserScopedStore {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		if k := userCredentialKey(n); k != "" {
			set[k] = true
		}
	}
	return &UserScopedStore{delegate: delegate, users: users, backend: backend, names: set, enrollURL: enrollURL}
}

// PerUser reports whether name is read from the calling user's namespace.
func (s *UserScopedStore) PerUser(name string) bool {
	return s.names[userCredentialKey(name)]
}

// PerUserNames returns the per-user names in their key form, sorted.
func (s *UserScopedStore) PerUserNames() []string {
	out := make([]string, 0, len(s.names))
	for n := range s.names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// fail builds the error of a lookup for tenant.
func (s *UserScopedStore) fail(tenant TenantInfo, reason, name string, accounts []string, err error) error {
	return &UserCredentialError{
		Backend: s.backend, Name: userCredentialKey(name), UserID: tenant.UserID,
		Account: tenant.Account, Accounts: accounts,
		Reason: reason, EnrollURL: s.enrollURL, Err: err,
	}
}

// Accounts returns the labels of the accounts userID has stored for the
// backend, sorted. An account counts as stored when it holds any of the
// backend's per-user credentials.
func (s *UserScopedStore) Accounts(ctx context.Context, userID string) ([]string, error) {
	if s.users == nil {
		return nil, nil
	}
	infos, err := s.users.ListUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, info := range infos {
		if info.Backend != s.backend || !s.names[info.Name] {
			continue
		}
		if !slices.Contains(out, info.Account) {
			out = append(out, info.Account)
		}
	}
	sort.Strings(out)
	return out, nil
}

// ResolveAccount returns the account the call of tenant uses: the one it
// names, which the user must have stored, or without a name the user's
// only account. A user with several accounts has to name one; the error
// lists them.
func (s *UserScopedStore) ResolveAccount(ctx context.Context, tenant TenantInfo) (string, error) {
	if tenant.UserID == "" || s.users == nil {
		return "", s.fail(tenant, UserCredentialNoUser, "", nil, nil)
	}
	accounts, err := s.Accounts(ctx, tenant.UserID)
	if err != nil {
		return "", s.fail(tenant, UserCredentialStoreFailed, "", nil, err)
	}
	if tenant.Account != "" {
		account, ok := NormalizeAccount(tenant.Account)
		if !ok || !slices.Contains(accounts, account) {
			return "", s.fail(tenant, UserCredentialUnknownAccount, "", accounts, nil)
		}
		return account, nil
	}
	switch len(accounts) {
	case 0:
		return "", s.fail(tenant, UserCredentialMissing, "", nil, nil)
	case 1:
		return accounts[0], nil
	}
	return "", s.fail(tenant, UserCredentialAmbiguous, "", accounts, nil)
}

// Get implements CredentialStore. A per-user name is read from the account
// of tenant; without one it is resolved as ResolveAccount does.
func (s *UserScopedStore) Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error) {
	if !s.PerUser(logicalName) {
		return s.delegate.Get(ctx, logicalName, tenant)
	}
	account, err := s.ResolveAccount(ctx, tenant)
	if err != nil {
		return "", err
	}
	tenant.Account = account
	val, err := s.users.GetUser(ctx, UserSlot{UserID: tenant.UserID, Backend: s.backend, Account: account, Name: logicalName})
	switch {
	case err == nil && val != "":
		return val, nil
	case err == nil, errors.Is(err, ErrCredentialNotFound):
		return "", s.fail(tenant, UserCredentialIncomplete, logicalName, nil, nil)
	case errors.Is(err, ErrUserCredentialUnreadable):
		return "", s.fail(tenant, UserCredentialUnreadable, logicalName, nil, nil)
	default:
		return "", s.fail(tenant, UserCredentialStoreFailed, logicalName, nil, err)
	}
}

// ListByPrefix implements PrefixLister with the delegate's credentials
// only: credentials of users are never listed.
func (s *UserScopedStore) ListByPrefix(ctx context.Context, prefix string, tenant TenantInfo) (map[string]string, error) {
	lister, ok := s.delegate.(PrefixLister)
	if !ok {
		return map[string]string{}, nil
	}
	all, err := lister.ListByPrefix(ctx, prefix, tenant)
	if err != nil {
		return nil, err
	}
	for name := range all {
		if s.PerUser(name) {
			delete(all, name)
		}
	}
	return all, nil
}

// Healthy implements CredentialStore.
func (s *UserScopedStore) Healthy(ctx context.Context) error {
	return s.delegate.Healthy(ctx)
}
