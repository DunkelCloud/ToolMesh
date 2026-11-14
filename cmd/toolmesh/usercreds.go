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
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/enroll"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// userCredentialSetup is what backends and the credentials page share for
// credentials that users store for themselves.
type userCredentialSetup struct {
	store *credentials.FileUserStore
	// key is the key the store encrypts with; the credentials page derives
	// the keys of its sessions from it.
	key []byte
	// enrollURL is the address of the credentials page for the message of
	// a call that lacks its user's credentials; "" when this ToolMesh has
	// no public address configured.
	enrollURL string
}

// userCredentialsKeyEnv names the setting that turns the store on, and
// userCredentialsKeyNextEnv the one that names the key to change to.
const (
	userCredentialsKeyEnv     = "TOOLMESH_USER_CREDENTIALS_KEY"      //nolint:gosec // the variable's name, not a credential
	userCredentialsKeyNextEnv = "TOOLMESH_USER_CREDENTIALS_KEY_NEXT" //nolint:gosec // the variable's name, not a credential
)

// newUserCredentialSetup opens the store for credentials of users in the
// data directory. It returns nil without TOOLMESH_USER_CREDENTIALS_KEY: the
// store is opt-in, because its key is the operator's to create and keep.
func newUserCredentialSetup(cfg *config.Config, logger *slog.Logger) (*userCredentialSetup, error) {
	if cfg.UserCredentialsKey == "" {
		if cfg.UserCredentialsKeyNext != "" {
			return nil, fmt.Errorf("%s is set without %s: it only names the key to change to. Put the key in use into %s", userCredentialsKeyNextEnv, userCredentialsKeyEnv, userCredentialsKeyEnv)
		}
		return nil, nil
	}
	key, err := credentials.ParseUserCredentialsKey(cfg.UserCredentialsKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", userCredentialsKeyEnv, err)
	}
	var next []byte
	if cfg.UserCredentialsKeyNext != "" {
		if next, err = credentials.ParseUserCredentialsKey(cfg.UserCredentialsKeyNext); err != nil {
			return nil, fmt.Errorf("%s: %w", userCredentialsKeyNextEnv, err)
		}
		if subtle.ConstantTimeCompare(key, next) == 1 {
			return nil, fmt.Errorf("%s is the same key as %s: there is nothing to change to. Remove it, or set a new key", userCredentialsKeyNextEnv, userCredentialsKeyEnv)
		}
	}
	// The keys are taken out of the configuration and out of the environment
	// once they are read: child processes such as stdio backends are started
	// later and inherit the environment, and none of them has any use for
	// the key to every user's credentials.
	cfg.UserCredentialsKey, cfg.UserCredentialsKeyNext = "", ""
	for _, name := range []string{userCredentialsKeyEnv, userCredentialsKeyNextEnv} {
		if err := os.Unsetenv(name); err != nil {
			logger.Warn("could not take a user credentials key out of the environment; stdio backends inherit it", "name", name, "error", err)
		}
	}
	store, err := credentials.NewFileUserStore(cfg.DataDir, key)
	if err != nil {
		return nil, err
	}
	setup := &userCredentialSetup{store: store, key: key}
	if next != nil {
		// A change of the key: what the key in use opens is sealed again
		// under the next one, and this instance runs on the next one. A
		// start after that, with both still set, finds everything under
		// the next key already.
		change, err := store.ChangeKey(next)
		if err != nil {
			return nil, fmt.Errorf("change of the user credentials key: %w", err)
		}
		setup.key = next
		logger.Info("user credential store: change of key. Every value this instance can read is sealed under "+userCredentialsKeyNextEnv+" now. To finish, make that key "+userCredentialsKeyEnv+" and remove "+userCredentialsKeyNextEnv+"; until then every start runs like this one",
			"resealed", change.Resealed, "underNextKey", change.UnderNext, "unreadable", change.Unreadable)
		if change.Resealed == 0 && change.UnderNext > 0 {
			// Nothing tells a start after the change from a first start
			// with the two settings the wrong way round. Said here, the
			// operator can tell before the other key is thrown away.
			logger.Info("user credential store: nothing was sealed again, every value lay under " + userCredentialsKeyNextEnv + " already. That is as it should be on a start after the change. On the first start of a change it means the two settings are the wrong way round: " + userCredentialsKeyEnv + " is the key the values are sealed under now, " + userCredentialsKeyNextEnv + " the new one")
		}
	}
	// What the key this instance runs on does not open is said at every
	// start. Without it a change of key that was finished wrongly, or a key
	// that is not the one the values were sealed under, shows only when a
	// user's call fails, and by then the right key may be gone.
	state := store.KeyState()
	switch {
	case state.Unreadable == 0:
	case next != nil:
		logger.Warn("user credential store: stored values open under neither "+userCredentialsKeyEnv+" nor "+userCredentialsKeyNextEnv+". They stay unreadable; their users store them again",
			"values", state.Unreadable, "ofValues", state.Readable+state.Unreadable, "sealedUnderKeyIds", state.OtherKeyIDs)
	default:
		logger.Warn("user credential store: stored values do not open under "+userCredentialsKeyEnv+". If they were sealed under another key, that key belongs into "+userCredentialsKeyEnv+"; to change keys, set the new one as "+userCredentialsKeyNextEnv+" next to it. Otherwise their users store them again",
			"values", state.Unreadable, "ofValues", state.Readable+state.Unreadable, "keyId", state.KeyID, "sealedUnderKeyIds", state.OtherKeyIDs)
	}
	if base := credentialsPageBase(cfg); base != "" {
		setup.enrollURL = base + enroll.Path
	}
	logger.Info("user credential store initialized", "dataDir", cfg.DataDir, "keyId", state.KeyID, "values", state.Readable+state.Unreadable)
	return setup, nil
}

// credentialsPageBase is the address users reach the credentials page at,
// without the page's path: the address of the page's own listener when it
// has one, otherwise the public address of this ToolMesh. "" when that is
// not configured.
func credentialsPageBase(cfg *config.Config) string {
	if cfg.CredentialsBind != "" {
		return cfg.CredentialsURL
	}
	if cfg.IssuerIsPlaceholder() {
		return ""
	}
	return strings.TrimRight(cfg.Issuer, "/")
}

// credentialsPageSharesHost reports whether the credentials page has a
// listener of its own under the host name of the main listener, on another
// port. Browsers do not keep cookies apart by port: whatever stands in
// front of the main listener is then sent the page's session cookie and can
// set one for it.
func credentialsPageSharesHost(cfg *config.Config) bool {
	if cfg.CredentialsBind == "" || cfg.IssuerIsPlaceholder() {
		return false
	}
	page, err := url.Parse(cfg.CredentialsURL)
	if err != nil {
		return false
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil {
		return false
	}
	return page.Hostname() != "" && strings.EqualFold(page.Hostname(), issuer.Hostname())
}

// binding returns the user credential binding of a backend entry, nil for
// an entry without user_credentials. On a nil setup the binding has no
// store, which makes the adapter refuse the backend with a message that
// names the setting to turn the store on.
func (u *userCredentialSetup) binding(declared []backend.UserCredential) *backend.UserCredentialBinding {
	if len(declared) == 0 {
		return nil
	}
	b := &backend.UserCredentialBinding{Credentials: declared}
	if u != nil {
		b.Store = u.store
		b.EnrollURL = u.enrollURL
	}
	return b
}

// userBackendRegistry holds the loaded backends that take credentials from
// their users. Every reload of the backends replaces it as a whole.
type userBackendRegistry struct {
	backends atomic.Pointer[map[string]*backend.RESTAdapter]
}

// set replaces the registry with the backends among named that declare
// user credentials.
func (r *userBackendRegistry) set(named map[string]backend.ToolBackend) {
	m := map[string]*backend.RESTAdapter{}
	for name, b := range named {
		if rest, ok := b.(*backend.RESTAdapter); ok && len(rest.UserCredentials()) > 0 {
			m[name] = rest
		}
	}
	r.backends.Store(&m)
}

// get returns the backend named name.
func (r *userBackendRegistry) get(name string) (*backend.RESTAdapter, bool) {
	m := r.backends.Load()
	if m == nil {
		return nil, false
	}
	rest, ok := (*m)[name]
	return rest, ok
}

// list returns the backends as the credentials page offers them.
func (r *userBackendRegistry) list() []enroll.Backend {
	m := r.backends.Load()
	if m == nil {
		return nil
	}
	out := make([]enroll.Backend, 0, len(*m))
	for name, rest := range *m {
		out = append(out, enroll.Backend{Name: name, Description: rest.Description(), Credentials: rest.UserCredentials()})
	}
	return out
}

// pageIdentity is what the credentials page needs of the server that signs
// users in: the login itself and the identity a user has now.
type pageIdentity interface {
	enroll.Authenticator
	UserIdentity(userID string) (*userctx.UserContext, bool)
}

// toolAuthorizer tells which of a list of tools a caller may execute.
// *executor.Executor implements it.
type toolAuthorizer interface {
	Authorizes() bool
	FilterAuthorizedTools(ctx context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor) []backend.ToolDescriptor
}

// credentialsPageCaller is the caller id the page acts under.
const credentialsPageCaller = "credentials-page"

// mayUseBackend reports whether userID may execute any tool of the backend,
// by the same authorization a tool call passes. The credentials page offers
// a backend, and sends its check, only to such users: a user who may call
// nothing of a backend has no business storing an account for it or making
// ToolMesh send requests to its API.
func mayUseBackend(ctx context.Context, authz toolAuthorizer, identity pageIdentity, backends *userBackendRegistry, userID, backendName string) bool {
	rest, ok := backends.get(backendName)
	if !ok {
		return false
	}
	if !authz.Authorizes() {
		return true
	}
	uc, ok := identity.UserIdentity(userID)
	if !ok {
		return false
	}
	uc.CallerID, uc.CallerName = credentialsPageCaller, credentialsPageCaller
	tools, err := rest.ListTools(ctx)
	if err != nil {
		return false
	}
	// Authorization knows tools by the names callers use.
	for i := range tools {
		tools[i].Name = backendName + "_" + tools[i].Name
	}
	return len(authz.FilterAuthorizedTools(ctx, uc, tools)) > 0
}

// warnOrphanedAccounts logs the users who have accounts stored but no
// password login any more. Their accounts are unused, and would be used
// again by whoever is given one of those user ids: accounts belong to the
// id, and nothing tells one holder of an id from the next.
func warnOrphanedAccounts(users *userCredentialSetup, identity enroll.Authenticator, logger *slog.Logger) {
	var orphaned []string
	for _, id := range users.store.Users() {
		if _, ok := identity.PasswordFingerprint(id); !ok {
			orphaned = append(orphaned, id)
		}
	}
	if len(orphaned) > 0 {
		logger.Warn("user credentials: accounts are stored for users who cannot sign in any more. They are unused, and would be used again by whoever gets one of these user ids. Before reusing an id, stop ToolMesh and remove its entries from user-credentials.json",
			"users", orphaned)
	}
}

// newCredentialsPage builds the credentials page on the user credential
// store and the loaded backends.
func newCredentialsPage(cfg *config.Config, users *userCredentialSetup, backends *userBackendRegistry, identity pageIdentity, authz toolAuthorizer, auditStore audit.AuditStore, logger *slog.Logger) (http.Handler, error) {
	page, err := enroll.New(enroll.Options{
		Store:    users.store,
		Backends: backends.list,
		Auth:     identity,
		Allowed: func(ctx context.Context, userID, backendName string) bool {
			return mayUseBackend(ctx, authz, identity, backends, userID, backendName)
		},
		Check: func(ctx context.Context, userID, backendName, account string) backend.UserCredentialCheck {
			rest, ok := backends.get(backendName)
			if !ok {
				return backend.UserCredentialCheck{Outcome: backend.UserCheckUnknown, Detail: "the backend is not loaded"}
			}
			// The check runs as the user who stores the account, so that
			// it reads that user's credentials and no one else's.
			ctx = userctx.WithUserContext(ctx, &userctx.UserContext{
				UserID:        userID,
				Authenticated: true,
				CallerID:      credentialsPageCaller,
				CallerName:    credentialsPageCaller,
			})
			return rest.CheckUserCredentials(ctx, account)
		},
		Forget: func(userID, backendName, account string) {
			if rest, ok := backends.get(backendName); ok {
				rest.ForgetAccount(userID, account)
			}
		},
		Audit:     auditStore,
		Logger:    logger,
		Key:       users.key,
		PublicURL: credentialsPageBase(cfg),
		// A page with a listener of its own is at its address and nowhere
		// else.
		AddressOnly: cfg.CredentialsBind != "",
	})
	if err != nil {
		return nil, err
	}
	return page.Handler(), nil
}
