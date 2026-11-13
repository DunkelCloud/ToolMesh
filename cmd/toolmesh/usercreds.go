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
	"fmt"
	"log/slog"
	"net/http"
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

// userCredentialsKeyEnv names the setting that turns the store on.
const userCredentialsKeyEnv = "TOOLMESH_USER_CREDENTIALS_KEY" //nolint:gosec // the variable's name, not a credential

// newUserCredentialSetup opens the store for credentials of users in the
// data directory. It returns nil without TOOLMESH_USER_CREDENTIALS_KEY: the
// store is opt-in, because its key is the operator's to create and keep.
func newUserCredentialSetup(cfg *config.Config, logger *slog.Logger) (*userCredentialSetup, error) {
	if cfg.UserCredentialsKey == "" {
		return nil, nil
	}
	key, err := credentials.ParseUserCredentialsKey(cfg.UserCredentialsKey)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", userCredentialsKeyEnv, err)
	}
	// The key is taken out of the environment once it is read: stdio
	// backends are started later and inherit the environment, and none of
	// them has any use for the key to every user's credentials.
	if err := os.Unsetenv(userCredentialsKeyEnv); err != nil {
		logger.Warn("could not take the user credentials key out of the environment; stdio backends inherit it", "error", err)
	}
	store, err := credentials.NewFileUserStore(cfg.DataDir, key)
	if err != nil {
		return nil, err
	}
	setup := &userCredentialSetup{store: store, key: key}
	if !cfg.IssuerIsPlaceholder() {
		setup.enrollURL = strings.TrimRight(cfg.Issuer, "/") + enroll.Path
	}
	logger.Info("user credential store initialized", "dataDir", cfg.DataDir)
	return setup, nil
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
	publicURL := ""
	if !cfg.IssuerIsPlaceholder() {
		publicURL = strings.TrimRight(cfg.Issuer, "/")
	}
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
		Forget: func(userID, backendName string) {
			if rest, ok := backends.get(backendName); ok {
				rest.ForgetUser(userID)
			}
		},
		Audit:     auditStore,
		Logger:    logger,
		Key:       users.key,
		PublicURL: publicURL,
	})
	if err != nil {
		return nil, err
	}
	return page.Handler(), nil
}
