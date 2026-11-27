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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/google/uuid"
)

// authReloadInterval is how often users.yaml and apikeys.yaml are read for
// changes. A change is put in force once two reads in a row agree on it, so
// it takes effect 5 to 10 seconds after the file is saved.
const authReloadInterval = 5 * time.Second

// Names of the two files in logs and audit entries, and the metadata keys
// and the caller of the audit entries of a reload.
const (
	authFileUsers   = "users.yaml"
	auditKeyAdded   = "added"
	auditKeyRemoved = "removed"
	auditKeyChanged = "changed"
	auditSystem     = "system"
	authFileAPIKeys = "apikeys.yaml" //nolint:gosec // G101: a file name, not a credential
)

// authFileState is what one read of users.yaml or apikeys.yaml found.
type authFileState struct {
	exists bool
	// readErr is set when the file exists but could not be read.
	readErr string
	sum     [sha256.Size]byte
	data    []byte
}

// readAuthFile reads the file at path. A file that does not exist is a state
// of its own, distinct from one that cannot be read.
func readAuthFile(path string) authFileState {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	switch {
	case err == nil:
		return authFileState{exists: true, sum: sha256.Sum256(data), data: data}
	case errors.Is(err, fs.ErrNotExist):
		return authFileState{}
	default:
		return authFileState{exists: true, readErr: err.Error()}
	}
}

// same reports whether s and o are the same state of the file: both absent,
// both unreadable for the same reason, or the same content.
func (s authFileState) same(o authFileState) bool {
	return s.exists == o.exists && s.readErr == o.readErr && s.sum == o.sum
}

// loadUsersFile reads users.yaml once and builds its store from those bytes,
// so that what is loaded and what the reloader compares with later are the
// same. The store is nil when the file does not exist.
func loadUsersFile(path string, limiter *auth.CompareLimiter) (authFileState, *auth.UserStore, error) {
	st := readAuthFile(path)
	switch {
	case st.readErr != "":
		return st, nil, fmt.Errorf("read users config: %s", st.readErr)
	case !st.exists:
		return st, nil, nil
	}
	users, err := auth.ParseUserStore(st.data, limiter)
	return st, users, err
}

// loadAPIKeysFile is loadUsersFile for apikeys.yaml.
func loadAPIKeysFile(path string, limiter *auth.CompareLimiter) (authFileState, *auth.APIKeyStore, error) {
	st := readAuthFile(path)
	switch {
	case st.readErr != "":
		return st, nil, fmt.Errorf("read apikeys config: %s", st.readErr)
	case !st.exists:
		return st, nil, nil
	}
	keys, err := auth.ParseAPIKeyStore(st.data, limiter)
	return st, keys, err
}

// logUsersLoaded logs what in a loaded users.yaml weakens or limits the
// login, at startup and after every reload.
func logUsersLoaded(logger *slog.Logger, path string, users *auth.UserStore) {
	if users == nil {
		return
	}
	if problems := users.Problems(); len(problems) > 0 {
		logger.Warn("users config: check the file, a reload while ToolMesh runs refuses a file like this", "file", path, "problems", problems)
	}
	unusable, costs := users.HashProblems()
	if len(unusable) > 0 {
		logger.Warn("users config: password_hash is not a usable bcrypt hash, these users cannot log in", "users", unusable)
	}
	if len(costs) > 0 {
		logger.Warn("users config: password hashes use different bcrypt costs, so response time can tell some configured users from unknown ones; re-hash all passwords at one cost", "costs", costs)
	}
	if users.Count() == 0 {
		logger.Warn("users config lists no users: nobody can sign in with a password", "file", path)
	}
}

// logAPIKeysLoaded logs how the keys of a loaded apikeys.yaml are found, at
// startup and after every reload.
func logAPIKeysLoaded(logger *slog.Logger, path string, keys *auth.APIKeyStore) {
	if keys == nil {
		return
	}
	if problems := keys.Problems(); len(problems) > 0 {
		logger.Warn("apikeys config: check the file, a reload while ToolMesh runs refuses a file like this", "file", path, "problems", problems)
	}
	summary := keys.Summary()
	if len(summary.Unusable) > 0 {
		logger.Warn("apikeys config: entries have neither a key_sha256 nor a usable bcrypt key_hash, no key matches them", "user_ids", summary.Unusable)
	}
	if summary.BcryptOnly > 0 {
		logger.Warn("apikeys config: entries without key_sha256 are compared with bcrypt until their key has been used once since it was loaded; an unknown bearer credential costs one comparison per such entry until then. Add key_sha256 to look them up without bcrypt",
			"entries", summary.BcryptOnly)
	}
}

// authStoreHolder is where the users and API keys in force live: the MCP
// server.
type authStoreHolder interface {
	UserStore() *auth.UserStore
	SetUserStore(users *auth.UserStore)
	APIKeyStore() *auth.APIKeyStore
	SetAPIKeyStore(keys *auth.APIKeyStore)
}

// watchedAuthFile tracks one of the two files between reads.
type watchedAuthFile struct {
	name string
	path string
	// inForce is the state the store in force was built from.
	inForce authFileState
	// prev is the state the previous read found.
	prev authFileState
	// handled is the state acted on last, applied or refused, so that a
	// refused state is logged and audited once and not at every read.
	handled authFileState
}

// next reads the file and returns the state to act on: one that differs from
// the state in force, that the previous read found as well (so a file in the
// middle of being written is not taken), and that was not acted on already.
func (w *watchedAuthFile) next() (authFileState, bool) {
	cur := readAuthFile(w.path)
	settled := cur.same(w.prev)
	w.prev = cur
	switch {
	case cur.same(w.inForce):
		// Back at the state in force: a later change counts as new again.
		w.handled = cur
		return authFileState{}, false
	case !settled || cur.same(w.handled):
		return authFileState{}, false
	}
	w.handled = cur
	return cur, true
}

// authReloader puts changes to users.yaml and apikeys.yaml in force while
// ToolMesh runs. A change replaces the store in the MCP server at once, so a
// user removed or disabled loses access with the next request, and a changed
// password ends the user's sessions (tokens carry a fingerprint of it). A file
// that cannot be used is refused and the store in force stays. Removing a
// file is refused as well: ToolMesh does not fall back to TOOLMESH_AUTH_PASSWORD
// or TOOLMESH_API_KEY while it runs, since a file moved aside for a moment
// would otherwise turn those into the credentials in force.
type authReloader struct {
	cfg     *config.Config
	server  authStoreHolder
	limiter *auth.CompareLimiter
	// authz is the applier of the embedded authorization, nil without it.
	authz  *authzApplier
	audit  audit.AuditStore
	logger *slog.Logger
	// usersApplied, when set, runs after a users.yaml was put in force.
	usersApplied func()

	users watchedAuthFile
	keys  watchedAuthFile
}

// newAuthReloader returns a reloader whose starting point is what was loaded
// at startup: usersFile and keysFile as loadUsersFile and loadAPIKeysFile
// read them. The caller sets limiter, authz, audit and usersApplied where
// they apply.
func newAuthReloader(cfg *config.Config, server authStoreHolder, usersFile, keysFile authFileState, logger *slog.Logger) *authReloader {
	return &authReloader{
		cfg:    cfg,
		server: server,
		logger: logger,
		users:  watchedAuthFile{name: authFileUsers, path: cfg.UsersConfigPath, inForce: usersFile, prev: usersFile, handled: usersFile},
		keys:   watchedAuthFile{name: authFileAPIKeys, path: cfg.APIKeysConfigPath, inForce: keysFile, prev: keysFile, handled: keysFile},
	}
}

// run reads the files every interval until ctx ends.
func (r *authReloader) run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.poll(ctx)
		}
	}
}

// poll reads both files once and acts on what changed.
func (r *authReloader) poll(ctx context.Context) {
	if st, ok := r.users.next(); ok && r.applyUsers(ctx, st) {
		r.users.inForce = st
	}
	if st, ok := r.keys.next(); ok && r.applyKeys(ctx, st) {
		r.keys.inForce = st
	}
}

// unusable says why st cannot be put in force before its content is looked
// at, or "" when it can be parsed. envFallback names the setting ToolMesh
// would otherwise fall back to.
func unusable(st authFileState, envFallback string) string {
	switch {
	case st.readErr != "":
		return "the file cannot be read: " + st.readErr
	case !st.exists:
		return "the file was removed; ToolMesh keeps what it loaded last until it restarts and does not fall back to " + envFallback + " while it runs"
	}
	return ""
}

// applyUsers puts the users.yaml in st in force and reports whether it did.
func (r *authReloader) applyUsers(ctx context.Context, st authFileState) bool {
	if reason := unusable(st, "TOOLMESH_AUTH_PASSWORD"); reason != "" {
		return r.refuse(ctx, &r.users, reason)
	}
	next, err := auth.ParseUserStore(st.data, r.limiter)
	if err != nil {
		return r.refuse(ctx, &r.users, err.Error())
	}
	if problems := next.Problems(); len(problems) > 0 {
		return r.refuse(ctx, &r.users, strings.Join(problems, "; "))
	}

	before := r.server.UserStore()
	added, removed, changed := before.Diff(next)
	r.server.SetUserStore(next)

	r.logger.Info("users config reloaded, in force now", "file", r.users.path, "users", next.Count(),
		"added", added, "removed", removed, "changed", changed)
	logUsersLoaded(r.logger, r.users.path, next)
	if before == nil {
		if r.cfg.AuthPassword != "" {
			r.logger.Warn("users config is in force now: TOOLMESH_AUTH_PASSWORD no longer signs in, and the sessions issued for it end", "file", r.users.path)
		}
		r.reapplyAuthz(ctx)
	}
	r.record(ctx, &r.users, audit.StatusConfigReloaded, "", map[string]string{
		"users":         strconv.Itoa(next.Count()),
		auditKeyAdded:   auditList(added),
		auditKeyRemoved: auditList(removed),
		auditKeyChanged: auditList(changed),
	})
	if r.usersApplied != nil {
		r.usersApplied()
	}
	return true
}

// applyKeys puts the apikeys.yaml in st in force and reports whether it did.
// Entries whose key is an approver's key are left out: an approver key must
// not also connect as an MCP caller, and refusing the whole file instead
// would keep a key in force that the same edit revoked.
func (r *authReloader) applyKeys(ctx context.Context, st authFileState) bool {
	if reason := unusable(st, "TOOLMESH_API_KEY"); reason != "" {
		return r.refuse(ctx, &r.keys, reason)
	}
	next, err := auth.ParseAPIKeyStore(st.data, r.limiter)
	if err != nil {
		return r.refuse(ctx, &r.keys, err.Error())
	}
	if problems := next.Problems(); len(problems) > 0 {
		return r.refuse(ctx, &r.keys, strings.Join(problems, "; "))
	}

	var before *auth.APIKeyStore
	var dropped []string
	r.authz.underPolicy(func(approverKeys map[string]string) {
		next, dropped, err = next.Without(approverKeys)
		if err == nil {
			before = r.server.APIKeyStore()
			r.server.SetAPIKeyStore(next)
		}
	})
	if err != nil {
		return r.refuse(ctx, &r.keys, err.Error())
	}

	added, removed := before.Diff(next)
	r.logger.Info("apikeys config reloaded, in force now", "file", r.keys.path, "keys", next.Count(),
		"added", added, "removed", removed)
	if len(dropped) > 0 {
		r.logger.Error("apikeys config: entries left out because their key is also an approver's key; give the approver or the caller a key of its own, then save apikeys.yaml again",
			"file", r.keys.path, "entries", dropped)
	}
	logAPIKeysLoaded(r.logger, r.keys.path, next)
	if before == nil {
		if r.cfg.APIKey != "" {
			r.logger.Warn("apikeys config is in force now: TOOLMESH_API_KEY is no longer accepted", "file", r.keys.path)
		}
		r.reapplyAuthz(ctx)
	}
	r.record(ctx, &r.keys, audit.StatusConfigReloaded, "", map[string]string{
		"keys":          strconv.Itoa(next.Count()),
		auditKeyAdded:   auditList(added),
		auditKeyRemoved: auditList(removed),
		"dropped":       strconv.Itoa(len(dropped)),
	})
	return true
}

// refuse logs and audits that the state of w was not put in force, and
// returns false.
func (r *authReloader) refuse(ctx context.Context, w *watchedAuthFile, reason string) bool {
	r.logger.Error("auth config reload refused, keeping what is in force", "file", w.path, "reason", reason)
	r.record(ctx, w, audit.StatusConfigReloadRefused, reason, nil)
	return false
}

// reapplyAuthz applies the authorization policy again after users.yaml or
// apikeys.yaml came into force: the default preset depends on them.
func (r *authReloader) reapplyAuthz(ctx context.Context) {
	if r.authz == nil {
		return
	}
	if _, err := r.authz.apply(ctx); err != nil && !errors.Is(err, context.Canceled) {
		r.logger.Error("authorization policy not applied again after the auth config changed, keeping the current grants", "error", err)
	}
}

// record writes the audit entry of a reload or a refused one.
func (r *authReloader) record(ctx context.Context, w *watchedAuthFile, status, errText string, meta map[string]string) {
	if r.audit == nil {
		return
	}
	metadata := map[string]string{"event": "auth_config_reload", "file": w.name}
	maps.Copy(metadata, meta)
	err := r.audit.Record(ctx, audit.AuditEntry{
		TraceID:     uuid.New().String(),
		Timestamp:   time.Now(),
		UserID:      auditSystem,
		CallerID:    auditSystem,
		CallerClass: "trusted",
		Tool:        "toolmesh_auth_config",
		Backend:     "toolmesh",
		Status:      status,
		Error:       errText,
		Metadata:    metadata,
	})
	if err != nil {
		r.logger.Error("failed to record the audit entry of an auth config reload", "file", w.path, "error", err)
	}
}

// auditListMax is how many names an audit entry lists before it counts the
// rest.
const auditListMax = 50

// auditList joins names for an audit entry, at most auditListMax of them.
func auditList(names []string) string {
	if len(names) <= auditListMax {
		return strings.Join(names, ",")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:auditListMax], ","), len(names)-auditListMax)
}
