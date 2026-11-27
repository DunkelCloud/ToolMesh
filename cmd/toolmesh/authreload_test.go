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
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// Users and API keys of the reload tests.
const (
	reloadUserA = "ada"
	reloadUserB = "grace"
	reloadKeyA  = "reload-test-key-of-ada"   //nolint:gosec // test fixture, not a credential
	reloadKeyB  = "reload-test-key-of-grace" //nolint:gosec // test fixture, not a credential
	// noUsersList is how a refusal names a file without a users list.
	noUsersList = "no users list"
)

// fakeAuthHolder holds the stores in force, as the MCP server does.
type fakeAuthHolder struct {
	users *auth.UserStore
	keys  *auth.APIKeyStore
}

func (h *fakeAuthHolder) UserStore() *auth.UserStore            { return h.users }
func (h *fakeAuthHolder) SetUserStore(users *auth.UserStore)    { h.users = users }
func (h *fakeAuthHolder) APIKeyStore() *auth.APIKeyStore        { return h.keys }
func (h *fakeAuthHolder) SetAPIKeyStore(keys *auth.APIKeyStore) { h.keys = keys }
func (h *fakeAuthHolder) inForce() (bool, map[string]string) {
	return h.users != nil || h.keys != nil, h.keys.SHA256Sums()
}
func (h *fakeAuthHolder) hasUser(name string) bool   { return h.users.Lookup(name) != nil }
func (h *fakeAuthHolder) acceptsKey(key string) bool { return h.keys != nil && h.keys.Find(key) != nil }

// usersYAML is a users.yaml with the given users, each with the password
// "<name>-pw".
func usersYAML(t *testing.T, names ...string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("users:\n")
	for _, name := range names {
		hash, err := bcrypt.GenerateFromPassword([]byte(name+"-pw"), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		b.WriteString("  - username: " + name + "\n    password_hash: \"" + string(hash) + "\"\n    plan: pro\n")
	}
	return b.String()
}

// apiKeysYAML is an apikeys.yaml with one key_sha256 entry per user_id/key
// pair.
func apiKeysYAML(pairs ...[2]string) string {
	var b strings.Builder
	b.WriteString("keys:\n")
	for _, p := range pairs {
		b.WriteString("  - user_id: " + p[0] + "\n    key_sha256: " + sha256Hex(p[1]) + "\n")
	}
	return b.String()
}

// newTestReloader loads the files of cfg as the startup does and returns a
// reloader on them with a fake server and a capturing audit store.
func newTestReloader(t *testing.T, cfg *config.Config) (*authReloader, *fakeAuthHolder, *capturingAudit) {
	t.Helper()
	usersFile, users, err := loadUsersFile(cfg.UsersConfigPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	keysFile, keys, err := loadAPIKeysFile(cfg.APIKeysConfigPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	holder := &fakeAuthHolder{users: users, keys: keys}
	rec := &capturingAudit{}
	r := newAuthReloader(cfg, holder, usersFile, keysFile, quietLogger())
	r.audit = rec
	return r, holder, rec
}

// statuses lists the statuses of the recorded audit entries.
func statuses(rec *capturingAudit) []string {
	out := make([]string, 0, len(rec.entries))
	for _, e := range rec.entries {
		out = append(out, e.Status)
	}
	return out
}

// A change is put in force once two reads agree on it, and only once.
func TestAuthReload_UsersChangeAppliedOnceSettled(t *testing.T) {
	cfg := authzTestConfig(t)
	writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserA))
	r, holder, rec := newTestReloader(t, cfg)
	ctx := context.Background()

	writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserB))
	r.poll(ctx)
	if !holder.hasUser(reloadUserA) || holder.hasUser(reloadUserB) {
		t.Fatal("a change was put in force before a second read agreed on it")
	}
	r.poll(ctx)
	if holder.hasUser(reloadUserA) || !holder.hasUser(reloadUserB) {
		t.Fatal("the settled change was not put in force")
	}
	r.poll(ctx)
	if got := statuses(rec); len(got) != 1 || got[0] != audit.StatusConfigReloaded {
		t.Fatalf("audit statuses = %v, want one %s", got, audit.StatusConfigReloaded)
	}
	md := rec.entries[0].Metadata
	if md["file"] != authFileUsers || md[auditKeyAdded] != reloadUserB || md[auditKeyRemoved] != reloadUserA {
		t.Errorf("audit metadata = %v", md)
	}
}

// A file that cannot be used is refused once, the users in force stay, and
// a usable file afterwards is put in force.
func TestAuthReload_UsersRefused(t *testing.T) {
	tests := []struct {
		name   string
		change func(t *testing.T, cfg *config.Config)
		reason string
	}{
		{"invalid YAML", func(t *testing.T, cfg *config.Config) { writeFile(t, cfg.UsersConfigPath, "users: [") }, "does not load"},
		{"misspelled key", func(t *testing.T, cfg *config.Config) {
			writeFile(t, cfg.UsersConfigPath, strings.Replace(usersYAML(t, reloadUserB), "users:", "user:", 1))
		}, noUsersList},
		{"empty file", func(t *testing.T, cfg *config.Config) { writeFile(t, cfg.UsersConfigPath, "") }, noUsersList},
		{"user without username", func(t *testing.T, cfg *config.Config) {
			writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserB)+"  - plan: pro\n")
		}, "has no username"},
		{"username twice", func(t *testing.T, cfg *config.Config) {
			writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserB, reloadUserB))
		}, "listed more than once"},
		{"file removed", func(t *testing.T, cfg *config.Config) {
			if err := os.Remove(cfg.UsersConfigPath); err != nil {
				t.Fatal(err)
			}
		}, "was removed"},
		{"unreadable", func(t *testing.T, cfg *config.Config) {
			if err := os.Remove(cfg.UsersConfigPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(cfg.UsersConfigPath, 0o700); err != nil {
				t.Fatal(err)
			}
		}, "cannot be read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authzTestConfig(t)
			cfg.AuthPassword = testMCPKey
			writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserA))
			r, holder, rec := newTestReloader(t, cfg)
			ctx := context.Background()
			inForce := holder.users

			tc.change(t, cfg)
			for range 4 {
				r.poll(ctx)
			}
			if holder.users != inForce {
				t.Fatal("the users in force were replaced")
			}
			if got := statuses(rec); len(got) != 1 || got[0] != audit.StatusConfigReloadRefused {
				t.Fatalf("audit statuses = %v, want one %s", got, audit.StatusConfigReloadRefused)
			}
			if !strings.Contains(rec.entries[0].Error, tc.reason) {
				t.Errorf("refusal %q does not say %q", rec.entries[0].Error, tc.reason)
			}

			// A usable file afterwards is put in force.
			_ = os.Remove(cfg.UsersConfigPath)
			writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserB))
			r.poll(ctx)
			r.poll(ctx)
			if !holder.hasUser(reloadUserB) || holder.hasUser(reloadUserA) {
				t.Error("the usable file after the refused one was not put in force")
			}
		})
	}
}

// A file that is gone or half written for less than one interval, as when an
// editor replaces it, is never acted on.
func TestAuthReload_TransientStatesIgnored(t *testing.T) {
	cfg := authzTestConfig(t)
	content := usersYAML(t, reloadUserA, reloadUserB)
	writeFile(t, cfg.UsersConfigPath, content)
	r, holder, rec := newTestReloader(t, cfg)
	ctx := context.Background()
	inForce := holder.users

	if err := os.Remove(cfg.UsersConfigPath); err != nil {
		t.Fatal(err)
	}
	r.poll(ctx)
	writeFile(t, cfg.UsersConfigPath, content[:strings.Index(content, "  - username: "+reloadUserB)])
	r.poll(ctx)
	writeFile(t, cfg.UsersConfigPath, content)
	r.poll(ctx)
	r.poll(ctx)

	// Rewritten with the same bytes and a new modification time.
	writeFile(t, cfg.UsersConfigPath, content)
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(cfg.UsersConfigPath, later, later); err != nil {
		t.Fatal(err)
	}
	r.poll(ctx)
	r.poll(ctx)

	if holder.users != inForce {
		t.Error("a transient state or an unchanged file replaced the users in force")
	}
	if len(rec.entries) != 0 {
		t.Errorf("audit statuses = %v, want none", statuses(rec))
	}
}

// A users.yaml that appears while ToolMesh runs without one is put in force:
// the single password no longer signs in, and the default authorization
// preset becomes team.
func TestAuthReload_UsersAppear(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.AuthPassword = testMCPKey
	s := mustSetup(t, cfg, false)
	if s.policy.Preset != authz.PresetSingleUser {
		t.Fatalf("preset at startup = %q, want %q", s.policy.Preset, authz.PresetSingleUser)
	}
	r, holder, _ := newTestReloader(t, cfg)
	r.authz = s.applier
	s.applier.setInForce(holder.inForce)
	ctx := context.Background()

	writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserA))
	r.poll(ctx)
	r.poll(ctx)
	if !holder.hasUser(reloadUserA) {
		t.Fatal("the users.yaml that appeared was not put in force")
	}
	if got := s.applier.policy.Preset; got != authz.PresetTeam {
		t.Errorf("preset after users.yaml appeared = %q, want %q", got, authz.PresetTeam)
	}
}

// A changed apikeys.yaml is put in force: a key removed from it no longer
// connects, the others do.
func TestAuthReload_APIKeyRemoved(t *testing.T) {
	cfg := authzTestConfig(t)
	writeFile(t, cfg.APIKeysConfigPath, apiKeysYAML([2]string{reloadUserA, reloadKeyA}, [2]string{reloadUserB, reloadKeyB}))
	r, holder, rec := newTestReloader(t, cfg)
	ctx := context.Background()

	writeFile(t, cfg.APIKeysConfigPath, apiKeysYAML([2]string{reloadUserB, reloadKeyB}))
	r.poll(ctx)
	r.poll(ctx)
	if holder.acceptsKey(reloadKeyA) || !holder.acceptsKey(reloadKeyB) {
		t.Fatal("the removed key still connects, or the kept one does not")
	}
	if len(rec.entries) != 1 || rec.entries[0].Metadata[auditKeyRemoved] != reloadUserA {
		t.Errorf("audit entries = %+v", rec.entries)
	}

	// Removing the file keeps the keys in force: no fall back to
	// TOOLMESH_API_KEY while ToolMesh runs.
	if err := os.Remove(cfg.APIKeysConfigPath); err != nil {
		t.Fatal(err)
	}
	r.poll(ctx)
	r.poll(ctx)
	if holder.keys == nil || !holder.acceptsKey(reloadKeyB) {
		t.Error("removing apikeys.yaml took the keys out of force")
	}
}

// An entry whose key is an approver's key does not stop a reload of
// apikeys.yaml: the rest of the file comes into force, so a key revoked in the
// same edit stops working, and the entry is reported. The MCP endpoint refuses
// the approver's key whatever the store holds (see the tests of
// mcp.Server.SetApproverKeyCheck).
func TestAuthReload_APIKeyOfApproverReported(t *testing.T) {
	cfg := authzTestConfig(t)
	writeFile(t, cfg.AuthzConfigPath, approverFile(testApproverKey))
	writeFile(t, cfg.APIKeysConfigPath, apiKeysYAML([2]string{reloadUserA, reloadKeyA}))
	s := mustSetup(t, cfg, false)
	r, holder, rec := newTestReloader(t, cfg)
	r.authz = s.applier
	s.applier.setInForce(holder.inForce)
	ctx := context.Background()

	writeFile(t, cfg.APIKeysConfigPath, apiKeysYAML([2]string{reloadUserB, reloadKeyB}, [2]string{"intruder", testApproverKey}))
	r.poll(ctx)
	r.poll(ctx)
	if holder.acceptsKey(reloadKeyA) || !holder.acceptsKey(reloadKeyB) {
		t.Fatal("the reload was not put in force")
	}
	if len(rec.entries) != 1 || rec.entries[0].Metadata["approver_keys"] != "1" {
		t.Errorf("audit entries = %+v, want one reload naming one approver key", rec.entries)
	}
}

// A file refused, then restored to the content in force, then refused again
// is reported both times; a refused file is not reported again while it
// stays.
func TestAuthReload_RefusalReportedPerChange(t *testing.T) {
	cfg := authzTestConfig(t)
	content := usersYAML(t, reloadUserA)
	writeFile(t, cfg.UsersConfigPath, content)
	r, _, rec := newTestReloader(t, cfg)
	ctx := context.Background()

	for _, step := range []string{"users: [", content, "users: ["} {
		writeFile(t, cfg.UsersConfigPath, step)
		for range 3 {
			r.poll(ctx)
		}
	}
	if got := statuses(rec); len(got) != 2 || got[0] != audit.StatusConfigReloadRefused || got[1] != audit.StatusConfigReloadRefused {
		t.Errorf("audit statuses = %v, want two refusals", got)
	}
	if strings.Contains(rec.entries[0].Error, "yaml") {
		t.Errorf("the audit entry carries the parser message %q; it belongs in the log only", rec.entries[0].Error)
	}
}

// When the authorization policy cannot be applied again after users.yaml
// came into force, the reloader tries again with every read until it can.
func TestAuthReload_AuthzReapplyRetried(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.AuthPassword = testMCPKey
	s := mustSetup(t, cfg, false)
	r, holder, _ := newTestReloader(t, cfg)
	r.authz = s.applier
	s.applier.setInForce(holder.inForce)
	ctx := context.Background()

	// The authz config is broken while users.yaml appears.
	writeFile(t, cfg.AuthzConfigPath, "grants: [")
	writeFile(t, cfg.UsersConfigPath, usersYAML(t, reloadUserA))
	r.poll(ctx)
	r.poll(ctx)
	if !holder.hasUser(reloadUserA) || !r.authzPending {
		t.Fatalf("users in force %v, retry pending %v; want both", holder.hasUser(reloadUserA), r.authzPending)
	}
	if got := s.applier.policy.Preset; got != authz.PresetSingleUser {
		t.Fatalf("preset = %q while the authz config is broken", got)
	}

	if err := os.Remove(cfg.AuthzConfigPath); err != nil {
		t.Fatal(err)
	}
	r.poll(ctx)
	if r.authzPending || s.applier.policy.Preset != authz.PresetTeam {
		t.Errorf("after the fix: retry pending %v, preset %q; want applied with %q", r.authzPending, s.applier.policy.Preset, authz.PresetTeam)
	}
}

// At startup the default preset goes by the stores that were loaded, not by
// a second look at the files.
func TestSetupAuthzInForce_FollowsLoadedStores(t *testing.T) {
	cfg := authzTestConfig(t)
	s, err := setupAuthzInForce(context.Background(), cfg, false, func() (bool, map[string]string) { return true, nil }, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	if s.policy.Preset != authz.PresetTeam {
		t.Errorf("preset = %q with a store loaded and no file on disk, want %q", s.policy.Preset, authz.PresetTeam)
	}
}

// The approver check of a reloaded authz config compares with the API keys in
// force, also when apikeys.yaml was removed from disk in the meantime.
func TestAuthzApplier_ChecksApproversAgainstKeysInForce(t *testing.T) {
	cfg := authzTestConfig(t)
	writeFile(t, cfg.APIKeysConfigPath, apiKeysYAML([2]string{reloadUserA, testMCPKey}))
	s := mustSetup(t, cfg, false)
	_, holder, _ := newTestReloader(t, cfg)
	s.applier.setInForce(holder.inForce)
	if err := os.Remove(cfg.APIKeysConfigPath); err != nil {
		t.Fatal(err)
	}

	writeFile(t, cfg.AuthzConfigPath, approverFile(testMCPKey))
	if _, err := s.applier.apply(context.Background()); err == nil || !strings.Contains(err.Error(), "alice") {
		t.Errorf("apply = %v, want the approver refused for holding a key in force", err)
	}
}
