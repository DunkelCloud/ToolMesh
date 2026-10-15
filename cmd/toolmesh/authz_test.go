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
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// authzTestConfig returns a config for setupAuthz whose files all live in
// one temporary directory: data/, authz.yaml, users.yaml, apikeys.yaml.
func authzTestConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		AuthzMode:         config.AuthzModeEmbedded,
		AuthzModeSource:   config.AuthzSourceDefault,
		DataDir:           filepath.Join(dir, "data"),
		AuthzConfigPath:   filepath.Join(dir, "authz.yaml"),
		UsersConfigPath:   filepath.Join(dir, "users.yaml"),
		APIKeysConfigPath: filepath.Join(dir, "apikeys.yaml"),
		AuthUser:          testOwner,
	}
}

// The backend and tool the grants in these tests name.
const (
	testOwner         = "owner"
	testPlanPro       = "pro"
	testBackendGitHub = "github"
	testToolGitHubX   = "github_x"
)

func mustSetup(t *testing.T, cfg *config.Config, priorState bool) *authzSetup {
	t.Helper()
	s, err := setupAuthz(context.Background(), cfg, priorState, quietLogger())
	if err != nil {
		t.Fatalf("setupAuthz: %v", err)
	}
	t.Cleanup(s.close)
	return s
}

func allowed(t *testing.T, s *authzSetup, req authz.Request) bool {
	t.Helper()
	ok, err := s.authorizer.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return ok
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetupAuthz_PresetSelection(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		legacy     string
		priorState bool
		usersFile  bool
		envPreset  string
		wantPreset string
		wantSource string
	}{
		{name: "fresh install", source: config.AuthzSourceDefault, wantPreset: authz.PresetSingleUser, wantSource: authz.SourceDefault},
		{name: "fresh install with users.yaml", source: config.AuthzSourceDefault, usersFile: true, wantPreset: authz.PresetTeam, wantSource: authz.SourceDefault},
		{name: "upgrade detected by prior state", source: config.AuthzSourceDefault, priorState: true, wantPreset: authz.PresetOpen, wantSource: authz.SourceUpgrade},
		{name: "upgrade detected by OPENFGA_MODE=bypass", source: config.AuthzSourceLegacy, legacy: config.OpenFGAModeBypass, wantPreset: authz.PresetOpen, wantSource: authz.SourceUpgrade},
		// Whoever sets the new variable has chosen authorization: no upgrade.
		{name: "explicit embedded with prior state", source: config.AuthzSourceEnv, priorState: true, wantPreset: authz.PresetSingleUser, wantSource: authz.SourceDefault},
		{name: "env preset over upgrade", source: config.AuthzSourceDefault, priorState: true, envPreset: authz.PresetTeam, wantPreset: authz.PresetTeam, wantSource: authz.SourceEnv},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := authzTestConfig(t)
			cfg.AuthzModeSource, cfg.LegacyOpenFGAMode, cfg.AuthzPreset = tc.source, tc.legacy, tc.envPreset
			if tc.usersFile {
				writeFile(t, cfg.UsersConfigPath, "users: []\n")
			}
			s := mustSetup(t, cfg, tc.priorState)
			if s.policy.Preset != tc.wantPreset || s.policy.Source != tc.wantSource {
				t.Errorf("policy = %s/%s, want %s/%s", s.policy.Preset, s.policy.Source, tc.wantPreset, tc.wantSource)
			}
			if got, want := s.openToEveryone(), tc.wantPreset == authz.PresetOpen; got != want {
				t.Errorf("openToEveryone = %v, want %v", got, want)
			}
		})
	}
}

// The upgrade decision is recorded on the first start; a later start of the
// same installation keeps it, although the data directory now always has
// prior state and the legacy variable may be gone.
func TestSetupAuthz_UpgradeIsRemembered(t *testing.T) {
	fresh := authzTestConfig(t)
	first := mustSetup(t, fresh, false)
	first.close()
	again := mustSetup(t, fresh, true)
	if again.policy.Preset != authz.PresetSingleUser {
		t.Errorf("fresh install restarted: preset = %s, want %s", again.policy.Preset, authz.PresetSingleUser)
	}

	upgraded := authzTestConfig(t)
	upgraded.AuthzModeSource, upgraded.LegacyOpenFGAMode = config.AuthzSourceLegacy, config.OpenFGAModeBypass
	first = mustSetup(t, upgraded, false)
	first.close()
	upgraded.AuthzModeSource, upgraded.LegacyOpenFGAMode = config.AuthzSourceDefault, ""
	again = mustSetup(t, upgraded, true)
	if again.policy.Preset != authz.PresetOpen || again.policy.Source != authz.SourceUpgrade {
		t.Errorf("upgraded install restarted: policy = %s/%s, want open/upgrade", again.policy.Preset, again.policy.Source)
	}
}

func TestSetupAuthz_FileReplacesPreset(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.AuthzPreset = authz.PresetOpen
	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - plan: pro\n    backends: [github]\n")

	var logs bytes.Buffer
	s, err := setupAuthz(context.Background(), cfg, true, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatalf("setupAuthz: %v", err)
	}
	t.Cleanup(s.close)

	if s.policy.Source != authz.SourceFile || s.openToEveryone() {
		t.Errorf("policy = %+v, want the file's grants only", s.policy)
	}
	if !strings.Contains(logs.String(), "TOOLMESH_AUTHZ_PRESET is ignored") {
		t.Errorf("no notice that the env preset is ignored:\n%s", logs.String())
	}
	if !allowed(t, s, authz.Request{UserID: "u", Plan: testPlanPro, Tool: testToolGitHubX, Backend: testBackendGitHub}) {
		t.Error("file grant not applied")
	}
	if allowed(t, s, authz.Request{UserID: testOwner, Roles: []string{"admin"}, Tool: testToolGitHubX, Backend: testBackendGitHub}) {
		t.Error("preset grant applied although the file names no preset")
	}
}

func TestSetupAuthz_Errors(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.AuthzPreset = "everyone"
	if _, err := setupAuthz(context.Background(), cfg, false, quietLogger()); err == nil || !strings.Contains(err.Error(), "TOOLMESH_AUTHZ_PRESET") {
		t.Errorf("invalid preset: err = %v", err)
	}

	cfg = authzTestConfig(t)
	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - role: admin\n")
	if _, err := setupAuthz(context.Background(), cfg, false, quietLogger()); err == nil || !strings.Contains(err.Error(), "grant 1") {
		t.Errorf("invalid file: err = %v", err)
	}
}

func TestSetupAuthz_DisabledAndExternal(t *testing.T) {
	cfg := authzTestConfig(t)
	cfg.AuthzMode = config.AuthzModeDisabled
	s := mustSetup(t, cfg, false)
	if s.authorizer != nil || !s.openToEveryone() {
		t.Errorf("disabled: authorizer = %v, openToEveryone = %v", s.authorizer, s.openToEveryone())
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, authz.DBFileName)); err == nil {
		t.Error("disabled mode created the embedded database")
	}

	cfg = authzTestConfig(t)
	cfg.AuthzMode, cfg.OpenFGAAPIURL, cfg.OpenFGAStoreID = config.AuthzModeExternal, "http://127.0.0.1:1", "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	s = mustSetup(t, cfg, false)
	if _, ok := s.authorizer.(*authz.External); !ok || s.embedded != nil {
		t.Errorf("external: authorizer = %T", s.authorizer)
	}
}

func TestWatchAuthzConfig_AppliesCreateChangeDelete(t *testing.T) {
	cfg := authzTestConfig(t)
	s := mustSetup(t, cfg, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAuthzConfig(ctx, cfg, s.embedded, 10*time.Millisecond, quietLogger())

	bob := authz.Request{UserID: "bob", Plan: testPlanPro, Tool: testToolGitHubX, Backend: testBackendGitHub}
	eventually := func(want bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for allowed(t, s, bob) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: allowed stayed %v", what, !want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	eventually(false, "before the file exists")
	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - plan: pro\n    backends: [github]\n")
	eventually(true, "after the file was created")

	// A file that does not parse keeps the grants in place.
	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - plan: pro\n")
	time.Sleep(100 * time.Millisecond)
	eventually(true, "after the file became invalid")

	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - plan: pro\n    backends: [deepl]\n")
	eventually(false, "after the grant was changed")

	writeFile(t, cfg.AuthzConfigPath, "grants:\n  - plan: pro\n    backends: [github]\n")
	eventually(true, "after the grant was restored")
	if err := os.Remove(cfg.AuthzConfigPath); err != nil {
		t.Fatal(err)
	}
	eventually(false, "after the file was removed (preset single-user)")
}

func TestRecordAuthzDisabled(t *testing.T) {
	store := &capturingAudit{}
	cfg := &config.Config{AuthzMode: config.AuthzModeDisabled, AuthzModeSource: config.AuthzSourceEnv}
	recordAuthzDisabled(context.Background(), store, cfg, quietLogger())
	if len(store.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(store.entries))
	}
	e := store.entries[0]
	if e.Status != audit.StatusAuthzDisabled || e.Metadata["event"] != "authz_disabled" || e.Metadata["source"] != config.AuthzSourceEnv || e.TraceID == "" {
		t.Errorf("entry = %+v", e)
	}
}

type capturingAudit struct{ entries []audit.AuditEntry }

func (c *capturingAudit) Record(_ context.Context, e audit.AuditEntry) error {
	c.entries = append(c.entries, e)
	return nil
}

func (c *capturingAudit) Query(context.Context, audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, audit.ErrQueryNotSupported
}

func (c *capturingAudit) Healthy(context.Context) error { return nil }

// A deny in the config file blocks a tool the preset grants, and lifting it
// on a later change restores the tool without a restart.
func TestWatchAuthzConfig_Denies(t *testing.T) {
	cfg := authzTestConfig(t)
	writeFile(t, cfg.AuthzConfigPath, "preset: team\ndenies:\n  - user: owner\n    tools: [github_x]\n")
	s := mustSetup(t, cfg, false)
	if len(s.policy.Denies) != 1 {
		t.Fatalf("policy denies = %v, want 1", s.policy.Denies)
	}

	owner := authz.Request{UserID: testOwner, Plan: testPlanPro, Roles: []string{"admin"}, Tool: testToolGitHubX, Backend: testBackendGitHub}
	neighbor := owner
	neighbor.Tool = "github_y"
	if allowed(t, s, owner) || !allowed(t, s, neighbor) {
		t.Fatalf("with deny: github_x=%v github_y=%v, want false/true", allowed(t, s, owner), allowed(t, s, neighbor))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchAuthzConfig(ctx, cfg, s.embedded, 10*time.Millisecond, quietLogger())
	writeFile(t, cfg.AuthzConfigPath, "preset: team\n")
	deadline := time.Now().Add(5 * time.Second)
	for !allowed(t, s, owner) {
		if time.Now().After(deadline) {
			t.Fatal("deny still in effect after it was removed from the file")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
