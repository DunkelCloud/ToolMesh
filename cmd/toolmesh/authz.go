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
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/google/uuid"
)

// authzSetup is the authorization engine chosen by TOOLMESH_AUTHZ_MODE.
type authzSetup struct {
	// authorizer is nil when authorization is disabled.
	authorizer authz.Authorizer
	// embedded is set in embedded mode, where ToolMesh manages the grants.
	embedded *authz.Embedded
	// applier applies the policy to embedded (embedded mode only).
	applier *authzApplier
	// policy is the policy applied at startup (embedded mode only).
	policy authz.Policy
}

// authzApplier applies the authorization policy to the embedded store. The
// policy depends on the authz config file and on whether users.yaml or
// apikeys.yaml is in force, so it is applied at startup, by the watcher of
// the authz config file, and when one of the two files comes into force while
// ToolMesh runs. mu keeps these apart: the policy resolved last is the one
// written last. The approver check of a reloaded apikeys.yaml runs under mu
// as well (underPolicy), so that no approver key and API key can come into
// force side by side.
type authzApplier struct {
	cfg    *config.Config
	emb    *authz.Embedded
	logger *slog.Logger

	mu sync.Mutex
	// policy is the policy applied last.
	policy authz.Policy
	// inForce, once set, says what the MCP server has in force: whether
	// users.yaml or apikeys.yaml is loaded, and the key_sha256 sums of the
	// API keys. Until it is set (during startup) the files on disk decide.
	inForce func() (filesLoaded bool, keySums map[string]string)
}

// apply resolves the policy and writes it to the embedded store. On an error
// the grants in the store stay as they were.
func (a *authzApplier) apply(ctx context.Context) (authz.Policy, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	preset := defaultAuthzPreset(a.cfg)
	keySums := func() (map[string]string, error) { return auth.KeySHA256Sums(a.cfg.APIKeysConfigPath) }
	if a.inForce != nil {
		loaded, sums := a.inForce()
		preset = presetForAuthFiles(loaded)
		keySums = func() (map[string]string, error) { return sums, nil }
	}
	policy, err := applyAuthzPolicyWith(ctx, a.cfg, a.emb, a.logger, preset, keySums)
	if err != nil {
		return authz.Policy{}, err
	}
	a.policy = policy
	return policy, nil
}

// setInForce makes the policy follow what the MCP server has in force from
// now on, instead of the files on disk.
func (a *authzApplier) setInForce(f func() (bool, map[string]string)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.inForce = f
}

// underPolicy calls f with the key_sha256 sums of the approvers of the policy
// in force, mapped to a description of each, while no policy can be applied.
// A nil applier (authorization not embedded) has no approvers.
func (a *authzApplier) underPolicy(f func(approverKeys map[string]string)) {
	if a == nil {
		f(nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := make(map[string]string)
	for _, ap := range a.policy.Approvers {
		if ap.KeySHA256 != "" {
			keys[strings.ToLower(ap.KeySHA256)] = fmt.Sprintf("approver %q", ap.Name)
		}
	}
	f(keys)
}

// open reports whether every authenticated caller may execute every tool,
// either because authorization is disabled or because the policy grants
// all tools to everyone.
func (s *authzSetup) openToEveryone() bool {
	return s.authorizer == nil || (s.embedded != nil && s.policy.OpenToEveryone())
}

// close releases the engine.
func (s *authzSetup) close() {
	if s.authorizer != nil {
		_ = s.authorizer.Close()
	}
}

// setupAuthz creates the authorization engine. priorState tells whether the
// data directory held state of an earlier run before this start touched it;
// together with how the mode was chosen it tells an installation that ran
// without authorization (OPENFGA_MODE=bypass, the old default) from a fresh
// one.
func setupAuthz(ctx context.Context, cfg *config.Config, priorState bool, logger *slog.Logger) (*authzSetup, error) {
	switch {
	case cfg.LegacyOpenFGAMode != "" && cfg.AuthzModeSource == config.AuthzSourceEnv:
		logger.Warn("OPENFGA_MODE is deprecated and ignored because TOOLMESH_AUTHZ_MODE is set; remove it",
			"OPENFGA_MODE", cfg.LegacyOpenFGAMode, "TOOLMESH_AUTHZ_MODE", cfg.AuthzMode)
	case cfg.LegacyOpenFGAMode != "":
		logger.Warn("OPENFGA_MODE is deprecated; replace it with TOOLMESH_AUTHZ_MODE (restrict becomes external, bypass becomes embedded)",
			"OPENFGA_MODE", cfg.LegacyOpenFGAMode, "TOOLMESH_AUTHZ_MODE", cfg.AuthzMode)
	}

	switch cfg.AuthzMode {
	case config.AuthzModeDisabled:
		// Reported by the security-posture summary and recorded in the audit
		// trail once the audit store is up (recordAuthzDisabled).
		return &authzSetup{}, nil

	case config.AuthzModeExternal:
		ext, err := authz.NewExternal(cfg.OpenFGAAPIURL, cfg.OpenFGAStoreID, logger)
		if err != nil {
			return nil, err
		}
		logger.Info("authorization: external OpenFGA server", "url", cfg.OpenFGAAPIURL, "store_id", cfg.OpenFGAStoreID)
		return &authzSetup{authorizer: ext}, nil
	}

	if cfg.AuthzPreset != "" && !authz.ValidPreset(cfg.AuthzPreset) {
		return nil, fmt.Errorf("invalid TOOLMESH_AUTHZ_PRESET: %q (must be %q, %q or %q)",
			cfg.AuthzPreset, authz.PresetSingleUser, authz.PresetTeam, authz.PresetOpen)
	}

	upgrade := cfg.AuthzModeSource == config.AuthzSourceLegacy ||
		(cfg.AuthzModeSource == config.AuthzSourceDefault && priorState)
	emb, err := authz.OpenEmbedded(ctx, authz.EmbeddedOptions{
		Path:    filepath.Join(cfg.DataDir, authz.DBFileName),
		Upgrade: upgrade,
		Logger:  logger,
	})
	if err != nil {
		return nil, err
	}
	applier := &authzApplier{cfg: cfg, emb: emb, logger: logger}
	policy, err := applier.apply(ctx)
	if err != nil {
		_ = emb.Close()
		return nil, err
	}
	logger.Info("authorization: embedded",
		"database", filepath.Join(cfg.DataDir, authz.DBFileName),
		"store_id", emb.StoreID(), "model_id", emb.ModelID())
	return &authzSetup{authorizer: emb, embedded: emb, applier: applier, policy: policy}, nil
}

// applyAuthzPolicy resolves the grants (config file, TOOLMESH_AUTHZ_PRESET,
// upgrade preset, default preset) and writes them, with the denies and kits
// of the config file, to the embedded store, deciding the default preset and
// the approver check by the files on disk. On an error the grants in the
// store stay as they were.
func applyAuthzPolicy(ctx context.Context, cfg *config.Config, emb *authz.Embedded, logger *slog.Logger) (authz.Policy, error) {
	return applyAuthzPolicyWith(ctx, cfg, emb, logger, defaultAuthzPreset(cfg), func() (map[string]string, error) {
		return auth.KeySHA256Sums(cfg.APIKeysConfigPath)
	})
}

// applyAuthzPolicyWith is applyAuthzPolicy with the default preset and the
// key_sha256 sums of the API keys in force given. keySums is called only when
// the policy has approvers.
func applyAuthzPolicyWith(ctx context.Context, cfg *config.Config, emb *authz.Embedded, logger *slog.Logger, defaultPreset string, keySums func() (map[string]string, error)) (authz.Policy, error) {
	file, err := authz.LoadFile(cfg.AuthzConfigPath)
	if err != nil {
		return authz.Policy{}, err
	}
	if file != nil && cfg.AuthzPreset != "" {
		logger.Info("TOOLMESH_AUTHZ_PRESET is ignored because the authz config file exists; name the preset in the file instead",
			"file", cfg.AuthzConfigPath, "TOOLMESH_AUTHZ_PRESET", cfg.AuthzPreset)
	}
	policy, err := authz.ResolvePolicy(authz.PolicyInput{
		File:          file,
		EnvPreset:     cfg.AuthzPreset,
		UpgradePreset: emb.UpgradePreset(),
		DefaultPreset: defaultPreset,
		Owner:         cfg.AuthUser,
	})
	if err != nil {
		return authz.Policy{}, err
	}
	if err := checkApproverKeys(cfg, policy.Approvers, keySums); err != nil {
		return authz.Policy{}, fmt.Errorf("authz config: %w", err)
	}
	res, err := emb.ApplyPolicy(ctx, policy)
	if err != nil {
		return authz.Policy{}, fmt.Errorf("apply authorization rules: %w", err)
	}

	attrs := []any{"preset", policy.Preset, "source", policy.Source, "grants", len(policy.Grants),
		"denies", len(policy.Denies), "kits", len(policy.Kits), "approvers", len(policy.Approvers),
		"tuples", res.Tuples, "written", res.Written, "deleted", res.Deleted}
	if policy.Source == authz.SourceFile {
		attrs = append(attrs, "file", cfg.AuthzConfigPath)
	}
	logger.Info("authorization policy applied", attrs...)
	if len(policy.Kits) > 0 && len(policy.Approvers) == 0 {
		logger.Warn("the authz config file defines kits but no approvers, so no kit can be granted; add approvers to it",
			"file", cfg.AuthzConfigPath, "kits", len(policy.Kits))
	}
	if policy.Source == authz.SourceUpgrade {
		logger.Warn("authorization keeps every tool open to every authenticated caller, as before the upgrade: this installation ran without authorization checks. Choose who may call what with TOOLMESH_AUTHZ_PRESET=single-user or team, or with grants in the authz config file",
			"preset", policy.Preset, "file", cfg.AuthzConfigPath)
	}
	return policy, nil
}

// Variables of the credentials checkApproverKeys compares approver keys with.
const (
	envAPIKey       = "TOOLMESH_API_KEY"       //nolint:gosec // the variable's name, not a credential
	envAuthPassword = "TOOLMESH_AUTH_PASSWORD" //nolint:gosec // the variable's name, not a credential
)

// checkApproverKeys refuses an approver whose key is also a credential MCP
// callers connect with: TOOLMESH_API_KEY, TOOLMESH_AUTH_PASSWORD or a key
// with a key_sha256 in apikeys.yaml, whose sums keySums returns. Keys known
// only by a bcrypt key_hash cannot be compared.
func checkApproverKeys(cfg *config.Config, approvers []authz.Approver, keySums func() (map[string]string, error)) error {
	if len(approvers) == 0 {
		return nil
	}
	sums, err := keySums()
	if err != nil {
		return fmt.Errorf("compare the approver keys with the API keys: %w", err)
	}
	reserved := make(map[string]string, len(sums)+2)
	maps.Copy(reserved, sums)
	for name, secret := range map[string]string{envAPIKey: cfg.APIKey, envAuthPassword: cfg.AuthPassword} {
		if secret != "" {
			sum := sha256.Sum256([]byte(secret))
			reserved[hex.EncodeToString(sum[:])] = name
		}
	}
	return authz.CheckApproverKeys(approvers, reserved)
}

// defaultAuthzPreset picks the preset for an installation that names none,
// by the files on disk: team when callers are configured in users.yaml or
// apikeys.yaml, so their plans count, otherwise single-user.
func defaultAuthzPreset(cfg *config.Config) string {
	for _, path := range []string{cfg.UsersConfigPath, cfg.APIKeysConfigPath} {
		if _, err := os.Stat(path); err == nil {
			return presetForAuthFiles(true)
		}
	}
	return presetForAuthFiles(false)
}

// presetForAuthFiles is the default preset when users.yaml or apikeys.yaml is
// in force (loaded) or not.
func presetForAuthFiles(loaded bool) string {
	if loaded {
		return authz.PresetTeam
	}
	return authz.PresetSingleUser
}

// startAuthzConfigWatch starts a goroutine that applies the authz config file
// again whenever it appears, changes or disappears, polling every interval
// until ctx ends. Unlike watchBackendsConfig it also reacts to the file being
// created or removed: either changes which grants apply.
//
// The state to compare against is taken before startAuthzConfigWatch
// returns, not inside the goroutine: otherwise an edit made right after the
// call could become that starting state and never be applied.
func startAuthzConfigWatch(ctx context.Context, applier *authzApplier, interval time.Duration) {
	cfg, logger := applier.cfg, applier.logger
	// Size as well as time: two edits within the file system's timestamp
	// resolution would otherwise look like one.
	type fileStamp struct {
		exists bool
		mod    time.Time
		size   int64
	}
	stamp := func() fileStamp {
		info, err := os.Stat(cfg.AuthzConfigPath)
		if err != nil {
			return fileStamp{}
		}
		return fileStamp{exists: true, mod: info.ModTime(), size: info.Size()}
	}
	last := stamp()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cur := stamp()
				if cur.exists == last.exists && cur.mod.Equal(last.mod) && cur.size == last.size {
					continue
				}
				last = cur
				logger.Info("authz config changed, applying grants", "file", cfg.AuthzConfigPath, "exists", cur.exists)
				if _, err := applier.apply(ctx); err != nil && !errors.Is(err, context.Canceled) {
					logger.Error("authz config reload failed, keeping the current grants", "file", cfg.AuthzConfigPath, "error", err)
				}
			}
		}
	}()
}

// recordAuthzDisabled writes an audit entry stating that authorization is
// disabled, so the audit trail shows for which period tool calls went
// unchecked.
func recordAuthzDisabled(ctx context.Context, store audit.AuditStore, cfg *config.Config, logger *slog.Logger) {
	err := store.Record(ctx, audit.AuditEntry{
		TraceID:     uuid.New().String(),
		Timestamp:   time.Now(),
		UserID:      auditSystem,
		CallerID:    auditSystem,
		CallerClass: "trusted",
		Tool:        "toolmesh_authz",
		Backend:     "toolmesh",
		Status:      audit.StatusAuthzDisabled,
		Metadata: map[string]string{
			"event":  "authz_disabled",
			"mode":   cfg.AuthzMode,
			"source": cfg.AuthzModeSource,
		},
	})
	if err != nil {
		logger.Error("failed to record the authz-disabled audit entry", "error", err)
	}
}
