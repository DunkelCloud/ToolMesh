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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
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
	// policy is the policy applied at startup (embedded mode only).
	policy authz.Policy
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
	policy, err := applyAuthzPolicy(ctx, cfg, emb, logger)
	if err != nil {
		_ = emb.Close()
		return nil, err
	}
	logger.Info("authorization: embedded",
		"database", filepath.Join(cfg.DataDir, authz.DBFileName),
		"store_id", emb.StoreID(), "model_id", emb.ModelID())
	return &authzSetup{authorizer: emb, embedded: emb, policy: policy}, nil
}

// applyAuthzPolicy resolves the grants (config file, TOOLMESH_AUTHZ_PRESET,
// upgrade preset, default preset) and writes them to the embedded store. On
// an error the grants in the store stay as they were.
func applyAuthzPolicy(ctx context.Context, cfg *config.Config, emb *authz.Embedded, logger *slog.Logger) (authz.Policy, error) {
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
		DefaultPreset: defaultAuthzPreset(cfg),
		Owner:         cfg.AuthUser,
	})
	if err != nil {
		return authz.Policy{}, err
	}
	res, err := emb.Apply(ctx, policy.Grants)
	if err != nil {
		return authz.Policy{}, fmt.Errorf("apply authorization grants: %w", err)
	}

	attrs := []any{"preset", policy.Preset, "source", policy.Source, "grants", len(policy.Grants),
		"tuples", res.Tuples, "written", res.Written, "deleted", res.Deleted}
	if policy.Source == authz.SourceFile {
		attrs = append(attrs, "file", cfg.AuthzConfigPath)
	}
	logger.Info("authorization policy applied", attrs...)
	if policy.Source == authz.SourceUpgrade {
		logger.Warn("authorization keeps every tool open to every authenticated caller, as before the upgrade: this installation ran without authorization checks. Choose who may call what with TOOLMESH_AUTHZ_PRESET=single-user or team, or with grants in the authz config file",
			"preset", policy.Preset, "file", cfg.AuthzConfigPath)
	}
	return policy, nil
}

// defaultAuthzPreset picks the preset for an installation that names none:
// team when callers are configured in users.yaml or apikeys.yaml, so their
// plans count, otherwise single-user.
func defaultAuthzPreset(cfg *config.Config) string {
	for _, path := range []string{cfg.UsersConfigPath, cfg.APIKeysConfigPath} {
		if _, err := os.Stat(path); err == nil {
			return authz.PresetTeam
		}
	}
	return authz.PresetSingleUser
}

// watchAuthzConfig applies the authz config file again whenever it appears,
// changes or disappears. Unlike watchBackendsConfig it also reacts to the
// file being created or removed: either changes which grants apply.
func watchAuthzConfig(ctx context.Context, cfg *config.Config, emb *authz.Embedded, interval time.Duration, logger *slog.Logger) {
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
			if _, err := applyAuthzPolicy(ctx, cfg, emb, logger); err != nil && !errors.Is(err, context.Canceled) {
				logger.Error("authz config reload failed, keeping the current grants", "file", cfg.AuthzConfigPath, "error", err)
			}
		}
	}
}

// recordAuthzDisabled writes an audit entry stating that authorization is
// disabled, so the audit trail shows for which period tool calls went
// unchecked.
func recordAuthzDisabled(ctx context.Context, store audit.AuditStore, cfg *config.Config, logger *slog.Logger) {
	err := store.Record(ctx, audit.AuditEntry{
		TraceID:     uuid.New().String(),
		Timestamp:   time.Now(),
		UserID:      "system",
		CallerID:    "system",
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
