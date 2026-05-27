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

package unit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"gopkg.in/yaml.v3"
)

// LoadResult bundles a fully-initialized unit Backend with the MCPAdapter
// that holds its private sub-backend sessions. The caller is responsible
// for invoking adapter.Close() during shutdown.
type LoadResult struct {
	Backend *Backend
	Adapter *backend.MCPAdapter
}

// ScanDir walks unitsDir recursively and returns every directory that
// contains a unit.yaml. Recursion stops at the first unit.yaml on a path,
// so a unit's own subdirectories (fixtures, sample inputs, sub-modules)
// are not mistaken for nested units. Authors are free to group units by
// any structure they like — e.g. examples/<name>, prod/<name>,
// tenants/<id>/<name>.
//
// Returns (nil, nil) when unitsDir does not exist so an absent units
// directory is not a hard error at startup.
func ScanDir(unitsDir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(unitsDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return filepath.SkipDir
			}
			return walkErr
		}
		if !d.IsDir() {
			return nil
		}
		if _, err := os.Stat(filepath.Join(path, configFileName)); err == nil {
			out = append(out, path)
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan units dir %s: %w", unitsDir, err)
	}
	return out, nil
}

// LoadUnit parses one unit directory and returns a ready-to-register
// Backend along with the MCPAdapter that owns its private sessions. The
// sub-backend sessions are connected synchronously so describe() sees
// fully-discovered tool lists; failures on individual sub-backends do not
// abort the unit (the MCPAdapter logs and skips them), matching the
// global startup semantics.
func LoadUnit(ctx context.Context, dir string, creds credentials.CredentialStore, logger *slog.Logger) (*LoadResult, error) {
	if logger == nil {
		logger = slog.Default()
	}
	cfgPath := filepath.Join(dir, configFileName)
	data, err := os.ReadFile(cfgPath) //nolint:gosec // path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", cfgPath, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", cfgPath, err)
	}
	if cfg.Unit == "" {
		return nil, fmt.Errorf("%s: unit name is required", cfgPath)
	}
	if cfg.Implementation == "" {
		return nil, fmt.Errorf("%s: implementation path is required", cfgPath)
	}

	implPath := cfg.Implementation
	if !filepath.IsAbs(implPath) {
		implPath = filepath.Join(dir, implPath)
	}
	source, err := os.ReadFile(implPath) //nolint:gosec // path under unit directory
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", implPath, err)
	}

	// Build the MCPAdapter for this unit. We connect synchronously here so
	// describe() can read the discovered tool lists.
	adapter := backend.NewMCPAdapterFromEntries(cfg.Backends, creds, logger)
	if err := adapter.Connect(ctx); err != nil {
		// Connect logs individual failures but never returns an error
		// today; treat any future return as fatal for the unit so we do
		// not silently expose a half-wired sandbox.
		return nil, fmt.Errorf("connect sub-backends for %s: %w", cfg.Unit, err)
	}

	subBackends := make(map[string]backend.ToolBackend, len(cfg.Backends))
	for _, e := range cfg.Backends {
		if e.Name == "" {
			continue
		}
		if e.Transport == "rest" {
			// REST sub-backends are deliberately deferred — the dice
			// walking-skeleton does not need them, and wiring them up
			// requires the blob store/telemetry threading that lives
			// in cmd/toolmesh. Track this as a follow-up.
			logger.Warn("unit sub-backend with transport=rest skipped (not yet supported in units)",
				"unit", cfg.Unit, "backend", e.Name)
			continue
		}
		subBackends[e.Name] = &mcpSubBackend{adapter: adapter, subName: e.Name}
	}

	b := New(cfg.Unit, string(source), implPath, subBackends, cfg.Expose, logger)
	if err := b.Init(ctx); err != nil {
		adapter.Close()
		return nil, err
	}
	return &LoadResult{Backend: b, Adapter: adapter}, nil
}
