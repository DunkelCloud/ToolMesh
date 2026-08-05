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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"gopkg.in/yaml.v3"
)

// transport identifiers accepted in unit.yaml backends entries. Kept as
// constants so the dispatch switch in LoadUnit stays grep-friendly.
const (
	transportMCPStdio = "stdio"
	transportMCPHTTP  = "http"
	transportREST     = "rest"
)

// LoadResult bundles a fully-initialized unit Backend with the MCPAdapter
// that holds its private sub-backend sessions. The caller is responsible
// for invoking adapter.Close() during shutdown. The blob store and other
// resources owned by REST sub-backends are not tracked here — they are
// reclaimed by the garbage collector when the unit Backend is dropped.
type LoadResult struct {
	Backend *Backend
	Adapter *backend.MCPAdapter
}

// ScanDir returns the absolute paths of every unit directory that is a
// direct child of unitsDir and contains a unit.yaml. The scan is
// deliberately NOT recursive: a unit must be present at
// <unitsDir>/<name>/unit.yaml to be activated. Anything deeper — for
// example shipped examples in <unitsDir>/examples/<name>/ — is ignored,
// so users opt in to running a unit by copying or linking it into the
// top level. This mirrors the project's policy of never auto-enabling
// security-relevant defaults.
//
// Returns (nil, nil) when unitsDir does not exist so an absent units
// directory is not a hard error at startup.
func ScanDir(unitsDir string) ([]string, error) {
	entries, err := os.ReadDir(unitsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("scan units dir %s: %w", unitsDir, err)
	}
	var out []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		dir := filepath.Join(unitsDir, entry.Name())
		if _, err := os.Stat(filepath.Join(dir, configFileName)); err != nil {
			continue
		}
		out = append(out, dir)
	}
	return out, nil
}

// LoadUnit parses one unit directory and returns a ready-to-register
// Backend along with the MCPAdapter that owns its private MCP sessions.
// REST sub-backends are wired in-place against blobStore; pass nil for
// units that do not declare any REST sub-backend (an absent blob store
// downgrades REST entries to a logged error rather than a panic).
//
// MCP sub-backend sessions are connected synchronously so describe() can
// observe fully-discovered tool lists. Failures on individual sub-backends
// do not abort the unit — the MCPAdapter logs and skips them, matching the
// global startup semantics — but a hard parse or wiring failure on a REST
// entry aborts the unit so a half-wired sandbox is never exposed.
//
// dadlDir is the global DADL directory (TOOLMESH_DADL_DIR). A REST
// sub-backend whose dadl path is not bundled next to unit.yaml is resolved
// against it, matching config/backends.yaml. Pass "" to disable that fallback
// (e.g. in tests with only bundled DADLs).
func LoadUnit(ctx context.Context, dir, dadlDir string, creds credentials.CredentialStore, blobStore *blob.Store, logger *slog.Logger) (*LoadResult, error) {
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
	// describe() can read the discovered tool lists. NewMCPAdapterFromEntries
	// already filters non-MCP transports, so passing the full backend list
	// is safe — REST entries fall through to the dedicated branch below.
	adapter := backend.NewMCPAdapterFromEntries(cfg.Backends, creds, logger)
	if err := adapter.Connect(ctx); err != nil {
		return nil, fmt.Errorf("connect sub-backends for %s: %w", cfg.Unit, err)
	}

	subBackends := make(map[string]backend.ToolBackend, len(cfg.Backends))
	for _, e := range cfg.Backends {
		if e.Name == "" {
			continue
		}
		switch e.Transport {
		case transportMCPStdio, transportMCPHTTP:
			subBackends[e.Name] = &mcpSubBackend{adapter: adapter, subName: e.Name}
		case transportREST:
			rest, err := loadRESTSubBackend(dir, dadlDir, e, creds, blobStore, logger)
			if err != nil {
				adapter.Close()
				return nil, fmt.Errorf("unit %s: sub-backend %q: %w", cfg.Unit, e.Name, err)
			}
			subBackends[e.Name] = rest
		default:
			adapter.Close()
			return nil, fmt.Errorf("unit %s: sub-backend %q: unknown transport %q", cfg.Unit, e.Name, e.Transport)
		}
	}

	b := New(cfg.Unit, string(source), implPath, subBackends, cfg.Expose, logger)
	if err := b.Init(ctx); err != nil {
		adapter.Close()
		return nil, err
	}
	return &LoadResult{Backend: b, Adapter: adapter}, nil
}

// loadRESTSubBackend parses the DADL file referenced by the unit entry
// and constructs a RESTAdapter ready for use as a sub-backend. The DADL
// path is resolved by resolveSubBackendDADL: a unit may bundle its DADL
// self-contained next to unit.yaml, or reference a shared one in the global
// DADL directory by bare name, the same way config/backends.yaml entries do.
//
// SSRF (allow_private_url) and TLS (tls_skip_verify) options carry the
// same defaults as global REST backends; per-tenant credential aliasing
// via env: works the same way.
func loadRESTSubBackend(
	unitDir, dadlDir string,
	entry backend.BackendEntry,
	creds credentials.CredentialStore,
	blobStore *blob.Store,
	logger *slog.Logger,
) (backend.ToolBackend, error) {
	if entry.DADL == "" {
		return nil, fmt.Errorf("transport=rest requires a dadl path")
	}
	dadlPath := resolveSubBackendDADL(unitDir, dadlDir, entry.DADL)
	spec, err := dadl.Parse(dadlPath)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dadlPath, err)
	}
	// Surface keys the runtime ignored (DADL spec §15.3 warn-and-ignore)
	for _, w := range spec.Warnings {
		logger.Warn(w, "dadl", dadlPath)
	}
	if entry.URL != "" {
		spec.Backend.BaseURL = entry.URL
	}
	// Force the in-spec backend name to match the unit-local entry name so
	// the RESTAdapter's tool descriptors line up with what the sandbox
	// binds under api.<entry.Name>.
	if entry.Name != "" && entry.Name != spec.Backend.Name {
		spec.Backend.Name = entry.Name
	}

	backendCreds := creds
	if len(entry.Env) > 0 {
		backendCreds = credentials.NewRemappingStore(creds, entry.Env)
	}

	allowPrivate := true
	if entry.AllowPrivateURL != nil {
		allowPrivate = *entry.AllowPrivateURL
	}
	// Caller file_url fetches fail closed by default, independent of the
	// admin-trusted base_url policy above.
	allowPrivateFile := false
	if entry.AllowPrivateFileURL != nil {
		allowPrivateFile = *entry.AllowPrivateFileURL
	}

	rest, err := backend.NewRESTAdapter(spec, backendCreds, logger, backend.RESTAdapterOptions{
		AllowPrivateURL:     allowPrivate,
		AllowPrivateFileURL: allowPrivateFile,
		FileURLAllowedHosts: entry.FileURLAllowedHosts,
		TLSSkipVerify:       entry.TLSSkipVerify,
		ExposeTools:         entry.ExposeTools,
		Hint:                entry.Hint,
	})
	if err != nil {
		return nil, fmt.Errorf("build REST adapter: %w", err)
	}
	if blobStore != nil {
		rest.SetBlobStore(blobStore)
	}
	if ttlStr, ok := entry.Options["blob_ttl"]; ok {
		if d, perr := time.ParseDuration(ttlStr); perr == nil {
			rest.SetBlobTTL(d)
		} else {
			logger.Warn("unit REST sub-backend: invalid blob_ttl, using default", "backend", entry.Name, "value", ttlStr)
		}
	}
	if timeoutStr, ok := entry.Options["timeout"]; ok {
		if d, perr := time.ParseDuration(timeoutStr); perr == nil {
			rest.SetHTTPTimeout(d)
		} else {
			logger.Warn("unit REST sub-backend: invalid timeout, using default", "backend", entry.Name, "value", timeoutStr)
		}
	}
	if timeoutStr, ok := entry.Options["streaming_timeout"]; ok {
		if d, perr := time.ParseDuration(timeoutStr); perr == nil {
			rest.SetStreamingHTTPTimeout(d)
		} else {
			logger.Warn("unit REST sub-backend: invalid streaming_timeout, using default", "backend", entry.Name, "value", timeoutStr)
		}
	}
	return rest, nil
}

// resolveSubBackendDADL locates a unit sub-backend's DADL file. An absolute
// path is used verbatim. A relative path is resolved first against the unit's
// own directory, so a unit that bundles its DADL next to unit.yaml keeps
// working; if no such file exists there it falls back to the global DADL
// directory, matching the config/backends.yaml convention where a bare
// filename refers to TOOLMESH_DADL_DIR. When neither a bundled file nor a
// global directory is available the unit-local path is returned, so the
// subsequent parse error names the location the author most likely intended.
func resolveSubBackendDADL(unitDir, dadlDir, dadlRef string) string {
	if filepath.IsAbs(dadlRef) {
		return dadlRef
	}
	local := filepath.Join(unitDir, dadlRef)
	if _, err := os.Stat(local); err == nil {
		return local
	}
	if dadlDir != "" {
		return filepath.Join(dadlDir, dadlRef)
	}
	return local
}
