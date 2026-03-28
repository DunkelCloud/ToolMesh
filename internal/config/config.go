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

// Package config provides environment-based configuration for ToolMesh.
package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all ToolMesh configuration values.
type Config struct {
	// MCP Server
	Port         int
	Transport    string // "http" or "stdio"
	AuthPassword string
	APIKey       string
	Issuer       string

	// Temporal
	TemporalMode      string // "bypass" (default) or "durable"
	TemporalAddress   string
	TemporalNamespace string
	TemporalTaskQueue string

	// OpenFGA
	OpenFGAAPIURL  string
	OpenFGAStoreID string
	OpenFGAMode    string // "bypass" (default) or "restrict"

	// Redis
	RedisURL string

	// Logging
	LogLevel  string
	LogFormat string

	// Debug file logging (per-backend)
	DebugBackends string // comma-separated backend names for file-level debug
	DebugFile     string // path to the debug log file

	// Backends config path
	BackendsConfigPath string

	// DADL directory for REST Proxy definitions
	DADLDir string

	// Policies directory
	PoliciesDir string

	// Tool definitions directory (TypeScript canonical source)
	ToolsDir string

	// User identity config paths
	UsersConfigPath         string
	APIKeysConfigPath       string
	CallerClassesConfigPath string

	// Simple-mode auth identity (used with TOOLMESH_AUTH_PASSWORD / TOOLMESH_API_KEY
	// when no users.yaml or apikeys.yaml is configured)
	AuthUser  string // TOOLMESH_AUTH_USER, default "owner"
	AuthPlan  string // TOOLMESH_AUTH_PLAN, default "pro"
	AuthRoles string // TOOLMESH_AUTH_ROLES, default "admin" (comma-separated)

	// Persistent state directory
	DataDir string

	// CORS
	CORSAllowedOrigins []string // TOOLMESH_CORS_ORIGINS, comma-separated allowlist

	// Registry-based provider selection
	CredentialStore string // registered store name (default: "embedded")
	GateEvaluators  string // comma-separated evaluator chain (default: "goja")
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Port:                    8080, // always listen on 8080 inside container; TOOLMESH_PORT controls host-side mapping only
		Transport:               envStr("TOOLMESH_TRANSPORT", "http"),
		AuthPassword:            envStr("TOOLMESH_AUTH_PASSWORD", ""),
		APIKey:                  envStr("TOOLMESH_API_KEY", ""),
		Issuer:                  envStr("TOOLMESH_ISSUER", "https://toolmesh.io/"),
		TemporalMode:            envStr("TEMPORAL_MODE", "bypass"),
		TemporalAddress:         envStr("TEMPORAL_ADDRESS", "localhost:7233"),
		TemporalNamespace:       envStr("TEMPORAL_NAMESPACE", "default"),
		TemporalTaskQueue:       envStr("TEMPORAL_TASK_QUEUE", "toolmesh"),
		OpenFGAAPIURL:           envStr("OPENFGA_API_URL", "http://localhost:8080"),
		OpenFGAStoreID:          envStr("OPENFGA_STORE_ID", ""),
		OpenFGAMode:             envStr("OPENFGA_MODE", "bypass"),
		RedisURL:                envStr("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:                envStr("LOG_LEVEL", "debug"), // default "debug" for MCP diagnostics; set to "info" in production
		LogFormat:               envStr("LOG_FORMAT", "json"),
		DebugBackends:           envStr("DEBUG_BACKENDS", ""),
		DebugFile:               envStr("DEBUG_FILE", ""),
		BackendsConfigPath:      envStr("TOOLMESH_BACKENDS_CONFIG", "/app/config/backends.yaml"),
		DADLDir:                 envStr("TOOLMESH_DADL_DIR", "/app/dadl"),
		PoliciesDir:             envStr("TOOLMESH_POLICIES_DIR", "/app/policies"),
		ToolsDir:                envStr("TOOLMESH_TOOLS_DIR", "/app/tools"),
		UsersConfigPath:         envStr("TOOLMESH_USERS_CONFIG", "/app/config/users.yaml"),
		APIKeysConfigPath:       envStr("TOOLMESH_APIKEYS_CONFIG", "/app/config/apikeys.yaml"),
		CallerClassesConfigPath: envStr("TOOLMESH_CALLER_CLASSES_CONFIG", "/app/config/caller-classes.yaml"),
		AuthUser:                envStr("TOOLMESH_AUTH_USER", "owner"),
		AuthPlan:                envStr("TOOLMESH_AUTH_PLAN", "pro"),
		AuthRoles:               envStr("TOOLMESH_AUTH_ROLES", "admin"),
		DataDir:                 envStr("TOOLMESH_DATA_DIR", "/app/data"),
		CredentialStore:         envStr("CREDENTIAL_STORE", "embedded"),
		GateEvaluators:          envStr("GATE_EVALUATORS", "goja"),
	}

	// Parse CORS origins
	if raw := envStr("TOOLMESH_CORS_ORIGINS", ""); raw != "" {
		for _, o := range strings.Split(raw, ",") {
			if s := strings.TrimSpace(o); s != "" {
				cfg.CORSAllowedOrigins = append(cfg.CORSAllowedOrigins, s)
			}
		}
	}

	if cfg.Transport != "http" && cfg.Transport != "stdio" {
		return nil, fmt.Errorf("invalid TOOLMESH_TRANSPORT: %q (must be \"http\" or \"stdio\")", cfg.Transport)
	}

	if cfg.OpenFGAMode != "bypass" && cfg.OpenFGAMode != "restrict" {
		return nil, fmt.Errorf("invalid OPENFGA_MODE: %q (must be \"bypass\" or \"restrict\")", cfg.OpenFGAMode)
	}

	if cfg.TemporalMode != "bypass" && cfg.TemporalMode != "durable" {
		return nil, fmt.Errorf("invalid TEMPORAL_MODE: %q (must be \"bypass\" or \"durable\")", cfg.TemporalMode)
	}

	return cfg, nil
}

// AuthRolesList returns the simple-mode auth roles as a string slice.
func (c *Config) AuthRolesList() []string {
	return strings.Split(c.AuthRoles, ",")
}

// DebugBackendsList returns the parsed list of backend names for debug logging.
// Returns nil if DEBUG_BACKENDS is empty.
func (c *Config) DebugBackendsList() []string {
	if c.DebugBackends == "" {
		return nil
	}
	parts := strings.Split(c.DebugBackends, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			result = append(result, s)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
