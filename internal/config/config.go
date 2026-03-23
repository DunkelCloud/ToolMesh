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
	"strconv"
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
	TemporalAddress   string
	TemporalNamespace string
	TemporalTaskQueue string

	// OpenFGA
	OpenFGAAPIURL  string
	OpenFGAStoreID string

	// Redis
	RedisURL string

	// Logging
	LogLevel  string
	LogFormat string

	// Backends config path
	BackendsConfigPath string

	// Policies directory
	PoliciesDir string

	// Tool definitions directory (TypeScript canonical source)
	ToolsDir string

	// User identity config paths
	UsersConfigPath  string
	APIKeysConfigPath string

	// Registry-based provider selection
	CredentialStore string // registered store name (default: "embedded")
	GateEvaluators  string // comma-separated evaluator chain (default: "goja")
}

// Load reads configuration from environment variables with sensible defaults.
func Load() (*Config, error) {
	cfg := &Config{
		Port:               envInt("TOOLMESH_PORT", 8080),
		Transport:          envStr("TOOLMESH_TRANSPORT", "http"),
		AuthPassword:       envStr("TOOLMESH_AUTH_PASSWORD", ""),
		APIKey:             envStr("TOOLMESH_API_KEY", ""),
		Issuer:             envStr("TOOLMESH_ISSUER", "https://toolmesh.io/"),
		TemporalAddress:    envStr("TEMPORAL_ADDRESS", "localhost:7233"),
		TemporalNamespace:  envStr("TEMPORAL_NAMESPACE", "default"),
		TemporalTaskQueue:  envStr("TEMPORAL_TASK_QUEUE", "toolmesh"),
		OpenFGAAPIURL:      envStr("OPENFGA_API_URL", "http://localhost:8080"),
		OpenFGAStoreID:     envStr("OPENFGA_STORE_ID", ""),
		RedisURL:           envStr("REDIS_URL", "redis://localhost:6379/0"),
		LogLevel:           envStr("LOG_LEVEL", "info"),
		LogFormat:          envStr("LOG_FORMAT", "json"),
		BackendsConfigPath: envStr("TOOLMESH_BACKENDS_CONFIG", "/app/config/backends.yaml"),
		PoliciesDir:        envStr("TOOLMESH_POLICIES_DIR", "/app/policies"),
		ToolsDir:           envStr("TOOLMESH_TOOLS_DIR", "/app/tools"),
		UsersConfigPath:    envStr("TOOLMESH_USERS_CONFIG", "/app/config/users.yaml"),
		APIKeysConfigPath:  envStr("TOOLMESH_APIKEYS_CONFIG", "/app/config/apikeys.yaml"),
		CredentialStore:    envStr("CREDENTIAL_STORE", "embedded"),
		GateEvaluators:     envStr("GATE_EVALUATORS", "goja"),
	}

	if cfg.Transport != "http" && cfg.Transport != "stdio" {
		return nil, fmt.Errorf("invalid TOOLMESH_TRANSPORT: %q (must be \"http\" or \"stdio\")", cfg.Transport)
	}

	return cfg, nil
}

func envStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
