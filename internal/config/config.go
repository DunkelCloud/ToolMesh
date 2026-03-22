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
