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

package config

import (
	"testing"
)

func TestLoad_Defaults(t *testing.T) {
	// Clear any env vars that might interfere
	t.Setenv("TOOLMESH_TRANSPORT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name string
		got  any
		want any
	}{
		{"Port", cfg.Port, 8080},
		{"Transport", cfg.Transport, "http"},
		{"AuthPassword", cfg.AuthPassword, ""},
		{"APIKey", cfg.APIKey, ""},
		{"Issuer", cfg.Issuer, "https://toolmesh.io/"},
		{"AuditStore", cfg.AuditStore, "log"},
		{"AuditRetentionDays", cfg.AuditRetentionDays, 90},
		{"ExecTimeout", cfg.ExecTimeout, 120},
		{"OpenFGAAPIURL", cfg.OpenFGAAPIURL, "http://localhost:8080"},
		{"OpenFGAStoreID", cfg.OpenFGAStoreID, ""},
		{"RedisURL", cfg.RedisURL, "redis://localhost:6379/0"},
		{"LogLevel", cfg.LogLevel, "debug"},
		{"LogFormat", cfg.LogFormat, "json"},
		{"DebugBackends", cfg.DebugBackends, ""},
		{"DebugFile", cfg.DebugFile, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
}

func TestLoad_CustomValues(t *testing.T) {
	t.Setenv("TOOLMESH_TRANSPORT", "stdio")
	t.Setenv("TOOLMESH_AUTH_PASSWORD", "secret123")
	t.Setenv("TOOLMESH_API_KEY", "my-api-key")
	t.Setenv("AUDIT_STORE", "sqlite")
	t.Setenv("AUDIT_RETENTION_DAYS", "30")
	t.Setenv("TOOLMESH_EXEC_TIMEOUT", "180")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("LOG_FORMAT", "text")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (fixed internal port)", cfg.Port)
	}
	if cfg.Transport != "stdio" {
		t.Errorf("Transport = %q, want \"stdio\"", cfg.Transport)
	}
	if cfg.AuthPassword != "secret123" {
		t.Errorf("AuthPassword = %q, want \"secret123\"", cfg.AuthPassword)
	}
	if cfg.APIKey != "my-api-key" {
		t.Errorf("APIKey = %q, want \"my-api-key\"", cfg.APIKey)
	}
	if cfg.AuditStore != "sqlite" {
		t.Errorf("AuditStore = %q, want \"sqlite\"", cfg.AuditStore)
	}
	if cfg.AuditRetentionDays != 30 {
		t.Errorf("AuditRetentionDays = %d, want 30", cfg.AuditRetentionDays)
	}
	if cfg.ExecTimeout != 180 {
		t.Errorf("ExecTimeout = %d, want 180", cfg.ExecTimeout)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want \"debug\"", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want \"text\"", cfg.LogFormat)
	}
}

func TestLoad_ExecTimeout_FallbackToActivityTimeout(t *testing.T) {
	// TOOLMESH_ACTIVITY_TIMEOUT should be read as fallback
	t.Setenv("TOOLMESH_EXEC_TIMEOUT", "")
	t.Setenv("TOOLMESH_ACTIVITY_TIMEOUT", "300")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ExecTimeout != 300 {
		t.Errorf("ExecTimeout = %d, want 300 (from TOOLMESH_ACTIVITY_TIMEOUT fallback)", cfg.ExecTimeout)
	}
}

func TestConfig_DebugBackendsList(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"github", []string{"github"}},
		{"github,shellycloud", []string{"github", "shellycloud"}},
		{"github, shellycloud , vikunja", []string{"github", "shellycloud", "vikunja"}},
		{",,,", nil},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			cfg := &Config{DebugBackends: tt.input}
			got := cfg.DebugBackendsList()
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestLoad_InvalidTransport(t *testing.T) {
	t.Setenv("TOOLMESH_TRANSPORT", "grpc")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid transport, got nil")
	}
}

func TestLoad_InvalidAuditStore(t *testing.T) {
	t.Setenv("AUDIT_STORE", "postgres")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid audit store, got nil")
	}
}

func TestLoad_PortIsAlwaysFixed(t *testing.T) {
	// Port is hardcoded to 8080; TOOLMESH_PORT only controls docker host mapping
	t.Setenv("TOOLMESH_TRANSPORT", "http")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want 8080 (fixed)", cfg.Port)
	}
}
