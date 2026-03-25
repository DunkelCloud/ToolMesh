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
		{"TemporalAddress", cfg.TemporalAddress, "localhost:7233"},
		{"TemporalNamespace", cfg.TemporalNamespace, "default"},
		{"TemporalTaskQueue", cfg.TemporalTaskQueue, "toolmesh"},
		{"OpenFGAAPIURL", cfg.OpenFGAAPIURL, "http://localhost:8080"},
		{"OpenFGAStoreID", cfg.OpenFGAStoreID, ""},
		{"RedisURL", cfg.RedisURL, "redis://localhost:6379/0"},
		{"LogLevel", cfg.LogLevel, "debug"},
		{"LogFormat", cfg.LogFormat, "json"},
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
	t.Setenv("TEMPORAL_ADDRESS", "temporal.example.com:7233")
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
	if cfg.TemporalAddress != "temporal.example.com:7233" {
		t.Errorf("TemporalAddress = %q, want \"temporal.example.com:7233\"", cfg.TemporalAddress)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want \"debug\"", cfg.LogLevel)
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat = %q, want \"text\"", cfg.LogFormat)
	}
}

func TestLoad_InvalidTransport(t *testing.T) {
	t.Setenv("TOOLMESH_TRANSPORT", "grpc")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid transport, got nil")
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
