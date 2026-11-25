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
	"slices"
	"strings"
	"testing"
)

const (
	envCIMDEnabled = "TOOLMESH_CIMD_ENABLED"
	envCIMDHosts   = "TOOLMESH_CIMD_HOSTS"
)

func clearCIMDEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{envCIMDEnabled, envCIMDHosts} {
		t.Setenv(key, "")
	}
}

// Without the variables, clients may name themselves by a metadata URL and
// no host is excluded.
func TestLoad_CIMDDefaults(t *testing.T) {
	clearCIMDEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.CIMDEnabled || len(cfg.CIMDHosts) != 0 {
		t.Errorf("defaults = enabled %v, hosts %v; want on without a host list", cfg.CIMDEnabled, cfg.CIMDHosts)
	}
}

func TestLoad_CIMDCustom(t *testing.T) {
	clearCIMDEnv(t)
	t.Setenv(envCIMDEnabled, "false")
	t.Setenv(envCIMDHosts, " Claude.AI , *.Example.com,, vscode.dev ,xn--bcher-kva.example")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CIMDEnabled {
		t.Error("CIMDEnabled = true, want false")
	}
	want := []string{"claude.ai", "*.example.com", "vscode.dev", "xn--bcher-kva.example"}
	if !slices.Equal(cfg.CIMDHosts, want) {
		t.Errorf("CIMDHosts = %v, want %v", cfg.CIMDHosts, want)
	}
}

// A typo must stop the server. A switch that is not a bool would leave the
// fetch on; an entry that can never match a host would look like a
// restriction and allow nothing, or be meant as one and not be in force.
func TestLoad_CIMDRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"switch is not a bool", envCIMDEnabled, "disabled"},
		{"entry with a scheme", envCIMDHosts, "https://claude.ai"},
		{"entry with a path", envCIMDHosts, "claude.ai/oauth"},
		{"entry with a port", envCIMDHosts, "claude.ai:443"},
		{"wildcard in the middle", envCIMDHosts, "clients.*.example.com"},
		{"wildcard without a dot", envCIMDHosts, "*example.com"},
		{"wildcard alone", envCIMDHosts, "*"},
		{"wildcard for everything", envCIMDHosts, "*."},
		{"empty label", envCIMDHosts, "claude..ai"},
		{"trailing dot", envCIMDHosts, "claude.ai."},
		{"label starts with a hyphen", envCIMDHosts, "-claude.ai"},
		{"space inside", envCIMDHosts, "claude .ai"},
		{"not ascii", envCIMDHosts, "b\xc3\xbccher.example"},
		{"one bad entry among good ones", envCIMDHosts, "claude.ai,vscode.dev/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearCIMDEnv(t)
			t.Setenv(tt.key, tt.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("Load accepted %s=%q", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error %q does not name %s", err, tt.key)
			}
		})
	}
}
