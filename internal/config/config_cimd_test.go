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

// Without the variables, client ID metadata documents are off: an
// installation that sets nothing fetches nothing, and an upgrade changes
// nothing for its clients.
func TestLoad_CIMDIsOffByDefault(t *testing.T) {
	clearCIMDEnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CIMDEnabled || len(cfg.CIMDHosts) != 0 {
		t.Errorf("defaults = enabled %v, hosts %v; want off without a host list", cfg.CIMDEnabled, cfg.CIMDHosts)
	}
	// Naming hosts alone does not switch the documents on.
	t.Setenv(envCIMDHosts, "claude.ai")
	if cfg, err = Load(); err != nil || cfg.CIMDEnabled {
		t.Errorf("hosts without the switch: enabled %v, err %v; want off", cfg != nil && cfg.CIMDEnabled, err)
	}
}

// The switch turns the documents on, for any public host until hosts are
// named. "*" says the same as the unset variable.
func TestLoad_CIMDSwitchAndHosts(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hosts string
		want  []string
	}{
		{"no hosts", "", nil},
		{"every host, spelled out", " * ", nil},
		{"hosts", " Claude.AI , *.Example.com,, vscode.dev ,xn--bcher-kva.example", []string{"claude.ai", "*.example.com", "vscode.dev", "xn--bcher-kva.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearCIMDEnv(t)
			t.Setenv(envCIMDEnabled, "true")
			t.Setenv(envCIMDHosts, tc.hosts)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.CIMDEnabled {
				t.Error("CIMDEnabled = false, want true")
			}
			if !slices.Equal(cfg.CIMDHosts, tc.want) {
				t.Errorf("CIMDHosts = %v, want %v", cfg.CIMDHosts, tc.want)
			}
		})
	}
}

// A typo must stop the server. A switch that is no boolean would be taken
// for off by an operator who meant on; an entry that can never match a host
// would look like a restriction and allow nothing.
func TestLoad_CIMDRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"switch is not a bool", envCIMDEnabled, "enabled"},
		{"entry with a scheme", envCIMDHosts, "https://claude.ai"},
		{"entry with a path", envCIMDHosts, "claude.ai/oauth"},
		{"entry with a port", envCIMDHosts, "claude.ai:443"},
		{"wildcard in the middle", envCIMDHosts, "clients.*.example.com"},
		{"wildcard without a dot", envCIMDHosts, "*example.com"},
		{"every host next to a host", envCIMDHosts, "claude.ai,*"},
		{"wildcard without a name", envCIMDHosts, "*."},
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
