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

const envCIMDHosts = "TOOLMESH_CIMD_HOSTS"

// Without the variable, client ID metadata documents are off: an
// installation that sets nothing fetches nothing.
func TestLoad_CIMDIsOffByDefault(t *testing.T) {
	t.Setenv(envCIMDHosts, "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CIMDEnabled() || len(cfg.CIMDHosts) != 0 {
		t.Errorf("defaults = enabled %v, hosts %v; want off without a host", cfg.CIMDEnabled(), cfg.CIMDHosts)
	}
	// A list of nothing but separators names no host either.
	t.Setenv(envCIMDHosts, " , ,")
	if cfg, err = Load(); err != nil || cfg.CIMDEnabled() {
		t.Errorf("a list without an entry: enabled %v, err %v; want off", cfg != nil && cfg.CIMDEnabled(), err)
	}
}

// Naming hosts is what switches the documents on, for those hosts.
func TestLoad_CIMDHosts(t *testing.T) {
	t.Setenv(envCIMDHosts, " Claude.AI , *.Example.com,, vscode.dev ,xn--bcher-kva.example")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.CIMDEnabled() {
		t.Error("CIMDEnabled() = false with hosts listed")
	}
	want := []string{"claude.ai", "*.example.com", "vscode.dev", "xn--bcher-kva.example"}
	if !slices.Equal(cfg.CIMDHosts, want) {
		t.Errorf("CIMDHosts = %v, want %v", cfg.CIMDHosts, want)
	}
}

// A typo must stop the server: an entry that can never match a host would
// switch the documents on, and announce them to clients, without letting any
// client in. There is no entry that allows every host.
func TestLoad_CIMDRejectsInvalidHosts(t *testing.T) {
	tests := []struct {
		name, value string
	}{
		{"entry with a scheme", "https://claude.ai"},
		{"entry with a path", "claude.ai/oauth"},
		{"entry with a port", "claude.ai:443"},
		{"wildcard in the middle", "clients.*.example.com"},
		{"wildcard without a dot", "*example.com"},
		{"every host", "*"},
		{"every host, with a dot", "*."},
		{"empty label", "claude..ai"},
		{"trailing dot", "claude.ai."},
		{"label starts with a hyphen", "-claude.ai"},
		{"space inside", "claude .ai"},
		{"not ascii", "b\xc3\xbccher.example"},
		{"a boolean instead of hosts", "true,"},
		{"one bad entry among good ones", "claude.ai,vscode.dev/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envCIMDHosts, tt.value)
			_, err := Load()
			if tt.name == "a boolean instead of hosts" {
				// "true" has the shape of a host name; nothing tells it from
				// one. It lists a host that serves no document.
				if err != nil {
					t.Fatalf("Load refused %q: %v", tt.value, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load accepted %s=%q", envCIMDHosts, tt.value)
			}
			if !strings.Contains(err.Error(), envCIMDHosts) {
				t.Errorf("error %q does not name %s", err, envCIMDHosts)
			}
		})
	}
}
