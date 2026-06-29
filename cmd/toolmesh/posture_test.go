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

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

// Log levels as they appear in slog's JSON output, named to keep the magic
// strings out of the table below.
const (
	levelWARN = "WARN"
	levelINFO = "INFO"
)

// hardenedConfig returns a Config whose every posture-checked control is in its
// secure state, so the only relaxation in a test is the one the test introduces.
func hardenedConfig() *config.Config {
	return &config.Config{
		OpenFGAMode:        config.OpenFGAModeRestrict,
		CORSAllowedOrigins: []string{"https://app.example.com"},
		DebugTools:         false,
		DevMode:            false,
	}
}

func TestLogSecurityPosture(t *testing.T) {
	tests := []struct {
		name           string
		mutate         func(*config.Config)
		authConfigured bool
		wantLevel      string   // "" when no relaxed-control line is expected
		wantContains   []string // substrings expected somewhere in the output
		wantAbsent     []string // substrings that must NOT appear
	}{
		{
			name:           "all hardened",
			mutate:         func(*config.Config) {},
			authConfigured: true,
			wantLevel:      "",
			wantContains:   []string{"all checked controls are hardened"},
			wantAbsent:     []string{levelWARN, "relaxed control"},
		},
		{
			name:           "authz bypass in production posture warns",
			mutate:         func(c *config.Config) { c.OpenFGAMode = config.OpenFGAModeBypass },
			authConfigured: true,
			wantLevel:      levelWARN,
			wantContains:   []string{"SECURITY POSTURE", "authorization is BYPASSED", "OPENFGA_MODE=restrict"},
		},
		{
			name:           "missing auth warns with remediation",
			mutate:         func(*config.Config) {},
			authConfigured: false,
			wantLevel:      levelWARN,
			wantContains:   []string{"no credential configured", "TOOLMESH_AUTH_PASSWORD"},
		},
		{
			name: "dev mode reports the same facts at info, never warn",
			mutate: func(c *config.Config) {
				c.OpenFGAMode = config.OpenFGAModeBypass
				c.DevMode = true
			},
			authConfigured: false,
			wantLevel:      levelINFO,
			wantContains:   []string{"TOOLMESH_DEV=true", "authorization is BYPASSED"},
			wantAbsent:     []string{"\"level\":\"" + levelWARN + "\""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

			cfg := hardenedConfig()
			tt.mutate(cfg)
			logSecurityPosture(cfg, tt.authConfigured, logger)

			out := buf.String()
			if tt.wantLevel != "" && !strings.Contains(out, "\"level\":\""+tt.wantLevel+"\"") {
				t.Errorf("expected a %s record, got:\n%s", tt.wantLevel, out)
			}
			for _, want := range tt.wantContains {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("output unexpectedly contains %q:\n%s", absent, out)
				}
			}
		})
	}
}
