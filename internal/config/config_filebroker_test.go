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
	"strings"
	"testing"
)

const (
	envFileBroker       = "TOOLMESH_FILE_BROKER_ENABLED"
	envFileBrokerTotal  = "TOOLMESH_FILE_BROKER_MAX_TOTAL_BYTES"
	envFileBrokerUser   = "TOOLMESH_FILE_BROKER_MAX_BYTES_PER_USER"
	envDCRClientTTL     = "TOOLMESH_DCR_CLIENT_TTL"
	envDCRClientIdleTTL = "TOOLMESH_DCR_CLIENT_IDLE_TTL"
)

func clearFileBrokerAndDCREnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{envFileBroker, envFileBrokerTotal, envFileBrokerUser, envDCRClientTTL, envDCRClientIdleTTL} {
		t.Setenv(key, "")
	}
}

// Without the new variables an existing installation behaves as before: the
// broker is on and has no quota.
func TestLoad_FileBrokerAndDCRDefaults(t *testing.T) {
	clearFileBrokerAndDCREnv(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.FileBrokerEnabled || cfg.FileBrokerMaxTotalBytes != 0 || cfg.FileBrokerMaxBytesPerUser != 0 {
		t.Errorf("file broker defaults = enabled %v, total %d, per user %d; want on without quota",
			cfg.FileBrokerEnabled, cfg.FileBrokerMaxTotalBytes, cfg.FileBrokerMaxBytesPerUser)
	}
	if cfg.DCRClientTTL != 86400 || cfg.DCRClientIdleTTL != 7776000 {
		t.Errorf("DCR client lifetimes = %d/%d, want 86400/7776000", cfg.DCRClientTTL, cfg.DCRClientIdleTTL)
	}
}

func TestLoad_FileBrokerAndDCRCustom(t *testing.T) {
	clearFileBrokerAndDCREnv(t)
	t.Setenv(envFileBroker, "false")
	t.Setenv(envFileBrokerTotal, "10737418240") // 10 GiB, beyond 32 bits
	t.Setenv(envFileBrokerUser, " 1073741824 ")
	t.Setenv(envDCRClientTTL, "0")
	t.Setenv(envDCRClientIdleTTL, "604800")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FileBrokerEnabled {
		t.Error("FileBrokerEnabled = true, want false")
	}
	if cfg.FileBrokerMaxTotalBytes != 10737418240 || cfg.FileBrokerMaxBytesPerUser != 1073741824 {
		t.Errorf("quota = %d/%d, want 10737418240/1073741824", cfg.FileBrokerMaxTotalBytes, cfg.FileBrokerMaxBytesPerUser)
	}
	if cfg.DCRClientTTL != 0 || cfg.DCRClientIdleTTL != 604800 {
		t.Errorf("DCR client lifetimes = %d/%d, want 0/604800", cfg.DCRClientTTL, cfg.DCRClientIdleTTL)
	}
}

// A typo must stop the server: "off" left the broker on with a lenient parser.
func TestLoad_FileBrokerAndDCRRejectInvalidValues(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"switch is not a bool", envFileBroker, "off"},
		{"total with a unit", envFileBrokerTotal, "10GiB"},
		{"negative total", envFileBrokerTotal, "-1"},
		{"negative per user", envFileBrokerUser, "-5"},
		{"client TTL with a unit", envDCRClientTTL, "24h"},
		{"client TTL too short to sign in", envDCRClientTTL, "60"},
		{"negative client TTL", envDCRClientTTL, "-1"},
		{"idle TTL below the refresh token lifetime", envDCRClientIdleTTL, "86400"},
		{"idle TTL with a unit", envDCRClientIdleTTL, "90d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearFileBrokerAndDCREnv(t)
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
