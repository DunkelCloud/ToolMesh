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
	envLoginPerUserIP = "TOOLMESH_LOGIN_MAX_FAILURES_PER_USER_IP"
	envLoginPerUser   = "TOOLMESH_LOGIN_MAX_FAILURES_PER_USER"
	envLoginPerIP     = "TOOLMESH_LOGIN_MAX_FAILURES_PER_IP"
	envLoginWindow    = "TOOLMESH_LOGIN_FAILURE_WINDOW"
)

func TestLoad_LoginThrottleDefaults(t *testing.T) {
	for _, key := range []string{envLoginPerUserIP, envLoginPerUser, envLoginPerIP, envLoginWindow} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LoginMaxFailuresPerUserIP != 5 || cfg.LoginMaxFailuresPerUser != 20 || cfg.LoginMaxFailuresPerIP != 50 || cfg.LoginFailureWindow != 900 {
		t.Errorf("defaults = %d/%d/%d per %ds, want 5/20/50 per 900s",
			cfg.LoginMaxFailuresPerUserIP, cfg.LoginMaxFailuresPerUser, cfg.LoginMaxFailuresPerIP, cfg.LoginFailureWindow)
	}
	if off := cfg.LoginThrottleDisabled(); len(off) != 0 {
		t.Errorf("LoginThrottleDisabled() = %v, want none with the defaults", off)
	}
}

func TestLoad_LoginThrottleCustomAndDisabled(t *testing.T) {
	t.Setenv(envLoginPerUserIP, "3")
	t.Setenv(envLoginPerUser, "0")
	t.Setenv(envLoginPerIP, " 40 ")
	t.Setenv(envLoginWindow, "60")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LoginMaxFailuresPerUserIP != 3 || cfg.LoginMaxFailuresPerUser != 0 || cfg.LoginMaxFailuresPerIP != 40 || cfg.LoginFailureWindow != 60 {
		t.Errorf("got %d/%d/%d per %ds, want 3/0/40 per 60s",
			cfg.LoginMaxFailuresPerUserIP, cfg.LoginMaxFailuresPerUser, cfg.LoginMaxFailuresPerIP, cfg.LoginFailureWindow)
	}
	off := cfg.LoginThrottleDisabled()
	if len(off) != 1 || off[0] != envLoginPerUser {
		t.Errorf("LoginThrottleDisabled() = %v, want [%s]", off, envLoginPerUser)
	}
}

// A typo in a security limit must stop the server, not fall back to a
// default the operator did not ask for.
func TestLoad_LoginThrottleRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name, key, value string
	}{
		{"limit is not a number", envLoginPerUserIP, "five"},
		{"limit with a unit", envLoginPerUser, "3x"},
		{"negative limit", envLoginPerIP, "-1"},
		{"window with a unit", envLoginWindow, "15m"},
		{"zero window", envLoginWindow, "0"},
		{"negative window", envLoginWindow, "-900"},
		{"window beyond 30 days", envLoginWindow, "9999999999"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.key, tt.value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.key) {
				t.Errorf("error %q does not name the variable %s", err, tt.key)
			}
		})
	}
}

// With every limit switched off the window is irrelevant and must not block
// startup.
func TestLoad_LoginThrottleWindowIgnoredWhenAllLimitsDisabled(t *testing.T) {
	t.Setenv(envLoginPerUserIP, "0")
	t.Setenv(envLoginPerUser, "0")
	t.Setenv(envLoginPerIP, "0")
	t.Setenv(envLoginWindow, "0")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(cfg.LoginThrottleDisabled()); got != 3 {
		t.Errorf("LoginThrottleDisabled() lists %d limits, want 3", got)
	}
}
