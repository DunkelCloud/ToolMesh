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

func TestAuthRolesList(t *testing.T) {
	// AuthRolesList is a raw Split — it returns the split tokens as-is.
	c := &Config{AuthRoles: "admin,user,guest"}
	roles := c.AuthRolesList()
	if len(roles) != 3 {
		t.Errorf("roles = %v", roles)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("LOG_LEVEL", testLogLevelDebug)
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != testLogLevelDebug {
		t.Errorf("log level = %q", cfg.LogLevel)
	}
}

func TestEnvInt_Invalid(t *testing.T) {
	t.Setenv("TEST_INVALID_INT", "not-a-number")
	if got := envInt("TEST_INVALID_INT", 42); got != 42 {
		t.Errorf("got %d", got)
	}
}

func TestLoad_TrustedProxies(t *testing.T) {
	cases := []struct {
		env     string
		want    []string // nil = default
		wantErr bool
	}{
		{"", nil, false},
		{"none", []string{}, false},
		{"10.1.0.0/16, 203.0.113.7", []string{"10.1.0.0/16", "203.0.113.7/32"}, false},
		{"2001:db8::1", []string{"2001:db8::1/128"}, false},
		{"10.1.2.3/16", []string{"10.1.0.0/16"}, false},
		{"not-an-ip", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("TOOLMESH_TRUSTED_PROXIES", tc.env)
			cfg, err := Load()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tc.want == nil {
				if cfg.TrustedProxies != nil {
					t.Errorf("TrustedProxies = %v, want nil (default)", cfg.TrustedProxies)
				}
				return
			}
			got := make([]string, 0, len(cfg.TrustedProxies))
			for _, p := range cfg.TrustedProxies {
				got = append(got, p.String())
			}
			if cfg.TrustedProxies == nil || strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("TrustedProxies = %v, want %v", got, tc.want)
			}
		})
	}
}
