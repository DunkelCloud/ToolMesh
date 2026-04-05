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

func TestAuthRolesList(t *testing.T) {
	// AuthRolesList is a raw Split — it returns the split tokens as-is.
	c := &Config{AuthRoles: "admin,user,guest"}
	roles := c.AuthRolesList()
	if len(roles) != 3 {
		t.Errorf("roles = %v", roles)
	}
}

func TestLoadConfig(t *testing.T) {
	t.Setenv("TOOLMESH_LOG_LEVEL", "debug")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("log level = %q", cfg.LogLevel)
	}
}

func TestEnvInt_Invalid(t *testing.T) {
	t.Setenv("TEST_INVALID_INT", "not-a-number")
	if got := envInt("TEST_INVALID_INT", 42); got != 42 {
		t.Errorf("got %d", got)
	}
}
