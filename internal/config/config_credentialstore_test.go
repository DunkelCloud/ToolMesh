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
	"reflect"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

func TestLoad_CredentialStoreCommandSettings(t *testing.T) {
	t.Setenv("CREDENTIAL_STORE", "command")
	t.Setenv("TOOLMESH_CREDENTIAL_COMMAND", "/usr/local/bin/sops -d --output-type dotenv /run/secrets/toolmesh.env")
	t.Setenv("TOOLMESH_CREDENTIAL_RELOAD_IN", "300")
	t.Setenv("TOOLMESH_CREDENTIAL_COMMAND_TIMEOUT", "10")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := map[string]string{
		credentials.CommandConfigCommand:  "/usr/local/bin/sops -d --output-type dotenv /run/secrets/toolmesh.env",
		credentials.CommandConfigReloadIn: "300",
		credentials.CommandConfigTimeout:  "10",
	}
	if got := cfg.CredentialStoreConfig(); !reflect.DeepEqual(got, want) {
		t.Errorf("CredentialStoreConfig() = %q, want %q", got, want)
	}
	opts, err := credentials.ParseCommandStoreConfig(cfg.CredentialStoreConfig())
	if err != nil {
		t.Fatalf("the command store rejects the settings: %v", err)
	}
	if opts.Interval.Seconds() != 300 || opts.Timeout.Seconds() != 10 {
		t.Errorf("parsed interval %s, timeout %s", opts.Interval, opts.Timeout)
	}
}

func TestApplySecrets(t *testing.T) {
	t.Setenv(envAuthPassword, "env-password")
	t.Setenv(envAPIKey, "env-api-key")
	t.Setenv(envRedisURL, "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	store := map[string]string{ //nolint:gosec // test fixtures, not credentials
		envAPIKey:       "store-api-key",
		envRedisURL:     "redis://:store-pass@keydb:6379/0",
		envAuthPassword: "", // empty: the environment value stays
	}
	applied := cfg.ApplySecrets(func(key string) (string, bool) {
		v, ok := store[key]
		return v, ok
	})

	if want := []string{envAPIKey, envRedisURL}; !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %q, want %q", applied, want)
	}
	if cfg.APIKey != "store-api-key" {
		t.Errorf("APIKey = %q, want the store's value", cfg.APIKey)
	}
	if cfg.RedisURL != "redis://:store-pass@keydb:6379/0" {
		t.Errorf("RedisURL = %q, want the store's value", cfg.RedisURL)
	}
	if cfg.AuthPassword != "env-password" {
		t.Errorf("AuthPassword = %q, an empty store value must not override", cfg.AuthPassword)
	}
}

func TestApplySecrets_NothingInStore(t *testing.T) {
	t.Setenv(envRedisURL, "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	before := *cfg
	applied := cfg.ApplySecrets(func(string) (string, bool) { return "", false })
	if len(applied) != 0 {
		t.Errorf("applied = %q, want none", applied)
	}
	if cfg.RedisURL != before.RedisURL || cfg.RedisURL != "redis://localhost:6379/0" {
		t.Errorf("RedisURL changed to %q", cfg.RedisURL)
	}
}
