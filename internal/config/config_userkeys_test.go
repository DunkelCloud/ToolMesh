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
)

// TestLoad_UserCredentialKeys pins that both keys of the user credential
// store, the one in use and the one to change to, come from the environment
// and, where a credential store holds them, from that store ahead of the
// environment.
func TestLoad_UserCredentialKeys(t *testing.T) {
	t.Setenv(envUserCredentialsKey, "key-from-env")
	t.Setenv(envUserCredentialsKeyNext, "next-from-env")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UserCredentialsKey != "key-from-env" || cfg.UserCredentialsKeyNext != "next-from-env" {
		t.Errorf("from the environment: key %q, next %q", cfg.UserCredentialsKey, cfg.UserCredentialsKeyNext)
	}

	store := map[string]string{ //nolint:gosec // test fixtures, not credentials
		envUserCredentialsKey:     "key-from-store",
		envUserCredentialsKeyNext: "next-from-store",
	}
	applied := cfg.ApplySecrets(func(name string) (string, bool) {
		v, ok := store[name]
		return v, ok
	})
	if want := []string{envUserCredentialsKey, envUserCredentialsKeyNext}; !reflect.DeepEqual(applied, want) {
		t.Errorf("applied = %q, want %q", applied, want)
	}
	if cfg.UserCredentialsKey != "key-from-store" || cfg.UserCredentialsKeyNext != "next-from-store" {
		t.Errorf("from the store: key %q, next %q", cfg.UserCredentialsKey, cfg.UserCredentialsKeyNext)
	}

	// Unset, both are empty: the store is off and no change is asked for.
	t.Setenv(envUserCredentialsKey, "")
	t.Setenv(envUserCredentialsKeyNext, "")
	if cfg, err = Load(); err != nil || cfg.UserCredentialsKey != "" || cfg.UserCredentialsKeyNext != "" {
		t.Errorf("unset: key %q, next %q, %v", cfg.UserCredentialsKey, cfg.UserCredentialsKeyNext, err)
	}
}
