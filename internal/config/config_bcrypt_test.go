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
	"runtime"
	"strings"
	"testing"
)

const envBcryptMaxConcurrent = "TOOLMESH_BCRYPT_MAX_CONCURRENT"

func TestDefaultBcryptMaxConcurrent(t *testing.T) {
	// Half of the CPUs the process may use, and never less than one.
	for procs, want := range map[int]int{1: 1, 2: 1, 3: 1, 4: 2, 8: 4, 9: 4} {
		previous := runtime.GOMAXPROCS(procs)
		got := DefaultBcryptMaxConcurrent()
		runtime.GOMAXPROCS(previous)
		if got != want {
			t.Errorf("with %d CPUs: DefaultBcryptMaxConcurrent() = %d, want %d", procs, got, want)
		}
	}
}

func TestLoad_BcryptMaxConcurrent(t *testing.T) {
	t.Setenv(envBcryptMaxConcurrent, "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := DefaultBcryptMaxConcurrent(); cfg.BcryptMaxConcurrent != want {
		t.Errorf("default = %d, want %d", cfg.BcryptMaxConcurrent, want)
	}

	t.Setenv(envBcryptMaxConcurrent, " 7 ")
	if cfg, err = Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BcryptMaxConcurrent != 7 {
		t.Errorf("configured = %d, want 7", cfg.BcryptMaxConcurrent)
	}
}

// The bound cannot be switched off and a typo must not silently become the
// default: both stop the server.
func TestLoad_BcryptMaxConcurrentRejectsInvalidValues(t *testing.T) {
	for name, value := range map[string]string{
		"zero":         "0",
		"negative":     "-2",
		"not a number": "two",
		"with a unit":  "2x",
		"a fraction":   "1.5",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(envBcryptMaxConcurrent, value)
			_, err := Load()
			if err == nil {
				t.Fatalf("%s=%q was accepted", envBcryptMaxConcurrent, value)
			}
			if !strings.Contains(err.Error(), envBcryptMaxConcurrent) {
				t.Errorf("error %q does not name the variable", err)
			}
		})
	}
}

func TestIssuerIsPlaceholder(t *testing.T) {
	for issuer, want := range map[string]bool{
		"https://toolmesh.io/":           true,
		"https://toolmesh.io":            true,
		"https://TOOLMESH.io/":           true,
		"https://toolmesh.example.com/":  false,
		"https://demo.toolmesh.io/":      false,
		"http://localhost:8123/":         false,
		"https://toolmesh.io/somewhere/": false,
	} {
		if got := (&Config{Issuer: issuer}).IssuerIsPlaceholder(); got != want {
			t.Errorf("IssuerIsPlaceholder(%q) = %v, want %v", issuer, got, want)
		}
	}

	// Unset, the variable falls back to the placeholder.
	t.Setenv("TOOLMESH_ISSUER", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.IssuerIsPlaceholder() {
		t.Errorf("default issuer %q is not recognized as the placeholder", cfg.Issuer)
	}
}
