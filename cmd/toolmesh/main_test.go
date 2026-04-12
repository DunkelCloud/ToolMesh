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
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestBackendsYAMLUnmarshal(t *testing.T) {
	yaml := []byte(`
backends:
  - name: test
    transport: rest
    dadl: test.yaml
    url: https://api.example.com
    options:
      timeout: 30s
`)
	var cfg backend.BackendConfig
	if err := backendsYAMLUnmarshal(yaml, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(cfg.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(cfg.Backends))
	}
	b := cfg.Backends[0]
	if b.Name != "test" || b.Transport != "rest" || b.DADL != "test.yaml" {
		t.Errorf("unexpected backend: %+v", b)
	}
}

func TestBackendsYAMLUnmarshal_Invalid(t *testing.T) {
	var cfg backend.BackendConfig
	if err := backendsYAMLUnmarshal([]byte("not: valid: yaml: : :"), &cfg); err == nil {
		t.Error("expected unmarshal error")
	}
}

func TestBackendLogger_NoDebug(t *testing.T) {
	global := quietLogger()
	stdoutHandler := slog.NewTextHandler(io.Discard, nil)
	got := backendLogger("github", global, stdoutHandler, nil, map[string]bool{})
	if got != global {
		t.Error("expected global logger fallback")
	}
}

func TestBackendLogger_DebugEnabled(t *testing.T) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "debug.log")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpFile.Close()

	global := quietLogger()
	stdoutHandler := slog.NewTextHandler(io.Discard, nil)
	got := backendLogger("github", global, stdoutHandler, tmpFile, map[string]bool{"github": true})
	if got == global {
		t.Error("expected custom logger when debug enabled for backend")
	}
}

func TestLoadRESTBackends_MissingFile(t *testing.T) {
	// Non-existent file should simply return without error.
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, filepath.Join(t.TempDir(), "does-not-exist.yaml"), "", nil, nil, nil, quietLogger(), nil, nil, nil)
	if len(named) != 0 {
		t.Errorf("expected 0 backends, got %d", len(named))
	}
}

func TestLoadRESTBackends_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backends.yaml")
	if err := os.WriteFile(path, []byte(":::not valid: : : yaml"), 0o600); err != nil {
		t.Fatal(err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, path, dir, nil, nil, nil, quietLogger(), nil, nil, nil)
	// Should log error but not panic.
}

func TestLoadRESTBackends_MissingDADLPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: test
    transport: rest
`)
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, path, dir, nil, nil, nil, quietLogger(), nil, nil, nil)
}

func TestLoadRESTBackends_NonRestBackendSkipped(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: other
    transport: mcp
    dadl: x.yaml
`)
	if err := os.WriteFile(path, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, path, dir, nil, nil, nil, quietLogger(), nil, nil, nil)
	if len(named) != 0 {
		t.Errorf("expected 0 backends for non-rest transport, got %d", len(named))
	}
}

func TestLoadRESTBackends_InvalidDADLFile(t *testing.T) {
	dir := t.TempDir()
	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: test
    transport: rest
    dadl: missing.yaml
`)
	if err := os.WriteFile(backendsPath, yaml, 0o600); err != nil {
		t.Fatal(err)
	}
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, nil, nil, quietLogger(), nil, nil, nil)
}
