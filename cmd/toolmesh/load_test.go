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
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

const testDADLContent = `spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: testapi
  type: rest
  base_url: "https://example.com"
  description: "Test API"
  tools:
    get_ping:
      method: GET
      path: /ping
      description: "Ping the API"
`

func TestLoadRESTBackends_HappyPath(t *testing.T) {
	dir := t.TempDir()

	// Write a DADL file.
	dadlPath := filepath.Join(dir, "api.dadl")
	if err := os.WriteFile(dadlPath, []byte(testDADLContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Write a backends.yaml pointing at it.
	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: testapi
    transport: rest
    dadl: api.dadl
    url: "https://example.com"
    options:
      timeout: 5s
      blob_ttl: 30m
      streaming_timeout: 60s
`)
	if err := os.WriteFile(backendsPath, yaml, 0o600); err != nil {
		t.Fatal(err)
	}

	composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{})
	creds := credentials.NewEmbeddedStore()

	// Capture logs to see why the backend might not load.
	buf := &capturedWriter{}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(buf), nil))
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, creds, nil, logger, nil, nil, nil)
	for k, v := range named {
		composite.AddNamed(k, v)
	}

	tools, err := composite.ListTools(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) == 0 {
		t.Logf("logs: %s", buf.data)
		t.Error("expected tools from loaded DADL")
	}
}

type capturedWriter struct{ data []byte }

func (c *capturedWriter) Write(p []byte) (int, error) {
	c.data = append(c.data, p...)
	return len(p), nil
}

func TestLoadRESTBackends_InvalidDurationOptions(t *testing.T) {
	dir := t.TempDir()
	dadlPath := filepath.Join(dir, "api.dadl")
	_ = os.WriteFile(dadlPath, []byte(testDADLContent), 0o600)

	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := []byte(`
backends:
  - name: testapi
    transport: rest
    dadl: api.dadl
    options:
      timeout: "not-a-duration"
      blob_ttl: "also-bad"
      streaming_timeout: "nope"
`)
	_ = os.WriteFile(backendsPath, yaml, 0o600)

	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, quietLogger(), nil, nil, nil)
	// Should still load without panic.
}

func TestLoadRESTBackends_AbsoluteDADLPath(t *testing.T) {
	dir := t.TempDir()
	dadlPath := filepath.Join(dir, "api.dadl")
	_ = os.WriteFile(dadlPath, []byte(testDADLContent), 0o600)

	backendsPath := filepath.Join(dir, "backends.yaml")
	// Absolute path bypasses TOOLMESH_DADL_DIR joining.
	yaml := []byte("backends:\n  - name: testapi\n    transport: rest\n    dadl: " + dadlPath + "\n")
	_ = os.WriteFile(backendsPath, yaml, 0o600)

	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, "/some/other/dir", nil, credentials.NewEmbeddedStore(), nil, quietLogger(), nil, nil, nil)
}
