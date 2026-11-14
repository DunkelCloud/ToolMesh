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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// TestLoadRESTBackends_OwnerFromOtherTransports pins that every named entry
// takes part in the division of the credential names: a REST entry "my"
// may not read my_other_token when an MCP entry "my-other" is configured,
// and the units directory adds its unit and sub-backend names.
func TestLoadRESTBackends_OwnerFromOtherTransports(t *testing.T) {
	dir := t.TempDir()
	dadlSrc := strings.Replace(scopeDADL, "credential: other_token", "credential: my_other_token", 1)
	dadlSrc = strings.Replace(dadlSrc, "path: https://uploads.elsewhere.example/v1/files", "path: /files", 1)
	if err := os.WriteFile(filepath.Join(dir, "scope.dadl"), []byte(dadlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	yamlSrc := `
backends:
  - name: my
    transport: rest
    dadl: scope.dadl
  - name: my-other
    transport: http
    url: http://127.0.0.1:1/mcp
`
	if err := os.WriteFile(backendsPath, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	named := make(map[string]backend.ToolBackend)
	_, refused := loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, quietLogger(), nil, nil, nil, nil)
	if _, ok := named["my"]; ok || !slices.Contains(refused, "my") {
		t.Errorf("entry my read the namespace of the MCP entry my-other; refused = %v", refused)
	}

	unitsDir := filepath.Join(dir, "units")
	unitDir := filepath.Join(unitsDir, "u1")
	if err := os.MkdirAll(unitDir, 0o750); err != nil {
		t.Fatal(err)
	}
	unitYAML := "unit: my-unit\nimplementation: impl.js\nbackends:\n  - name: my-sub\n    transport: rest\n    dadl: x.dadl\n"
	if err := os.WriteFile(filepath.Join(unitDir, "unit.yaml"), []byte(unitYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	names := credentialOwnerNames(backendsPath, unitsDir)
	for _, want := range []string{"my", "my-other", "my-unit", "my-sub"} {
		if !slices.Contains(names, want) {
			t.Errorf("owner names %v lack %q", names, want)
		}
	}
}
