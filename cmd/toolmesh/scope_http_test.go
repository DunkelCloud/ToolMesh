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
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// TestLoadRESTBackends_WarnsPlainHTTPFromDADL pins the warning for
// credentials over plain http chosen by the DADL: an entry without url
// whose DADL has an http base_url is warned about, an entry with its own
// url is not.
func TestLoadRESTBackends_WarnsPlainHTTPFromDADL(t *testing.T) {
	dir := t.TempDir()
	dadlSrc := strings.Replace(scopeDADL, `base_url: "https://api.example.com"`, `base_url: "http://api.example.com"`, 1)
	dadlSrc = strings.Replace(dadlSrc, "path: https://uploads.elsewhere.example/v1/files", "path: /files", 1)
	if err := os.WriteFile(filepath.Join(dir, "plain.dadl"), []byte(dadlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	yamlSrc := `
backends:
  - name: fromdadl
    transport: rest
    dadl: plain.dadl
    credentials: [other_token]
  - name: ownurl
    transport: rest
    dadl: plain.dadl
    url: https://api.example.com
    credentials: [other_token]
`
	if err := os.WriteFile(backendsPath, []byte(yamlSrc), 0o600); err != nil {
		t.Fatal(err)
	}
	buf := &capturedWriter{}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(buf, io.Discard), nil))
	named := make(map[string]backend.ToolBackend)
	loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, nil, logger, nil, nil, nil, nil)

	var warned []string
	for _, line := range strings.Split(string(buf.data), "\n") {
		if strings.Contains(line, "plain http") {
			warned = append(warned, line)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "name=fromdadl") {
		t.Errorf("plain http warnings = %q, want one for fromdadl", warned)
	}
}
