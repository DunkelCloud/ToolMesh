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
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// scopeDADL reads the credential "other_token", outside the namespace of an
// entry named "mine", and has a tool on a foreign host.
const scopeDADL = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: whatever
  type: rest
  base_url: "https://api.example.com"
  description: "Scope test"
  auth:
    type: bearer
    credential: other_token
  tools:
    get_ping:
      method: GET
      path: /ping
      description: "Ping"
    upload:
      method: POST
      path: https://uploads.elsewhere.example/v1/files
      description: "Upload"
`

// TestLoadRESTBackends_CredentialAndHostBinding pins the load-time binding:
// a backend whose DADL reaches outside its entry's credentials or hosts is
// refused with the backends.yaml lines that allow it, an entry without a name
// is refused, and the other backends load.
func TestLoadRESTBackends_CredentialAndHostBinding(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{"scope.dadl": scopeDADL, "api.dadl": testDADLContent} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	backendsPath := filepath.Join(dir, "backends.yaml")
	yaml := `
backends:
  - name: mine
    transport: rest
    dadl: scope.dadl
  - name: allowed
    transport: rest
    dadl: scope.dadl
    credentials: [other_token]
    allowed_hosts: [uploads.elsewhere.example]
  - transport: rest
    dadl: api.dadl
  - name: testapi
    transport: rest
    dadl: api.dadl
`
	if err := os.WriteFile(backendsPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	buf := &capturedWriter{}
	logger := slog.New(slog.NewTextHandler(io.MultiWriter(buf, io.Discard), nil))
	named := make(map[string]backend.ToolBackend)
	_, refused := loadRESTBackendsInto(named, backendsPath, dir, nil, credentials.NewEmbeddedStore(), nil, logger, nil, nil, nil)

	if _, ok := named["mine"]; ok {
		t.Error("backend reaching outside its binding was loaded")
	}
	for _, want := range []string{"allowed", "testapi"} {
		if _, ok := named[want]; !ok {
			t.Errorf("backend %q was not loaded; logs:\n%s", want, buf.data)
		}
	}
	if !slices.Contains(refused, "mine") || len(refused) != 2 {
		t.Errorf("refused = %v, want mine and the unnamed entry", refused)
	}
	logs := string(buf.data)
	for _, want := range []string{"backend refused", "credentials: [other_token]", "allowed_hosts: [uploads.elsewhere.example]", "entry has no name"} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
}
