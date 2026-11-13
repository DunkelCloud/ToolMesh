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

package unit_test

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/unit"
)

// TestLoadUnit_RefusesUserCredentials pins that a unit whose backend asks
// for credentials of users is not loaded. Units cannot honor the request,
// and loading the backend anyway would run it with one credential for all
// callers. The key without a name under it is refused as well: it decodes
// to nothing and would pass for no key at all.
func TestLoadUnit_RefusesUserCredentials(t *testing.T) {
	const dadlSrc = `spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: itemsapi
  type: rest
  base_url: "https://api.example.com"
  auth:
    type: bearer
    credential: itemsapi_token
  tools:
    list_items:
      method: GET
      path: /items
`
	const js = `function describe() { return { tools: [{ name: "fetch", description: "Fetch", params: {} }] }; }
async function fetch() { return await api.itemsapi.list_items({}); }
`
	for name, declaration := range map[string]string{ //nolint:gosec // G101: the cases name a credential, they hold none
		"a named credential": "    user_credentials:\n      - itemsapi_token\n",
		"the key alone":      "    user_credentials:\n",
		"an empty item":      "    user_credentials:\n      -\n",
	} {
		dir := t.TempDir()
		files := map[string]string{
			"items.dadl": dadlSrc,
			"items.js":   js,
			"unit.yaml": "unit: items\nimplementation: ./items.js\nbackends:\n" +
				"  - name: itemsapi\n    transport: rest\n    dadl: ./items.dadl\n" + declaration,
		}
		for file, content := range files {
			if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		_, err := unit.LoadUnit(context.Background(), dir, "", credentials.NewEmbeddedStore(), dadl.NewCredentialOwners(unit.EntryNames(dir)...), nil, logger)
		if err == nil || !strings.Contains(err.Error(), "user_credentials") {
			t.Errorf("%s: err = %v, want the unit refused for its user_credentials", name, err)
		}
	}
}
