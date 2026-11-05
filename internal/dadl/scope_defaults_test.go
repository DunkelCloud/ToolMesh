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

package dadl

import (
	"strings"
	"testing"
)

// defaultsDADL is a minimal DADL with one tool parameter and one composite
// parameter whose defaults are the YAML values toolDefault and compDefault.
func defaultsDADL(toolDefault, compDefault string) []byte {
	return []byte(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: defaults
  type: rest
  base_url: https://api.example.com
  auth:
    type: bearer
    credential: defaults_token
  tools:
    get_item:
      method: GET
      path: /items/{project}
      params:
        project:
          type: string
          in: path
          default: ` + toolDefault + `
  composites:
    wrap:
      description: "Wrap"
      params:
        project:
          type: string
          default: ` + compDefault + `
      code: "return await api.get_item({project: params.project});"
`)
}

// plainDefault is a parameter default that names no credential.
const plainDefault = `"p2"`

// TestParse_CredentialDefaultsRefused pins that a parameter default never
// names a credential: the runtime sends a default as written, and a later
// resolution of such a default would bypass the credential binding.
func TestParse_CredentialDefaultsRefused(t *testing.T) {
	cases := []struct {
		name, tool, comp string
		ok               bool
	}{
		{"plain defaults", `"p1"`, plainDefault, true},
		{"tool default", `"credential:google_cloud_project_id"`, plainDefault, false},
		{"other case and spaces", `" Credential:x"`, plainDefault, false},
		{"nested", `{a: ["credential:x"]}`, plainDefault, false},
		{"composite default", `"p1"`, `"credential:x"`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseBytes(defaultsDADL(c.tool, c.comp))
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "may not name a credential")) {
				t.Fatalf("ParseBytes = %v, want the credential default refused", err)
			}
		})
	}
}
