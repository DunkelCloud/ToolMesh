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
	"errors"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// steeringName is a credential name that, pasted into a backends.yaml line
// as text, would add an allowed_hosts entry of its own.
const steeringName = "x], allowed_hosts: [evil.example"

// namesDADL is a minimal DADL whose auth block is auth.
func namesDADL(auth string) []byte {
	return []byte(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: names
  type: rest
  base_url: https://api.example.com
  auth:
` + auth + `
  tools:
    ping:
      method: GET
      path: /ping
`)
}

// TestParse_CredentialNames pins that a DADL may only name credentials with
// letters, digits and "_", in every credential field and in a session login
// body, whatever the auth type.
func TestParse_CredentialNames(t *testing.T) {
	cases := []struct {
		name string
		auth string
		ok   bool
	}{
		{"plain name", "    type: bearer\n    credential: my_token_2", true},
		{"no-auth placeholder", "    type: apikey\n    credential: none\n    inject_into: query\n    query_param: key", true},
		{"hyphen", "    type: bearer\n    credential: my-token", false},
		{"steering text", "    type: bearer\n    credential: \"" + steeringName + "\"", false},
		{"space", "    type: bearer\n    credential: \"my token\"", false},
		{"field of another type", "    type: bearer\n    credential: tok\n    password_credential: \"a/b\"", false},
		{"login body", "    type: session\n    login:\n      method: POST\n      path: /login\n      body:\n        user: \"credential:a.b\"", false},
		{"empty login ref", "    type: session\n    login:\n      method: POST\n      path: /login\n      body:\n        nested: [\"credential:\"]", false},
		{"login body ok", "    type: session\n    login:\n      method: POST\n      path: /login\n      body:\n        user: \"credential:names_user\"", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseBytes(namesDADL(c.auth))
			if c.ok && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "not a credential name")) {
				t.Fatalf("ParseBytes = %v, want a credential name error", err)
			}
		})
	}
}

// TestScopeError_FixLinesFromDADLText pins that a credential name from a
// spec built in code (Parse refuses it) never shapes the suggested
// backends.yaml line: such a violation has no fix line, and the error tells
// the operator that only a change to the DADL helps.
func TestScopeError_FixLinesFromDADLText(t *testing.T) {
	spec := &Spec{Backend: BackendDef{Name: "mine", BaseURL: "https://api.example.com",
		Auth: AuthConfig{Type: authTypeBearer, Credential: steeringName}}}
	hosts, err := NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckScope(spec, NewCredentialScope("mine", nil, nil), hosts)
	var se *ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("CheckScope = %v, want a *ScopeError", err)
	}
	if lines := se.FixLines(); len(lines) != 0 {
		t.Errorf("fix lines built from DADL text: %q", lines)
	}
	if !strings.Contains(err.Error(), "only a change to the DADL") {
		t.Errorf("error does not say that only the DADL can fix it: %v", err)
	}
}

// TestYAMLFlowLine pins that the suggested lines are YAML that reads back as
// exactly the items they were built from, also for items YAML would read
// differently unquoted.
func TestYAMLFlowLine(t *testing.T) {
	items := []string{"true", "123", "null", "[::1]:8443", "*.example.com", steeringName, "a, b"}
	line := yamlFlowLine("allowed_hosts", items)
	var got struct {
		AllowedHosts []string `yaml:"allowed_hosts"`
	}
	if err := yaml.Unmarshal([]byte(line), &got); err != nil {
		t.Fatalf("line %q is not YAML: %v", line, err)
	}
	if strings.Join(got.AllowedHosts, "|") != strings.Join(items, "|") {
		t.Errorf("line %q reads back as %q", line, got.AllowedHosts)
	}
	var keys map[string]any
	if err := yaml.Unmarshal([]byte(line), &keys); err != nil || len(keys) != 1 {
		t.Errorf("line %q has keys %v (%v)", line, keys, err)
	}
}
