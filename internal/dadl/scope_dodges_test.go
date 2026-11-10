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

// dodgeDADL is a minimal DADL with the auth block auth and extra YAML after
// its tools.
func dodgeDADL(auth, extra string) []byte {
	return []byte(`spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: mine
  type: rest
  base_url: "https://api.example.com"
  description: "dodges"
  auth:
` + auth + `
  tools:
    ping:
      method: GET
      path: /ping
      description: "Ping"
` + extra)
}

// TestParse_CredentialNameDodges pins that YAML forms do not carry a name
// other than letters, digits and _ past the parse-time check: anchors,
// block scalars, look-alike letters, nested login bodies and fields the
// auth type does not use. Credential defaults in other spellings and
// depths are refused as well.
func TestParse_CredentialNameDodges(t *testing.T) {
	names := map[string]string{
		"anchor":               "    type: bearer\n    credential: &c \"" + steeringName + "\"\n",
		"literal block":        "    type: bearer\n    credential: |\n      github_token\n      evil\n",
		"folded block":         "    type: bearer\n    credential: >-\n      github_token evil\n",
		"look-alike letter":    "    type: bearer\n    credential: \"github_t\u043eken\"\n",
		"list in login body":   "    type: session\n    login:\n      method: POST\n      path: /login\n      body:\n        params:\n          - user: \"credential:other-token\"\n",
		"basic username":       "    type: basic\n    username_credential: \"my-user\"\n    password_credential: \"my_pass\"\n",
		"oauth2 client id":     "    type: oauth2\n    client_id_credential: \"a b\"\n    client_secret_credential: ok\n    token_url: \"https://api.example.com/token\"\n",
		"field the type skips": "    type: bearer\n    credential: ok_token\n    password_credential: \"x]\"\n",
	}
	for name, auth := range names {
		if _, err := ParseBytes(dodgeDADL(auth, "")); err == nil || !strings.Contains(err.Error(), "not a credential name") {
			t.Errorf("%s: ParseBytes = %v, want a credential name error", name, err)
		}
	}
	defaults := map[string]string{
		"upper case": "    other:\n      method: GET\n      path: /o\n      description: \"o\"\n      params:\n        k:\n          type: string\n          in: query\n          description: \"k\"\n          default: \"CREDENTIAL:github_token\"\n",
		"deep":       "    other:\n      method: GET\n      path: /o\n      description: \"o\"\n      params:\n        k:\n          type: object\n          in: body\n          description: \"k\"\n          default: {a: [{b: \"credential:github_token\"}]}\n",
	}
	for name, extra := range defaults {
		if _, err := ParseBytes(dodgeDADL("    type: bearer\n    credential: mine_token\n", extra)); err == nil || !strings.Contains(err.Error(), "may not name a credential") {
			t.Errorf("%s: ParseBytes = %v, want the credential default refused", name, err)
		}
	}
}

// TestCredentialOwners_EdgeForms pins edge forms of the ownership: entry
// names that differ only in case or "-"/"_" share a namespace and own
// nothing in it, names are trimmed, a bare entry name is in no namespace,
// and a suggested line stays one line whatever the owner is called.
func TestCredentialOwners_EdgeForms(t *testing.T) {
	o := NewCredentialOwners("github", "GitHub", "x", "  pad  ")
	cases := []struct {
		entry, name string
		want        bool
	}{
		{ghEntry, scopeForeignCred, false},
		{"GitHub", scopeForeignCred, false},
		{"x", "x_1", true},
		{"x", "x", false},
		{"x", "xy_1", false},
		{"pad", "pad_1", true},
		{"", "pad_1", false},
	}
	for _, c := range cases {
		s, err := NewCredentialScope(c.entry, nil, nil, o)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.Allows(c.name); got != c.want {
			t.Errorf("entry %q Allows(%q) = %v, want %v", c.entry, c.name, got, c.want)
		}
	}
	e := &ScopeError{Backend: "b", Violations: []ScopeViolation{
		{Rule: RuleHostBinding, Host: "evil.example:8443"},
		{Rule: RuleCredentialNamespace, Credential: "x_y", Owners: []string{"other\"]#, bad: [1\nnext: line"}},
	}}
	for _, l := range e.FixLines() {
		if strings.Contains(l, "\n") {
			t.Errorf("fix line spans lines: %q", l)
		}
	}
}
