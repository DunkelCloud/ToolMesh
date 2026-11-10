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

const (
	gheToken = "github_enterprise_token" //nolint:gosec // credential name, not a credential
	ghEntry  = "github"
	gheEntry = "github-enterprise"
)

// TestCredentialOwners_LongestPrefix pins that a credential name belongs to
// the entry whose namespace is its longest prefix: an entry does not read
// the credentials of an entry whose name extends its own, a one-letter
// entry does not read every name starting with that letter, and a name in
// a namespace shared by two spellings, or in none, needs a listing.
func TestCredentialOwners_LongestPrefix(t *testing.T) {
	owners := NewCredentialOwners(ghEntry, gheEntry, "s", "shelly-cloud", "my-api", "my_api", "")
	scope := func(entry string, allowed ...string) *CredentialScope {
		t.Helper()
		s, err := NewCredentialScope(entry, allowed, nil, owners)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		entry, name string
		want        bool
	}{
		{ghEntry, scopeForeignCred, true},
		{ghEntry, gheToken, false},
		{gheEntry, gheToken, true},
		{gheEntry, scopeForeignCred, false},
		{"s", "s_token", true},
		{"s", "shelly_cloud_auth_key", false},
		{"s", "shelly_token", false}, // SHELLY_TOKEN is not in S_, and no entry "shelly" exists
		{"shelly-cloud", "shelly_cloud_auth_key", true},
		{"my-api", "my_api_token", false},
		{"my_api", "my_api_token", false},
		{ghEntry, "orphan_token", false},
	}
	for _, c := range cases {
		if got := scope(c.entry).Allows(c.name); got != c.want {
			t.Errorf("entry %q Allows(%q) = %v, want %v", c.entry, c.name, got, c.want)
		}
	}
	if !scope(ghEntry, gheToken).Allows(gheToken) ||
		!scope("my-api", "my_api_token").Allows("my_api_token") ||
		!scope(ghEntry, "orphan_token").Allows("orphan_token") {
		t.Error("a listed name must be allowed whoever owns it")
	}
	if s, err := NewCredentialScope(ghEntry, nil, nil, nil); err != nil || s.Allows("github_token") {
		t.Errorf("without owners an entry must own no names (err %v)", err)
	}
}

// TestCredentialOwners_Set pins that the division follows the
// configuration: an entry added later takes its names away from an entry
// with a shorter namespace, also in a scope built before.
func TestCredentialOwners_Set(t *testing.T) {
	owners := NewCredentialOwners(ghEntry)
	s, err := NewCredentialScope(ghEntry, nil, nil, owners)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows(gheToken) {
		t.Fatal("without an entry github-enterprise the name belongs to github")
	}
	owners.Set([]string{ghEntry, gheEntry})
	if s.Allows(gheToken) {
		t.Error("the added entry github-enterprise did not take its names away")
	}
	if !s.Allows("github_token") {
		t.Error("github lost its own names")
	}
}

// TestCheckScope_NamesOwner pins that the error and the suggested line name
// the entry a refused credential belongs to, and that the line stays YAML.
func TestCheckScope_NamesOwner(t *testing.T) {
	creds, err := NewCredentialScope(ghEntry, nil, nil, NewCredentialOwners(ghEntry, gheEntry))
	if err != nil {
		t.Fatal(err)
	}
	spec := &Spec{Backend: BackendDef{Name: ghEntry, BaseURL: "https://api.github.com",
		Auth: AuthConfig{Type: authTypeBearer, Credential: gheToken}}}
	hosts, err := NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = CheckScope(spec, creds, hosts)
	var se *ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("CheckScope = %v, want a *ScopeError", err)
	}
	if !strings.Contains(err.Error(), `namespace of entry "github-enterprise"`) {
		t.Errorf("error does not name the owner: %v", err)
	}
	lines := se.FixLines()
	if len(lines) != 1 || !strings.Contains(lines[0], `entry "github-enterprise"`) {
		t.Fatalf("fix lines %q do not name the owner", lines)
	}
	var got struct {
		Credentials []string `yaml:"credentials"`
	}
	if err := yaml.Unmarshal([]byte(lines[0]), &got); err != nil || len(got.Credentials) != 1 || got.Credentials[0] != gheToken {
		t.Errorf("line %q reads back as %v (%v)", lines[0], got.Credentials, err)
	}
}
