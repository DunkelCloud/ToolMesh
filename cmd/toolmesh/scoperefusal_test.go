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
	"errors"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// refusalAttr returns the value of the attribute key in attrs, as the lines
// it holds.
func refusalAttr(t *testing.T, attrs []any, key string) []string {
	t.Helper()
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] != key {
			continue
		}
		switch v := attrs[i+1].(type) {
		case []string:
			return v
		case string:
			return []string{v}
		}
		t.Fatalf("attribute %q holds a %T", key, attrs[i+1])
	}
	return nil
}

// TestScopeRefusalAttrs pins what the "backend refused" log line offers for
// copying. A second backend that uses the DADL of another service reads
// that service's credential by default, and a tool path can name any host
// and port: neither the line that lists the other entry's credential nor
// a line that allows a destination the DADL names may stand among the
// lines to add. They come apart, with a warning, and the line to add for
// the credential gives the backend one of its own.
func TestScopeRefusalAttrs(t *testing.T) {
	const entry, other = "second", "first"
	spec := &dadl.Spec{Backend: dadl.BackendDef{
		Name:    entry,
		BaseURL: "https://api.second.example",
		Auth:    dadl.AuthConfig{Type: "bearer", Credential: "first_api_key"},
		Tools: map[string]dadl.ToolDef{
			"ping":   {Method: "GET", Path: "/ping"},
			"port":   {Method: "GET", Path: "https://api.second.example:8443/ping"},
			"upload": {Method: "POST", Path: "https://uploads.elsewhere.example/v1/files"},
		},
	}}
	creds, err := dadl.NewCredentialScope(entry, nil, nil, dadl.NewCredentialOwners(entry, other))
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := dadl.NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	var scopeErr *dadl.ScopeError
	if !errors.As(dadl.CheckScope(spec, creds, hosts), &scopeErr) {
		t.Fatal("the DADL was not refused")
	}

	attrs := scopeRefusalAttrs(entry, "first.dadl", scopeErr)
	fix := strings.Join(refusalAttr(t, attrs, logKeyFixLines), "\n")
	if fix != "env: {CREDENTIAL_FIRST_API_KEY: CREDENTIAL_SECOND_FIRST_API_KEY}" {
		t.Errorf("%s = %q, want the line that gives the backend a credential of its own, alone", logKeyFixLines, fix)
	}

	caution := strings.Join(refusalAttr(t, attrs, logKeyCautionLines), "\n")
	for _, want := range []string{
		"credentials: [first_api_key]", `entry "first"`,
		"allowed_hosts: ['api.second.example:8443', uploads.elsewhere.example]", "further destinations",
	} {
		if !strings.Contains(caution, want) {
			t.Errorf("%s = %q, lacks %q", logKeyCautionLines, caution, want)
		}
	}
	if warning := refusalAttr(t, attrs, logKeyCaution); len(warning) != 1 || !strings.Contains(warning[0], "only after checking") {
		t.Errorf("%s = %q, want the warning", logKeyCaution, warning)
	}

	// A violation only the own credential resolves gets no warning
	// attribute for lines it does not have.
	credOnly := &dadl.ScopeError{Backend: entry, Violations: []dadl.ScopeViolation{
		{Rule: dadl.RuleHostBinding, What: "base_url: it uses http while base_url uses https"},
	}}
	attrs = scopeRefusalAttrs(entry, "first.dadl", credOnly)
	for _, key := range []string{logKeyFixLines, logKeyCaution, logKeyCautionLines} {
		if got := refusalAttr(t, attrs, key); got != nil {
			t.Errorf("a violation without any line has %s = %q", key, got)
		}
	}
}
