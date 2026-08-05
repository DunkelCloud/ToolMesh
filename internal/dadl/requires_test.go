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

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in     string
		want   [3]int
		wantOK bool
	}{
		{"0.9.0", [3]int{0, 9, 0}, true},
		{"1.2", [3]int{1, 2, 0}, true},
		{"v1.2.3", [3]int{1, 2, 3}, true},
		{" 1.0.0 ", [3]int{1, 0, 0}, true},
		{testVersionDev, [3]int{}, false},
		{"1.0.0-rc1", [3]int{}, false},
		{"1", [3]int{}, false},
		{"", [3]int{}, false},
	}
	for _, tt := range tests {
		got, ok := parseVersion(tt.in)
		if ok != tt.wantOK {
			t.Errorf("parseVersion(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("parseVersion(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestVersionRange(t *testing.T) {
	tests := []struct {
		name      string
		rangeExpr string
		current   string
		want      bool
		wantErr   string
	}{
		{name: "gte satisfied exact", rangeExpr: testRangeGte090, current: "0.9.0", want: true},
		{name: "gte satisfied above", rangeExpr: testRangeGte090, current: "1.4.2", want: true},
		{name: "gte unsatisfied", rangeExpr: testRangeGte090, current: "0.8.9", want: false},
		{name: "and both hold", rangeExpr: ">=0.9.0, <2.0.0", current: "1.5.0", want: true},
		{name: "and upper bound violated", rangeExpr: ">=0.9.0, <2.0.0", current: "2.0.0", want: false},
		{name: "exact match", rangeExpr: "=1.2.3", current: testVersion123, want: true},
		{name: "exact mismatch", rangeExpr: "=1.2.3", current: "1.2.4", want: false},
		{name: "bare version means exact", rangeExpr: testVersion123, current: testVersion123, want: true},
		{name: "gt patch above short form", rangeExpr: ">1.0", current: "1.0.1", want: true},
		{name: "lte satisfied", rangeExpr: "<=1.0.0", current: testVersion100, want: true},
		{name: "malformed operator", rangeExpr: "~1.0.0", current: testVersion100, wantErr: "invalid version"},
		{name: "empty clause", rangeExpr: ">=1.0.0,,<2.0.0", current: "1.5.0", wantErr: "empty clause"},
		{name: "garbage version", rangeExpr: ">=banana", current: testVersion100, wantErr: "invalid version"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clauses, err := parseVersionRange(tt.rangeExpr)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseVersionRange(%q) error = %v, want containing %q", tt.rangeExpr, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVersionRange(%q) unexpected error: %v", tt.rangeExpr, err)
			}
			current, ok := parseVersion(tt.current)
			if !ok {
				t.Fatalf("bad test fixture version %q", tt.current)
			}
			got := true
			for _, c := range clauses {
				if !c.satisfiedBy(current) {
					got = false
					break
				}
			}
			if got != tt.want {
				t.Errorf("range %q vs %s = %v, want %v", tt.rangeExpr, tt.current, got, tt.want)
			}
		})
	}
}

func TestCheckRequires(t *testing.T) {
	tests := []struct {
		name        string
		requires    *RequiresConfig
		version     string
		wantErr     string
		wantWarning string
	}{
		{
			name:     "nil requires passes",
			requires: nil,
			version:  testVersion100,
		},
		{
			name:     "implemented features pass",
			requires: &RequiresConfig{Features: []string{"composites", "file_url", "refresh_token"}},
			version:  testVersion100,
		},
		{
			name:     "unimplemented feature refused",
			requires: &RequiresConfig{Features: []string{"idempotency"}},
			version:  testVersion100,
			wantErr:  `requires feature "idempotency"`,
		},
		{
			name:     "unknown feature identifier refused",
			requires: &RequiresConfig{Features: []string{"warp_drive"}},
			version:  testVersion100,
			wantErr:  `requires feature "warp_drive"`,
		},
		{
			name:     "empty feature identifier refused",
			requires: &RequiresConfig{Features: []string{""}},
			version:  testVersion100,
			wantErr:  "empty feature identifier",
		},
		{
			name:     "version range satisfied",
			requires: &RequiresConfig{ToolMesh: testRangeGte090},
			version:  testVersion100,
		},
		{
			name:     "version range unsatisfied",
			requires: &RequiresConfig{ToolMesh: ">=2.0.0"},
			version:  testVersion100,
			wantErr:  `requires toolmesh ">=2.0.0"`,
		},
		{
			name:     "malformed range is an error even on dev builds",
			requires: &RequiresConfig{ToolMesh: "banana"},
			version:  testVersionDev,
			wantErr:  "requires.toolmesh",
		},
		{
			name:        "non-semver build skips range with warning",
			requires:    &RequiresConfig{ToolMesh: ">=99.0.0"},
			version:     testVersionDev,
			wantWarning: "not checked",
		},
		{
			name:     "feature check runs before version skip",
			requires: &RequiresConfig{ToolMesh: ">=0.1.0", Features: []string{"idempotency"}},
			version:  testVersionDev,
			wantErr:  `requires feature "idempotency"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &Spec{Requires: tt.requires}
			err := checkRequires(spec, tt.version)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("checkRequires() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkRequires() unexpected error: %v", err)
			}
			if tt.wantWarning != "" {
				if len(spec.Warnings) != 1 || !strings.Contains(spec.Warnings[0], tt.wantWarning) {
					t.Fatalf("warnings = %v, want one containing %q", spec.Warnings, tt.wantWarning)
				}
			} else if len(spec.Warnings) != 0 {
				t.Fatalf("unexpected warnings: %v", spec.Warnings)
			}
		})
	}
}

// TestParseBytes_RequiresGate exercises the gate end-to-end through
// ParseBytes. The test binary carries version.Version == "dev", so the
// toolmesh range path is covered by the dev-skip warning case.
func TestParseBytes_RequiresGate(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
%s
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    get_item:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
`
	t.Run("satisfied features load", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "requires:\n  features: [composites, file_url]", 1)
		spec, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 0 {
			t.Errorf("unexpected warnings: %v", spec.Warnings)
		}
	})
	t.Run("missing feature refuses load", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "requires:\n  features: [idempotency]", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "refusing to load dadl") || !strings.Contains(err.Error(), `"idempotency"`) {
			t.Fatalf("error = %v, want refusal naming idempotency", err)
		}
	})
	t.Run("dev build skips version range with warning", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "requires:\n  toolmesh: \">=99.0.0\"", 1)
		spec, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 1 || !strings.Contains(spec.Warnings[0], "not checked") {
			t.Fatalf("warnings = %v, want dev-skip note", spec.Warnings)
		}
	})
	t.Run("empty requires block loads", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "requires: {}", 1)
		if _, err := ParseBytes([]byte(yaml)); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestParseBytes_UnknownKeyWarnings(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
frobnicate: true
_workspace:
  reusable: &anchor "x"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  health:
    tool: get_item
  tools:
    get_item:
      method: GET
      path: /items/{id}
      returns: Item
      params:
        id: { type: integer, in: path, required: true, descriptionn: "typo" }
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantSubstrings := []string{
		`unknown key "frobnicate" in top level`,
		`unknown key "health" in backend`,
		`unknown key "returns" in tool definition`,
		`unknown key "descriptionn" in parameter definition`,
	}
	if len(spec.Warnings) != len(wantSubstrings) {
		t.Fatalf("got %d warnings, want %d: %v", len(spec.Warnings), len(wantSubstrings), spec.Warnings)
	}
	for i, want := range wantSubstrings {
		if !strings.Contains(spec.Warnings[i], want) {
			t.Errorf("warning[%d] = %q, want containing %q", i, spec.Warnings[i], want)
		}
		if !strings.Contains(spec.Warnings[i], "line ") {
			t.Errorf("warning[%d] = %q, want a line number", i, spec.Warnings[i])
		}
	}
	if spec.ContentHash == "" {
		t.Error("ContentHash must still be computed when warnings exist")
	}
}

// TestParseBytes_UnknownKeyWarningsDeduped pins the aggregation: the same
// unknown key across many tools yields one warning carrying a count.
func TestParseBytes_UnknownKeyWarningsDeduped(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    upload_a:
      method: POST
      path: /a
      max_body_size: 10MB
    upload_b:
      method: POST
      path: /b
      max_body_size: 20MB
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Warnings) != 1 {
		t.Fatalf("got %d warnings, want 1 deduped: %v", len(spec.Warnings), spec.Warnings)
	}
	if !strings.Contains(spec.Warnings[0], `unknown key "max_body_size"`) ||
		!strings.Contains(spec.Warnings[0], "2 occurrences") {
		t.Errorf("warning = %q, want max_body_size with occurrence count", spec.Warnings[0])
	}
}

// TestParseBytes_SpecConformantKeysDoNotWarn pins the documentation
// passthrough: every key the spec defines and the runtime deliberately
// leaves uninterpreted must parse without an unknown-key warning.
func TestParseBytes_SpecConformantKeysDoNotWarn(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
credits:
  - "Jane Doe (@janedoe)"
source_name: "Example API"
source_url: https://docs.example.com
date: "2026-08-05"
_anchors:
  shared: &page_size 50
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  arazzo_source: workflows.arazzo.yaml
  coverage:
    focus: "items and search"
    areas: [items]
  hints:
    get_item:
      rate_limit: "10/s"
  setup:
    credential: EXAMPLE_TOKEN
    steps: ["create a token"]
  examples:
    - title: "Fetch one item"
      code: "await api.get_item({id: 1})"
  tools:
    get_item:
      method: GET
      path: /items/{id}
      description: "Fetch a single item"
      depends_on: [list_items]
      params:
        id: { type: integer, in: path, required: true, description: "Item id" }
    list_items:
      method: GET
      path: /items
      description: "List items"
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Warnings) != 0 {
		t.Fatalf("spec-conformant keys must not warn, got: %v", spec.Warnings)
	}
	if spec.Backend.Tools["get_item"].Params["id"].Description != "Item id" {
		t.Error("param description not parsed")
	}
	if got := spec.Backend.Tools["get_item"].DependsOn; len(got) != 1 || got[0] != testToolListItems {
		t.Errorf("tool depends_on not parsed, got %v", got)
	}
}
