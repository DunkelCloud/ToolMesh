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

package composite

import (
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestLintDADL_DetectsViolations(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Composites: map[string]dadl.CompositeDef{
				"bad": {
					Code: `fetch("https://evil.com")`,
				},
				"good": {
					Code: `return 1 + 1;`,
				},
			},
		},
	}
	results, found := LintDADL(spec, "/tmp/test.dadl")
	if !found {
		t.Fatal("expected violations")
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
	if results[0].Composite != "bad" {
		t.Errorf("wrong composite: %s", results[0].Composite)
	}
}

func TestLintDADL_ParseError(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Composites: map[string]dadl.CompositeDef{
				"broken": {
					Code: `function {{{`,
				},
			},
		},
	}
	results, found := LintDADL(spec, "f.dadl")
	if !found {
		t.Error("expected parse error to count as violation")
	}
	if len(results) != 1 {
		t.Errorf("got %d results", len(results))
	}
}

func TestLintDADL_Clean(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Composites: map[string]dadl.CompositeDef{
				"good": {Code: `return params.x;`},
			},
		},
	}
	_, found := LintDADL(spec, "f.dadl")
	if found {
		t.Error("expected no violations")
	}
}

func TestFormatLintResults(t *testing.T) {
	results := []LintResult{
		{
			File:      "f.dadl",
			Composite: "bad",
			Violations: []Violation{
				{Line: 3, Column: 5, Message: "forbidden fetch"},
				{Message: "parse error"},
			},
		},
	}
	out := FormatLintResults(results)
	if !strings.Contains(out, "forbidden fetch") || !strings.Contains(out, "line 3") {
		t.Errorf("missing line/message: %s", out)
	}
	if !strings.Contains(out, "parse error") {
		t.Errorf("missing parse error: %s", out)
	}
}

func TestFormatLintResults_Empty(t *testing.T) {
	if got := FormatLintResults(nil); got != "" {
		t.Errorf("empty: got %q", got)
	}
}
