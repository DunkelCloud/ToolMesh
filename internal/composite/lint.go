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
	"fmt"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// LintResult holds the lint results for a single DADL file.
type LintResult struct {
	File       string      `json:"file"`
	Composite  string      `json:"composite"`
	Violations []Violation `json:"violations"`
}

// LintDADL scans all composites in a parsed DADL spec for security violations.
// Returns a list of results (one per composite with violations) and whether any
// violations were found.
func LintDADL(spec *dadl.Spec, filePath string) ([]LintResult, bool) {
	var results []LintResult
	hasViolations := false

	for name, comp := range spec.Backend.Composites {
		violations, err := ScanCode(comp.Code, name)
		if err != nil {
			results = append(results, LintResult{
				File:      filePath,
				Composite: name,
				Violations: []Violation{{
					Message: fmt.Sprintf("parse error: %s", err),
				}},
			})
			hasViolations = true
			continue
		}
		if len(violations) > 0 {
			results = append(results, LintResult{
				File:       filePath,
				Composite:  name,
				Violations: violations,
			})
			hasViolations = true
		}
	}

	return results, hasViolations
}

// FormatLintResults formats lint results as human-readable text.
func FormatLintResults(results []LintResult) string {
	var sb strings.Builder
	for _, r := range results {
		for _, v := range r.Violations {
			if v.Line > 0 {
				fmt.Fprintf(&sb, "%s: composite %q line %d col %d: %s\n",
					r.File, r.Composite, v.Line, v.Column, v.Message)
			} else {
				fmt.Fprintf(&sb, "%s: composite %q: %s\n",
					r.File, r.Composite, v.Message)
			}
		}
	}
	return sb.String()
}
