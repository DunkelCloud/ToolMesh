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

// Command lint-dadl scans DADL files for composite tool security violations.
// Exit code 1 if any violations are found.
//
// Usage:
//
//	lint-dadl [dadl-files...]
//	lint-dadl dadl/*.dadl
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: lint-dadl <dadl-files...>\n")
		os.Exit(2)
	}

	var allResults []composite.LintResult
	hasViolations := false

	for _, pattern := range os.Args[1:] {
		// Expand glob patterns
		matches, err := filepath.Glob(pattern)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid pattern %q: %v\n", pattern, err)
			os.Exit(2)
		}
		if len(matches) == 0 {
			// Treat as literal path
			matches = []string{pattern}
		}

		for _, path := range matches {
			spec, err := dadl.Parse(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: parse error: %v\n", path, err)
				hasViolations = true
				continue
			}

			if !spec.ContainsCode() {
				continue
			}

			results, found := composite.LintDADL(spec, path)
			if found {
				allResults = append(allResults, results...)
				hasViolations = true
			}
		}
	}

	if len(allResults) > 0 {
		fmt.Fprint(os.Stderr, composite.FormatLintResults(allResults))
	}

	if hasViolations {
		os.Exit(1)
	}

	fmt.Println("lint-dadl: all composites clean")
}
