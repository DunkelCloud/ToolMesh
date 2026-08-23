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

// Command lint-dadl checks DADL files against what this ToolMesh version
// implements. Exit code 1 if any file has an error; warnings do not fail the
// run.
//
// It covers three classes:
//
//   - Structural faults that stop a file loading at all (spec §15.2) — a
//     missing method, an unknown auth type, a composite naming a tool that
//     does not exist.
//
//   - Keys this runtime does not implement (spec §15.3). The server warns and
//     ignores these, as §15.3 requires of a runtime; a linter is held to the
//     other half of the same rule. These split in two, and the canonical
//     schema decides which is which:
//
//     A key the spec does not define is an error. It was invented or
//     misspelled — `next_link_header` where the spec says `total_pages_header`
//     — and nothing will ever honor it. Without a linter it reaches production
//     as a line in a startup log nobody reads.
//
//     A key the spec does define is a warning: the file is correct and this
//     build is behind. `max_body_size` sat in that state for months. Failing
//     an author's build over a gap in the runtime would put the complaint on
//     the wrong side.
//
//   - Security violations in composite JavaScript.
//
// Point it at the DADL directory a deployment actually loads, not only at the
// files in a repository: a file that never passes through registry CI is
// otherwise checked by nothing at all.
//
// Usage:
//
//	lint-dadl [flags] <path...>
//
// Paths may be files, directories (scanned for *.dadl, not recursive, matching
// how ToolMesh loads a DADL directory), or globs.
//
// Flags:
//
//	-warn          report every unimplemented key as a warning, including ones
//	               the spec does not define. Use when linting a file that
//	               targets a newer spec version than this build.
//	-schema PATH   canonical DADL JSON Schema (default docs/schema/dadl-v0.2.schema.json
//	               relative to the working directory). Without it every
//	               unimplemented key is an error, which is the fail-closed
//	               reading but tells you less.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// exit codes: 0 clean, 1 findings, 2 usage or I/O failure.
const (
	exitFindings = 1
	exitUsage    = 2
)

// fileReport collects everything found in one file.
type fileReport struct {
	path     string
	errors   []string
	warnings []string
}

func main() {
	warnOnly := flag.Bool("warn", false,
		"report every key this ToolMesh version does not implement as a warning, not an error")
	schemaPath := flag.String("schema", "",
		"canonical DADL JSON Schema (default "+defaultSchemaPath+"); used to tell an invented key from one this build has not caught up with")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() == 0 {
		usage()
		os.Exit(exitUsage)
	}

	keys, err := loadSpecKeys(*schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lint-dadl: %v\n", err)
		os.Exit(exitUsage)
	}
	if keys == nil {
		fmt.Fprintf(os.Stderr,
			"lint-dadl: no schema at %s — every unimplemented key is reported as an error;\n"+
				"           pass -schema to separate an invented key from a runtime gap\n",
			defaultSchemaPath)
	}

	paths, err := collectPaths(flag.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "lint-dadl: %v\n", err)
		os.Exit(exitUsage)
	}
	if len(paths) == 0 {
		fmt.Fprintf(os.Stderr, "lint-dadl: no .dadl files matched\n")
		os.Exit(exitUsage)
	}

	var (
		reports    []fileReport
		errorFiles int
		errorCount int
		warnCount  int
		cleanFiles int
	)
	for _, path := range paths {
		r := lintFile(path, keys, *warnOnly)
		if len(r.errors) == 0 && len(r.warnings) == 0 {
			cleanFiles++
			continue
		}
		if len(r.errors) > 0 {
			errorFiles++
			errorCount += len(r.errors)
		}
		warnCount += len(r.warnings)
		reports = append(reports, r)
	}

	for _, r := range reports {
		fmt.Fprintf(os.Stderr, "\n%s\n", r.path)
		for _, e := range r.errors {
			fmt.Fprintf(os.Stderr, "  error:   %s\n", e)
		}
		for _, w := range r.warnings {
			fmt.Fprintf(os.Stderr, "  warning: %s\n", w)
		}
	}

	fmt.Fprintf(os.Stderr, "\nlint-dadl: %d file(s) checked, %d clean, %d error(s) in %d file(s), %d warning(s)\n",
		len(paths), cleanFiles, errorCount, errorFiles, warnCount)

	if errorCount > 0 {
		os.Exit(exitFindings)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lint-dadl checks DADL files against what this ToolMesh version implements.

Usage:
  lint-dadl [flags] <path...>

Paths may be files, directories (scanned for *.dadl, not recursive), or globs.

Flags:
  -warn          report every key this ToolMesh version does not implement as a
                 warning, not an error (for files targeting a newer spec version)
  -schema PATH   canonical DADL JSON Schema (default docs/schema/dadl-v0.2.schema.json).
                 A key the spec defines but this build does not implement is a
                 warning; a key the spec does not define at all is an error.

Exit codes:
  0  no errors
  1  at least one error
  2  usage or I/O failure
`)
}

// collectPaths expands the command line into a deduplicated, sorted list of
// .dadl files. A directory contributes its direct *.dadl children — not a
// recursive walk, which is how ToolMesh itself reads a DADL directory.
func collectPaths(args []string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	add := func(p string) {
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, arg := range args {
		info, statErr := os.Stat(arg)
		switch {
		case statErr == nil && info.IsDir():
			entries, err := filepath.Glob(filepath.Join(arg, "*.dadl"))
			if err != nil {
				return nil, fmt.Errorf("scan directory %q: %w", arg, err)
			}
			for _, e := range entries {
				add(e)
			}
		case statErr == nil:
			add(arg)
		default:
			// Not an existing path: treat it as a glob. A pattern matching
			// nothing is reported by the caller, not silently skipped.
			matches, err := filepath.Glob(arg)
			if err != nil {
				return nil, fmt.Errorf("invalid pattern %q: %w", arg, err)
			}
			if len(matches) == 0 {
				return nil, fmt.Errorf("no such file or pattern: %q", arg)
			}
			for _, m := range matches {
				add(m)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// lintFile runs every check against one file. A parse failure is terminal for
// that file — the later checks need a parsed spec — so it is reported alone.
func lintFile(path string, keys specKeys, warnOnly bool) fileReport {
	r := fileReport{path: path}

	spec, err := dadl.Parse(path)
	if err != nil {
		r.errors = append(r.errors, err.Error())
		return r
	}

	for _, w := range spec.Warnings {
		switch {
		case !dadl.IsUnknownKeyWarning(w):
			// Not a §15.3 finding — e.g. a requires.toolmesh range a
			// non-semver build could not check. Informational either way.
			r.warnings = append(r.warnings, w)
		case warnOnly:
			r.warnings = append(r.warnings, w)
		case keys.definedBySpec(w):
			r.warnings = append(r.warnings, w+" [the spec defines this key; the gap is in ToolMesh, not in the file]")
		default:
			r.errors = append(r.errors, w+" [the spec does not define this key]")
		}
	}

	if spec.ContainsCode() {
		results, found := composite.LintDADL(spec, path)
		if found {
			for _, line := range strings.Split(strings.TrimRight(composite.FormatLintResults(results), "\n"), "\n") {
				// FormatLintResults prefixes each line with the file path,
				// which the per-file heading already carries.
				r.errors = append(r.errors, strings.TrimPrefix(line, path+": "))
			}
		}
	}

	return r
}
