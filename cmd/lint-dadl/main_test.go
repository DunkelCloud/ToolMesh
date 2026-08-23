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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// specHeader is the minimum every fixture needs to parse.
const specHeader = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
`

// canonicalSchema is the repository's own schema, which the linter reads to
// tell an invented key from a runtime gap.
const canonicalSchema = "../../docs/schema/dadl-v0.2.schema.json"

func writeDADL(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(specHeader+body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func loadTestKeys(t *testing.T) specKeys {
	t.Helper()
	keys, err := loadSpecKeys(canonicalSchema)
	if err != nil {
		t.Fatalf("load schema: %v", err)
	}
	if keys == nil {
		t.Fatalf("schema %s not found", canonicalSchema)
	}
	return keys
}

// TestLintFile_UnknownKeyClassification is the heart of the tool: the same
// §15.3 finding means opposite things depending on whether the spec defines
// the key, and the two need opposite handling.
func TestLintFile_UnknownKeyClassification(t *testing.T) {
	dir := t.TempDir()
	keys := loadTestKeys(t)

	t.Run("a key the spec does not define is an error", func(t *testing.T) {
		// next_link_header is the real case from github.dadl: invented, and
		// silently ignored by the runtime ever since.
		path := writeDADL(t, dir, "invented.dadl", `  defaults:
    pagination:
      strategy: page
      request:
        page_param: page
      response:
        next_link_header: Link
  tools:
    t:
      method: GET
      path: /x
`)
		r := lintFile(path, keys, false)
		if len(r.errors) != 1 {
			t.Fatalf("errors = %v, want exactly one", r.errors)
		}
		for _, want := range []string{`unknown key "next_link_header"`, "the spec does not define this key"} {
			if !strings.Contains(r.errors[0], want) {
				t.Errorf("error = %q, want substring %q", r.errors[0], want)
			}
		}
		if len(r.warnings) != 0 {
			t.Errorf("warnings = %v, want none", r.warnings)
		}
	})

	t.Run("a key the spec defines is a warning", func(t *testing.T) {
		// backend.health is spec §4.6 and this build does not implement it —
		// the same state max_body_size was in. The file is correct; failing
		// the author's build over a gap in ToolMesh would misdirect the fix.
		path := writeDADL(t, dir, "specdefined.dadl", `  health:
    tool: t
  tools:
    t:
      method: GET
      path: /x
`)
		r := lintFile(path, keys, false)
		if len(r.errors) != 0 {
			t.Fatalf("errors = %v, want none: a spec-defined key is a ToolMesh gap", r.errors)
		}
		if len(r.warnings) != 1 {
			t.Fatalf("warnings = %v, want exactly one", r.warnings)
		}
		for _, want := range []string{`unknown key "health"`, "the gap is in ToolMesh, not in the file"} {
			if !strings.Contains(r.warnings[0], want) {
				t.Errorf("warning = %q, want substring %q", r.warnings[0], want)
			}
		}
	})

	t.Run("-warn downgrades every unimplemented key", func(t *testing.T) {
		path := filepath.Join(dir, "invented.dadl")
		r := lintFile(path, keys, true)
		if len(r.errors) != 0 {
			t.Errorf("errors = %v, want none under -warn", r.errors)
		}
		if len(r.warnings) != 1 {
			t.Errorf("warnings = %v, want the finding kept as a warning", r.warnings)
		}
	})

	t.Run("without a schema every unimplemented key is an error", func(t *testing.T) {
		path := filepath.Join(dir, "invented.dadl")
		r := lintFile(path, nil, false)
		if len(r.errors) != 1 {
			t.Fatalf("errors = %v, want the fail-closed reading", r.errors)
		}
	})

	t.Run("a clean file reports nothing", func(t *testing.T) {
		path := writeDADL(t, dir, "clean.dadl", `  tools:
    t:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
`)
		r := lintFile(path, keys, false)
		if len(r.errors) != 0 || len(r.warnings) != 0 {
			t.Errorf("errors = %v, warnings = %v, want both empty", r.errors, r.warnings)
		}
	})

	t.Run("a structural fault is reported and stops further checks", func(t *testing.T) {
		path := writeDADL(t, dir, "broken.dadl", `  tools:
    t:
      path: /x
`)
		r := lintFile(path, keys, false)
		if len(r.errors) != 1 || !strings.Contains(r.errors[0], "method is required") {
			t.Fatalf("errors = %v, want the parse failure", r.errors)
		}
	})
}

// TestLintFile_ImplementedKeyIsSilent closes the loop on max_body_size, the
// key that motivated the spec-defined/invented split. It sat in the
// spec-defined bucket for months — declared by 42 tools, warned about on every
// load, honored by nothing — and is now implemented. An implemented key must
// produce no finding at all: not an error, which would blame the file, and not
// a warning, which would keep reporting a gap that has been closed.
func TestLintFile_ImplementedKeyIsSilent(t *testing.T) {
	dir := t.TempDir()
	keys := loadTestKeys(t)

	path := writeDADL(t, dir, "maxbody.dadl", `  tools:
    upload:
      method: POST
      path: /upload
      max_body_size: 50MB
`)
	r := lintFile(path, keys, false)
	if len(r.errors) != 0 || len(r.warnings) != 0 {
		t.Errorf("errors = %v, warnings = %v, want both empty: max_body_size is implemented",
			r.errors, r.warnings)
	}
}

func TestCollectPaths(t *testing.T) {
	dir := t.TempDir()
	writeDADL(t, dir, "b.dadl", "  tools:\n    t: { method: GET, path: /x }\n")
	writeDADL(t, dir, "a.dadl", "  tools:\n    t: { method: GET, path: /x }\n")
	if err := os.WriteFile(filepath.Join(dir, "notes.md"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	t.Run("a directory yields its dadl files, sorted", func(t *testing.T) {
		got, err := collectPaths([]string{dir})
		if err != nil {
			t.Fatalf("collectPaths: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %d paths, want 2: %v", len(got), got)
		}
		if filepath.Base(got[0]) != "a.dadl" || filepath.Base(got[1]) != "b.dadl" {
			t.Errorf("paths = %v, want a.dadl then b.dadl", got)
		}
	})

	t.Run("a repeated file is listed once", func(t *testing.T) {
		f := filepath.Join(dir, "a.dadl")
		got, err := collectPaths([]string{f, f, dir})
		if err != nil {
			t.Fatalf("collectPaths: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("got %d paths, want 2 deduplicated: %v", len(got), got)
		}
	})

	t.Run("a pattern matching nothing is an error, not a silent skip", func(t *testing.T) {
		if _, err := collectPaths([]string{filepath.Join(dir, "*.nope")}); err == nil {
			t.Error("err = nil, want the empty match reported")
		}
	})
}

func TestLoadSpecKeys(t *testing.T) {
	t.Run("the canonical schema loads", func(t *testing.T) {
		keys := loadTestKeys(t)
		for _, name := range []string{"max_body_size", "next_cursor", "total_pages_header", "retry_after_header"} {
			if !keys[name] {
				t.Errorf("schema key %q not collected", name)
			}
		}
		for _, name := range []string{"next_link_header", "requests_per_second", "current_page"} {
			if keys[name] {
				t.Errorf("key %q collected, but the spec does not define it", name)
			}
		}
	})

	t.Run("a missing default schema degrades instead of failing", func(t *testing.T) {
		t.Chdir(t.TempDir())
		keys, err := loadSpecKeys("")
		if err != nil {
			t.Fatalf("loadSpecKeys: %v", err)
		}
		if keys != nil {
			t.Errorf("keys = %v, want nil so the caller falls back to strict", keys)
		}
	})

	t.Run("an explicitly named missing schema is an error", func(t *testing.T) {
		if _, err := loadSpecKeys(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Error("err = nil, want the missing file reported")
		}
	})

	t.Run("definedBySpec ignores anything that is not an unknown-key warning", func(t *testing.T) {
		keys := loadTestKeys(t)
		if keys.definedBySpec(`requires.toolmesh ">=9.0.0" not checked: running version "dev" is not a semver literal`) {
			t.Error("a non-§15.3 warning was classified as a spec key")
		}
	})
}
