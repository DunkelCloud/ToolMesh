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

package unit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDir_MissingIsNotAnError(t *testing.T) {
	dirs, err := ScanDir(filepath.Join(t.TempDir(), "does", "not", "exist"))
	if err != nil {
		t.Fatalf("missing dir should be nil error, got %v", err)
	}
	if len(dirs) != 0 {
		t.Fatalf("expected zero dirs, got %v", dirs)
	}
}

func TestScanDir_FindsDirectChildren(t *testing.T) {
	root := t.TempDir()
	writeUnitYAML(t, filepath.Join(root, "alpha"))
	writeUnitYAML(t, filepath.Join(root, "beta"))

	dirs, err := ScanDir(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(dirs) != 2 {
		t.Fatalf("expected 2 dirs, got %d: %v", len(dirs), dirs)
	}
}

// TestScanDir_ExamplesDoNotAutoActivate is the security-relevant
// regression guard. Shipped examples live one directory deeper than the
// scan target so they must not be discovered. If this test ever fails,
// the loader has become recursive and example units would start auto-
// activating at startup — the exact "security off by default" pattern
// the project explicitly avoids.
func TestScanDir_ExamplesDoNotAutoActivate(t *testing.T) {
	root := t.TempDir()
	writeUnitYAML(t, filepath.Join(root, "examples", "dice"))
	writeUnitYAML(t, filepath.Join(root, "examples", "imap-trust"))

	dirs, err := ScanDir(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(dirs) != 0 {
		t.Fatalf("examples must not auto-activate, got %v", dirs)
	}
}

func TestScanDir_IgnoresDirsWithoutUnitYAML(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "notes"), 0o700); err != nil {
		t.Fatalf("mkdir notes: %v", err)
	}
	writeUnitYAML(t, filepath.Join(root, "real-unit"))

	dirs, err := ScanDir(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(dirs) != 1 || filepath.Base(dirs[0]) != "real-unit" {
		t.Fatalf("expected only real-unit, got %v", dirs)
	}
}

func writeUnitYAML(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	yaml := "unit: " + filepath.Base(dir) + "\nimplementation: ./impl.js\n"
	if err := os.WriteFile(filepath.Join(dir, "unit.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatalf("write unit.yaml: %v", err)
	}
}

// TestResolveSubBackendDADL covers every branch of the DADL path resolution a
// unit sub-backend goes through: absolute verbatim, bundled-next-to-unit,
// bare-name fallback to the global dir (the config/backends.yaml convention),
// bundled taking precedence when a name exists in both, and the missing-file
// cases whose returned path drives the parse error message.
func TestResolveSubBackendDADL(t *testing.T) {
	unitDir := t.TempDir()
	dadlDir := t.TempDir()

	writeFile(t, filepath.Join(unitDir, "bundled.dadl"))
	writeFile(t, filepath.Join(dadlDir, "global.dadl"))
	// A name present in BOTH locations — bundled must win.
	writeFile(t, filepath.Join(unitDir, "both.dadl"))
	writeFile(t, filepath.Join(dadlDir, "both.dadl"))

	abs := filepath.Join(t.TempDir(), "abs.dadl")

	tests := []struct {
		name    string
		ref     string
		dadlDir string
		want    string
	}{
		{"absolute used verbatim", abs, dadlDir, abs},
		{"bundled next to unit", "bundled.dadl", dadlDir, filepath.Join(unitDir, "bundled.dadl")},
		{"bare name falls back to global dir", "global.dadl", dadlDir, filepath.Join(dadlDir, "global.dadl")},
		{"bundled wins over global", "both.dadl", dadlDir, filepath.Join(unitDir, "both.dadl")},
		{"missing, no global dir, stays unit-local", "missing.dadl", "", filepath.Join(unitDir, "missing.dadl")},
		{"missing locally, resolves to global path", "missing.dadl", dadlDir, filepath.Join(dadlDir, "missing.dadl")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveSubBackendDADL(unitDir, tt.dadlDir, tt.ref)
			if got != tt.want {
				t.Errorf("resolveSubBackendDADL(unitDir, %q, %q) = %q, want %q",
					tt.dadlDir, tt.ref, got, tt.want)
			}
		})
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
