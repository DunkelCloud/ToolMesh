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

package tsdef

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDir(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.ts"), []byte(`/** Tool A */
export function toolA(): Promise<any>;`), 0600)
	os.WriteFile(filepath.Join(dir, "b.ts"), []byte(`/** Tool B */
export function toolB(params: {
  x: number;
}): Promise<any>;`), 0600)

	defs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(defs) != 2 {
		t.Errorf("expected 2 defs, got %d", len(defs))
	}
}

func TestLoadDir_Empty(t *testing.T) {
	dir := t.TempDir()
	defs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(defs) != 0 {
		t.Errorf("expected 0 defs, got %d", len(defs))
	}
}

func TestLoadDir_Missing(t *testing.T) {
	defs, err := LoadDir("/nonexistent/path")
	if err != nil {
		t.Fatalf("expected no error for missing dir, got: %v", err)
	}
	if len(defs) != 0 {
		t.Errorf("expected 0 defs, got %d", len(defs))
	}
}

func TestLoadRawTS(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "echo.ts"), []byte("// echo tools\n"), 0600)

	raw, err := LoadRawTS(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw == "" {
		t.Error("expected non-empty raw TS content")
	}
}
