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

func TestLoadDir_MissingDir(t *testing.T) {
	// Non-existent directory → returns nil tools, no error.
	defs, err := LoadDir(filepath.Join(t.TempDir(), "no-such-dir"))
	if err != nil {
		t.Logf("LoadDir error (acceptable): %v", err)
	}
	if len(defs) != 0 {
		t.Errorf("got %d defs", len(defs))
	}
}

func TestLoadDir_WithTSFile(t *testing.T) {
	dir := t.TempDir()
	ts := `/** Greet user */
export function hello(params: { name: string }): Promise<any>;
`
	if err := os.WriteFile(filepath.Join(dir, "tools.ts"), []byte(ts), 0o600); err != nil {
		t.Fatal(err)
	}
	defs, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(defs) != 1 || defs[0].Name != "hello" {
		t.Errorf("defs = %v", defs)
	}
}

func TestLoadRawTS_Extra(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.ts"), []byte("// file a"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "b.ts"), []byte("// file b"), 0o600)

	raw, err := LoadRawTS(dir)
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" {
		t.Error("expected non-empty raw TS")
	}
}
