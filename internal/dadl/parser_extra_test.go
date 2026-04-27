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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParse_File(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.dadl")
	content := `spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test
  type: rest
  base_url: "https://example.com"
  tools:
    ping:
      method: GET
      path: /ping
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	spec, err := Parse(path)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Backend.Name != "test" {
		t.Errorf("name = %s", spec.Backend.Name)
	}
}

func TestParse_MissingFile(t *testing.T) {
	if _, err := Parse("/nonexistent/file/x.dadl"); err == nil {
		t.Error("expected error")
	}
}

// TestParseBytes_ContentHashIsLineEndingAgnostic verifies that the same logical
// DADL file produces the same ContentHash whether it has CRLF or LF line endings.
// This matters when DADL files travel across platforms (e.g. Git autocrlf on
// Windows) and we want telemetry / registry lookups to match.
func TestParseBytes_ContentHashIsLineEndingAgnostic(t *testing.T) {
	lf := `spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test
  type: rest
  base_url: "https://example.com"
  tools:
    ping:
      method: GET
      path: /ping
`
	crlf := strings.ReplaceAll(lf, "\n", "\r\n")

	specLF, err := ParseBytes([]byte(lf))
	if err != nil {
		t.Fatalf("LF parse: %v", err)
	}
	specCRLF, err := ParseBytes([]byte(crlf))
	if err != nil {
		t.Fatalf("CRLF parse: %v", err)
	}

	if specLF.ContentHash == "" {
		t.Fatal("LF hash is empty")
	}
	if specLF.ContentHash != specCRLF.ContentHash {
		t.Errorf("hashes differ across line endings:\n  LF:   %s\n  CRLF: %s",
			specLF.ContentHash, specCRLF.ContentHash)
	}
}

func TestCompositeTimeout(t *testing.T) {
	c := CompositeDef{Timeout: "10s"}
	if d := c.CompositeTimeout(); d != 10*time.Second {
		t.Errorf("got %v", d)
	}

	// Empty → default.
	c2 := CompositeDef{}
	if d := c2.CompositeTimeout(); d == 0 {
		t.Error("expected non-zero default")
	}

	// Invalid → default.
	c3 := CompositeDef{Timeout: "invalid"}
	if d := c3.CompositeTimeout(); d == 0 {
		t.Error("expected non-zero default on invalid")
	}
}
