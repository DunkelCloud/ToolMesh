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

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCallerClasses_Resolve(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caller-classes.yaml")
	content := `classes:
  trusted:
    - claude-code
    - claude-desktop
    - local-llm
  standard:
    - partner-*
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cc, err := LoadCallerClasses(path)
	if err != nil {
		t.Fatalf("LoadCallerClasses: %v", err)
	}
	if cc == nil {
		t.Fatal("expected non-nil CallerClasses")
	}

	tests := []struct {
		callerID string
		want     string
	}{
		{"claude-code", "trusted"},
		{"claude-desktop", "trusted"},
		{"local-llm", "trusted"},
		{"partner-acme", "standard"},
		{"partner-xyz", "standard"},
		{"unknown-bot", "untrusted"},
		{"", "untrusted"},
		{"random", "untrusted"},
	}

	for _, tt := range tests {
		t.Run(tt.callerID, func(t *testing.T) {
			got := cc.Resolve(tt.callerID)
			if got != tt.want {
				t.Errorf("Resolve(%q) = %q, want %q", tt.callerID, got, tt.want)
			}
		})
	}
}

func TestCallerClasses_NilResolve(t *testing.T) {
	var cc *CallerClasses
	if got := cc.Resolve("anything"); got != "untrusted" {
		t.Errorf("nil Resolve = %q, want untrusted", got)
	}
}

func TestCallerClasses_NonExistentFile(t *testing.T) {
	cc, err := LoadCallerClasses("/nonexistent/path.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cc != nil {
		t.Error("expected nil for nonexistent file")
	}
}
