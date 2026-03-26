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
)

func TestScanCode(t *testing.T) {
	tests := []struct {
		name           string
		code           string
		wantViolations int
		wantContains   string
	}{
		{
			name:           "clean code — no violations",
			code:           `const x = 1 + 2; const arr = [1,2,3].map(x => x * 2);`,
			wantViolations: 0,
		},
		{
			name:           "fetch is forbidden",
			code:           `const data = fetch("http://evil.com");`,
			wantViolations: 1,
			wantContains:   "fetch",
		},
		{
			name:           "require is forbidden",
			code:           `const fs = require("fs");`,
			wantViolations: 1,
			wantContains:   "require",
		},
		{
			name:           "eval call is forbidden",
			code:           `const x = eval("1+1");`,
			wantViolations: 1,
			wantContains:   "eval",
		},
		{
			name:           "Function call is forbidden",
			code:           `const fn = Function("return 1");`,
			wantViolations: 1,
			wantContains:   "Function",
		},
		{
			name:           "process.env is forbidden",
			code:           `const secret = process.env.API_KEY;`,
			wantViolations: 1,
			wantContains:   "process",
		},
		{
			name:           "globalThis access is forbidden",
			code:           `const g = globalThis.fetch;`,
			wantViolations: 1,
			wantContains:   "globalThis",
		},
		{
			name:           "setTimeout is forbidden",
			code:           `setTimeout(() => {}, 1000);`,
			wantViolations: 1,
			wantContains:   "setTimeout",
		},
		{
			name:           "multiple violations",
			code:           `fetch("x"); require("y"); eval("z");`,
			wantViolations: 3,
		},
		{
			name:           "window.location is forbidden",
			code:           `const loc = window.location;`,
			wantViolations: 1,
			wantContains:   "window",
		},
		{
			name:           "violations have line numbers",
			code:           "const a = 1;\nfetch('evil');\nconst b = 2;",
			wantViolations: 1,
			wantContains:   "fetch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := ScanCode(tt.code, "test")
			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}
			if len(violations) != tt.wantViolations {
				t.Errorf("got %d violations, want %d: %v", len(violations), tt.wantViolations, violations)
			}
			if tt.wantContains != "" && len(violations) > 0 {
				found := false
				for _, v := range violations {
					if strings.Contains(v.Message, tt.wantContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no violation message contains %q: %v", tt.wantContains, violations)
				}
			}
		})
	}
}

func TestScanCode_LineNumbers(t *testing.T) {
	code := "const a = 1;\nconst b = fetch('x');\nconst c = 3;"
	violations, err := ScanCode(code, "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Line != 2 {
		t.Errorf("violation line = %d, want 2", violations[0].Line)
	}
}

func TestScanCode_InvalidSyntax(t *testing.T) {
	_, err := ScanCode("function {{{", "test")
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
}
