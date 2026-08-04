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

package backend

import "testing"

// ResolveBackendName has to agree with routing in the cases a "split on the
// first underscore" shortcut would get wrong: backend names containing
// underscores, and one name being a prefix of another.
func TestResolveBackendName(t *testing.T) {
	const (
		rnPlain      = "alpha"
		rnUnderscore = "raw_nd"
		rnLong       = "alpha_extended"
		rnPass       = "mcp-alpha"
	)

	c := NewCompositeBackend(map[string]ToolBackend{
		rnPlain:      &stubBackend{name: rnPlain},
		rnUnderscore: &stubBackend{name: rnUnderscore},
		rnLong:       &stubBackend{name: rnLong},
	})
	c.AddPassthrough(summarizerPassthrough{subs: []BackendInfo{{Name: rnPass}}})

	tests := []struct {
		name      string
		tool      string
		want      string
		wantOK    bool
		rationale string
	}{
		{
			name:      "plain named backend",
			tool:      "alpha_list_items",
			want:      rnPlain,
			wantOK:    true,
			rationale: "ordinary prefix match",
		},
		{
			name:      "backend name contains an underscore",
			tool:      "raw_nd_execute_function",
			want:      rnUnderscore,
			wantOK:    true,
			rationale: "splitting on the first underscore would yield \"raw\"",
		},
		{
			name:      "longer name wins over its own prefix",
			tool:      "alpha_extended_list_items",
			want:      rnLong,
			wantOK:    true,
			rationale: "both \"alpha\" and \"alpha_extended\" match; routing takes the longest",
		},
		{
			name:      "passthrough sub-backend",
			tool:      "mcp-alpha_search",
			want:      rnPass,
			wantOK:    true,
			rationale: "sub-backends surfaced via BackendSummaries are resolvable too",
		},
		{
			name:      "no backend owns the tool",
			tool:      "unknown_tool",
			wantOK:    false,
			rationale: "callers must be able to tell ownership apart from a guess",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := c.ResolveBackendName(tc.tool)
			if ok != tc.wantOK {
				t.Fatalf("ResolveBackendName(%q) ok = %v, want %v (%s)", tc.tool, ok, tc.wantOK, tc.rationale)
			}
			if got != tc.want {
				t.Errorf("ResolveBackendName(%q) = %q, want %q (%s)", tc.tool, got, tc.want, tc.rationale)
			}
		})
	}
}

func TestResolveBackendName_EmptyComposite(t *testing.T) {
	c := NewCompositeBackend(nil)
	if name, ok := c.ResolveBackendName("alpha_list"); ok || name != "" {
		t.Errorf("ResolveBackendName on empty composite = (%q, %v), want (\"\", false)", name, ok)
	}
}
