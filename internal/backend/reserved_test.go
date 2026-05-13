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

// TestIsReservedClientToolName guards the public predicate the composite
// layer uses to decide when an expose_tools alias must fall back to its
// canonical form. The set is small enough to enumerate exhaustively, which
// makes regressions when someone edits reserved.go obvious.
func TestIsReservedClientToolName(t *testing.T) {
	reserved := []string{"web_search", "code_interpreter", "file_search", "computer_use"}
	for _, name := range reserved {
		if !IsReservedClientToolName(name) {
			t.Errorf("IsReservedClientToolName(%q) = false, want true", name)
		}
	}
	notReserved := []string{
		"fetch_url",         // dunkel-cloud-internal tool that must keep its bare alias
		"brave_web_search",  // canonical form — only the bare name is reserved
		"WebSearch",         // case mismatch — exact match only
		"web_search_extra",  // prefix collision — exact match only
		"",                  // empty
	}
	for _, name := range notReserved {
		if IsReservedClientToolName(name) {
			t.Errorf("IsReservedClientToolName(%q) = true, want false", name)
		}
	}
}
