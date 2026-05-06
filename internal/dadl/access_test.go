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

import "testing"

// TestParseBytes_AccessField verifies that the optional `access` field is
// parsed for both regular tools and composites, and that the value is
// preserved verbatim — well-known and custom strings alike.
func TestParseBytes_AccessField(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    list_items:
      method: GET
      path: /items
      access: read
      description: "List items"
    create_item:
      method: POST
      path: /items
      access: write
      description: "Create an item"
    delete_all:
      method: DELETE
      path: /items
      access: dangerous
      description: "Delete every item"
    process_billing:
      method: POST
      path: /billing/run
      access: billing
      description: "Custom access tag"
    legacy_tool:
      method: GET
      path: /legacy
      description: "No access tag — unclassified"
  composites:
    refresh_all:
      description: "Compound write operation"
      access: admin
      code: "return api.list_items({});"
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}

	wantTools := map[string]string{
		"list_items":      "read",
		"create_item":     "write",
		"delete_all":      "dangerous",
		"process_billing": "billing",
		"legacy_tool":     "",
	}
	for name, want := range wantTools {
		got := spec.Backend.Tools[name].Access
		if got != want {
			t.Errorf("tool %q: Access = %q, want %q", name, got, want)
		}
	}

	if got := spec.Backend.Composites["refresh_all"].Access; got != testAccessAdmin {
		t.Errorf("composite refresh_all: Access = %q, want %q", got, testAccessAdmin)
	}
}
