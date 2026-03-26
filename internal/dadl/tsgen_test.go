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
	"strings"
	"testing"
)

func TestGenerateTypeScript(t *testing.T) {
	spec := &Spec{
		Version: "1.0",
		Backend: BackendDef{
			Name:        "myapi",
			Type:        "rest",
			BaseURL:     "https://api.example.com",
			Description: "Test API service",
			Tools: map[string]ToolDef{
				"get_item": {
					Method:      "GET",
					Path:        "/items/{id}",
					Description: "Get a single item by ID",
					Params: map[string]ParamDef{
						"id": {Type: "integer", In: "path", Required: true},
					},
				},
				"list_items": {
					Method:      "GET",
					Path:        "/items",
					Description: "List all items with optional filtering",
					Params: map[string]ParamDef{
						"page":    {Type: "integer", In: "query"},
						"per_page": {Type: "integer", In: "query"},
						"search":  {Type: "string", In: "query"},
					},
				},
				"create_item": {
					Method:      "POST",
					Path:        "/items",
					Description: "Create a new item",
					Params: map[string]ParamDef{
						"name":   {Type: "string", In: "body", Required: true},
						"tags":   {Type: "array", In: "body"},
						"active": {Type: "boolean", In: "body"},
					},
				},
			},
		},
	}

	ts := GenerateTypeScript(spec)

	// Check structure
	if !strings.Contains(ts, "myapi — Test API service") {
		t.Error("missing backend description comment")
	}

	// Check get_item
	if !strings.Contains(ts, "function myapi_get_item") {
		t.Error("missing get_item function")
	}
	if !strings.Contains(ts, "id: number") {
		t.Error("missing required id param")
	}

	// Check list_items — all optional
	if !strings.Contains(ts, "function myapi_list_items") {
		t.Error("missing list_items function")
	}
	if !strings.Contains(ts, "page?: number") {
		t.Error("missing optional page param")
	}
	if !strings.Contains(ts, "search?: string") {
		t.Error("missing optional search param")
	}

	// Check create_item — mixed required/optional
	if !strings.Contains(ts, "name: string") {
		t.Error("missing required name param")
	}
	if !strings.Contains(ts, "tags?: any[]") {
		t.Error("missing optional tags param")
	}
	if !strings.Contains(ts, "active?: boolean") {
		t.Error("missing optional active param")
	}

	// Check JSDoc
	if !strings.Contains(ts, "/** Get a single item by ID */") {
		t.Error("missing JSDoc comment for get_item")
	}
}

func TestDadlTypeToTS(t *testing.T) {
	tests := []struct {
		dadl string
		want string
	}{
		{"string", "string"},
		{"integer", "number"},
		{"number", "number"},
		{"boolean", "boolean"},
		{"array", "any[]"},
		{"object", "Record<string, any>"},
		{"unknown", "any"},
	}
	for _, tt := range tests {
		t.Run(tt.dadl, func(t *testing.T) {
			got := dadlTypeToTS(tt.dadl)
			if got != tt.want {
				t.Errorf("dadlTypeToTS(%q) = %q, want %q", tt.dadl, got, tt.want)
			}
		})
	}
}
