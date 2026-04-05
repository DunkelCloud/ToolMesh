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
	"testing"
)

func TestToToolDescriptor(t *testing.T) {
	td := ToolDef{
		Name:        "test",
		Description: "A test",
		Params: []ParamDef{
			{Name: "x", Type: ParamType{Kind: "string"}, Required: true},
		},
	}
	desc := td.ToToolDescriptor("builtin")
	if desc.Name != "test" || desc.Backend != "builtin" {
		t.Errorf("unexpected: %+v", desc)
	}
	if desc.InputSchema["type"] != "object" {
		t.Error("missing object type")
	}
}

func TestSchemaTypeToParamType(t *testing.T) {
	cases := []struct {
		t    string
		want string
	}{
		{"string", "string"},
		{"number", "number"},
		{"integer", "number"},
		{"boolean", "boolean"},
		{"array", "array"},
		{"object", "object"},
		{"unknown", "any"},
	}
	for _, c := range cases {
		got := schemaTypeToParamType(map[string]any{"type": c.t})
		if got.Kind != c.want {
			t.Errorf("type=%q got %q, want %q", c.t, got.Kind, c.want)
		}
	}

	// array with items.
	got := schemaTypeToParamType(map[string]any{"type": "array", "items": map[string]any{"type": "string"}})
	if got.Kind != "array" || got.ItemKind != "string" {
		t.Errorf("array items: %+v", got)
	}
}

func TestToolDefFromSchema_WithEnum(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"color": map[string]any{
				"type":        "string",
				"enum":        []any{"red", "green", "blue"},
				"description": "pick a color",
			},
			"count": map[string]any{"type": "number"},
		},
		"required": []any{"color"},
	}
	td := ToolDefFromSchema("paint", "", schema)
	if len(td.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(td.Params))
	}
	for _, p := range td.Params {
		if p.Name == "color" {
			if len(p.Enum) != 3 {
				t.Errorf("enum len = %d", len(p.Enum))
			}
			if !p.Required {
				t.Error("color should be required")
			}
		}
	}
}

func TestParamToSchema_ObjectWithProperties(t *testing.T) {
	p := ParamDef{
		Name: "config",
		Type: ParamType{
			Kind: "object",
			Properties: []ParamDef{
				{Name: "host", Type: ParamType{Kind: "string"}, Required: true},
				{Name: "port", Type: ParamType{Kind: "number"}},
			},
		},
	}
	s := paramToSchema(p)
	if s["type"] != "object" {
		t.Error("type not object")
	}
	nested, _ := s["properties"].(map[string]any)
	if _, ok := nested["host"]; !ok {
		t.Error("missing host")
	}
	req, _ := s["required"].([]any)
	if len(req) != 1 {
		t.Errorf("required = %v", req)
	}
}

func TestParamToSchema_ArrayWithItems(t *testing.T) {
	p := ParamDef{
		Name: "tags",
		Type: ParamType{Kind: "array", ItemKind: "string"},
	}
	s := paramToSchema(p)
	items, _ := s["items"].(map[string]any)
	if items["type"] != "string" {
		t.Errorf("items = %v", items)
	}
}
