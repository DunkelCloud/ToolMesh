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
		Name:        testToolName,
		Description: "A test",
		Params: []ParamDef{
			{Name: "x", Type: ParamType{Kind: kindString}, Required: true},
		},
	}
	desc := td.ToToolDescriptor("builtin")
	if desc.Name != testToolName || desc.Backend != "builtin" {
		t.Errorf("unexpected: %+v", desc)
	}
	if desc.InputSchema["type"] != kindObject {
		t.Error("missing object type")
	}
}

func TestSchemaTypeToParamType(t *testing.T) {
	cases := []struct {
		t    string
		want string
	}{
		{kindString, kindString},
		{kindNumber, kindNumber},
		{"integer", kindNumber},
		{kindBoolean, kindBoolean},
		{kindArray, kindArray},
		{kindObject, kindObject},
		{"unknown", "any"},
	}
	for _, c := range cases {
		got := schemaTypeToParamType(map[string]any{schemaKeyType: c.t})
		if got.Kind != c.want {
			t.Errorf("type=%q got %q, want %q", c.t, got.Kind, c.want)
		}
	}

	// array with items.
	got := schemaTypeToParamType(map[string]any{schemaKeyType: kindArray, "items": map[string]any{schemaKeyType: kindString}})
	if got.Kind != kindArray || got.ItemKind != kindString {
		t.Errorf("array items: %+v", got)
	}
}

func TestToolDefFromSchema_WithEnum(t *testing.T) {
	schema := map[string]any{
		schemaKeyType: kindObject,
		"properties": map[string]any{
			testParamColor: map[string]any{
				schemaKeyType: kindString,
				"enum":        []any{"red", "green", "blue"},
				"description": "pick a color",
			},
			"count": map[string]any{schemaKeyType: kindNumber},
		},
		"required": []any{testParamColor},
	}
	td := ToolDefFromSchema("paint", "", schema)
	if len(td.Params) != 2 {
		t.Errorf("expected 2 params, got %d", len(td.Params))
	}
	for _, p := range td.Params {
		if p.Name == testParamColor {
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
			Kind: kindObject,
			Properties: []ParamDef{
				{Name: "host", Type: ParamType{Kind: kindString}, Required: true},
				{Name: "port", Type: ParamType{Kind: kindNumber}},
			},
		},
	}
	s := paramToSchema(p)
	if s["type"] != kindObject {
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
		Name: testParamTags,
		Type: ParamType{Kind: kindArray, ItemKind: kindString},
	}
	s := paramToSchema(p)
	items, _ := s["items"].(map[string]any)
	if items["type"] != kindString {
		t.Errorf("items = %v", items)
	}
}
