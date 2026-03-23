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

func TestToInputSchema_BasicTypes(t *testing.T) {
	td := ToolDef{
		Name: "test",
		Params: []ParamDef{
			{Name: "q", Type: ParamType{Kind: "string"}, Required: true},
			{Name: "n", Type: ParamType{Kind: "number"}, Required: true},
			{Name: "b", Type: ParamType{Kind: "boolean"}, Required: false},
		},
	}

	schema := td.ToInputSchema()

	props, _ := schema["properties"].(map[string]any)
	if props["q"].(map[string]any)["type"] != "string" {
		t.Error("q should be string")
	}
	if props["n"].(map[string]any)["type"] != "number" {
		t.Error("n should be number")
	}
	if props["b"].(map[string]any)["type"] != "boolean" {
		t.Error("b should be boolean")
	}

	required, _ := schema["required"].([]any)
	if len(required) != 2 {
		t.Errorf("expected 2 required, got %d", len(required))
	}
}

func TestToInputSchema_Enum(t *testing.T) {
	td := ToolDef{
		Params: []ParamDef{
			{Name: "dir", Type: ParamType{Kind: "string"}, Enum: []string{"up", "down"}, Required: true},
		},
	}

	schema := td.ToInputSchema()
	props, _ := schema["properties"].(map[string]any)
	dir := props["dir"].(map[string]any)

	if dir["type"] != "string" {
		t.Error("enum should be string type")
	}
	enum, _ := dir["enum"].([]any)
	if len(enum) != 2 {
		t.Errorf("expected 2 enum values, got %d", len(enum))
	}
}

func TestToInputSchema_Array(t *testing.T) {
	td := ToolDef{
		Params: []ParamDef{
			{Name: "tags", Type: ParamType{Kind: "array", ItemKind: "string"}, Required: true},
		},
	}

	schema := td.ToInputSchema()
	props, _ := schema["properties"].(map[string]any)
	tags := props["tags"].(map[string]any)

	if tags["type"] != "array" {
		t.Error("should be array type")
	}
	items, _ := tags["items"].(map[string]any)
	if items["type"] != "string" {
		t.Error("items should be string")
	}
}

func TestToInputSchema_NoParams(t *testing.T) {
	td := ToolDef{Name: "test"}
	schema := td.ToInputSchema()
	if schema["type"] != "object" {
		t.Error("should be object")
	}
}

func TestToolDefFromSchema_Roundtrip(t *testing.T) {
	original := ToolDef{
		Name:        "search",
		Description: "Search things",
		Params: []ParamDef{
			{Name: "query", Type: ParamType{Kind: "string"}, Required: true, Description: "The query"},
			{Name: "limit", Type: ParamType{Kind: "number"}, Required: false, Description: "Max results"},
		},
	}

	schema := original.ToInputSchema()
	reconstructed := ToolDefFromSchema("search", "Search things", schema)

	if reconstructed.Name != original.Name {
		t.Errorf("name = %q, want %q", reconstructed.Name, original.Name)
	}
	if len(reconstructed.Params) != 2 {
		t.Fatalf("expected 2 params, got %d", len(reconstructed.Params))
	}

	// Find the "query" param (order may differ in map iteration)
	var queryParam *ParamDef
	for i := range reconstructed.Params {
		if reconstructed.Params[i].Name == "query" {
			queryParam = &reconstructed.Params[i]
			break
		}
	}
	if queryParam == nil {
		t.Fatal("query param not found")
	}
	if queryParam.Type.Kind != "string" {
		t.Errorf("query type = %q, want %q", queryParam.Type.Kind, "string")
	}
	if !queryParam.Required {
		t.Error("query should be required")
	}
}
