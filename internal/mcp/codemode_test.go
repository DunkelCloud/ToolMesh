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

package mcp

import (
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

func TestGenerateToolDefinitions(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{
			Name:        "search",
			Description: "Search for things",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string"},
					"limit": map[string]any{"type": "integer"},
				},
				"required": []any{"query"},
			},
		},
		{
			Name:        "memorizer:store",
			Description: "Store data",
		},
	}

	result := GenerateToolDefinitions(tools)

	if !strings.Contains(result, "declare namespace toolmesh") {
		t.Error("expected namespace declaration")
	}
	if !strings.Contains(result, "function search") {
		t.Error("expected search function")
	}
	if !strings.Contains(result, "function memorizer_store") {
		t.Error("expected sanitized memorizer_store function")
	}
	if !strings.Contains(result, "Search for things") {
		t.Error("expected description in JSDoc comment")
	}
	if !strings.Contains(result, "Promise<any>") {
		t.Error("expected Promise<any> return type")
	}
}

func TestSchemaToTypeScript_RequiredStringSlice(t *testing.T) {
	// Regression: buildInputSchema produces []string for the required array,
	// but schemaToTypeScript only handled []any. This caused all params to
	// appear optional in list_tools output.
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"query": map[string]any{"type": "string"},
			"limit": map[string]any{"type": "integer"},
		},
		"required": []string{"query"},
	}

	got := schemaToTypeScript(schema)

	if !strings.Contains(got, "query: string") {
		t.Errorf("query should be required (no ?), got:\n%s", got)
	}
	if strings.Contains(got, "query?") {
		t.Errorf("query must not be optional, got:\n%s", got)
	}
	if !strings.Contains(got, "limit?: number") {
		t.Errorf("limit should be optional, got:\n%s", got)
	}
}

func TestSchemaToTypeScript_RequiredAnySlice(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"page":  map[string]any{"type": "string"},
			"text":  map[string]any{"type": "string"},
			"minor": map[string]any{"type": "boolean"},
		},
		"required": []any{"page", "text"},
	}

	got := schemaToTypeScript(schema)

	if strings.Contains(got, "page?") {
		t.Errorf("page must not be optional, got:\n%s", got)
	}
	if strings.Contains(got, "text?") {
		t.Errorf("text must not be optional, got:\n%s", got)
	}
	if !strings.Contains(got, "minor?: boolean") {
		t.Errorf("minor should be optional, got:\n%s", got)
	}
}

func TestSchemaToTypeScript_NoRequired(t *testing.T) {
	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"limit": map[string]any{"type": "integer"},
		},
	}

	got := schemaToTypeScript(schema)

	if !strings.Contains(got, "limit?: number") {
		t.Errorf("limit should be optional when no required field, got:\n%s", got)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"camelCase", "camelCase"},
		{"with:colon", "with_colon"},
		{"with-dash", "with_dash"},
		{"with.dot", "with_dot"},
		{"under_score", "under_score"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeName(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
