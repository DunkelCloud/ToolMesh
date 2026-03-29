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
