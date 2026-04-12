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
	"fmt"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// CodeModeParser maintains a reverse lookup from sanitized JS names back to
// canonical tool names. Used by CodeRunner for name resolution and by
// GenerateToolDefinitions for list_tools output.
type CodeModeParser struct {
	// nameMap maps sanitized names (e.g. "memorizer_knowledge_status")
	// back to canonical tool names (e.g. "memorizer:knowledge_status").
	nameMap map[string]string
}

// NewCodeModeParser creates a parser with a reverse name lookup built from
// the registered tool descriptors.
func NewCodeModeParser(tools []backend.ToolDescriptor) *CodeModeParser {
	m := make(map[string]string, len(tools))
	for _, t := range tools {
		m[sanitizeName(t.Name)] = t.Name
	}
	return &CodeModeParser{nameMap: m}
}

// GenerateToolDefinitions creates TypeScript-like interface definitions for list_tools.
func GenerateToolDefinitions(tools []backend.ToolDescriptor) string {
	var sb strings.Builder
	sb.WriteString("// Available ToolMesh tools\n")
	sb.WriteString("declare namespace toolmesh {\n")

	for _, tool := range tools {
		fmt.Fprintf(&sb, "  /** %s */\n", tool.Description)

		// Generate parameter signature from input schema
		params := schemaToTypeScript(tool.InputSchema)
		fmt.Fprintf(&sb, "  function %s(%s): Promise<any>;\n\n", sanitizeName(tool.Name), params)
	}

	sb.WriteString("}\n")
	return sb.String()
}

func schemaToTypeScript(schema map[string]any) string {
	if schema == nil {
		return ""
	}

	props, ok := schema["properties"].(map[string]any)
	if !ok {
		return "params?: Record<string, any>"
	}

	required := make(map[string]bool)
	switch req := schema["required"].(type) {
	case []any:
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	case []string:
		for _, s := range req {
			required[s] = true
		}
	}

	parts := make([]string, 0, len(props))
	for name, prop := range props {
		tsType := "any"
		if propMap, ok := prop.(map[string]any); ok {
			if t, ok := propMap["type"].(string); ok {
				switch t {
				case "string":
					tsType = "string"
				case "number", "integer":
					tsType = "number"
				case "boolean":
					tsType = "boolean"
				case "array":
					tsType = "any[]"
				case "object":
					tsType = "Record<string, any>"
				}
			}
		}

		opt := "?"
		if required[name] {
			opt = ""
		}
		parts = append(parts, fmt.Sprintf("%s%s: %s", name, opt, tsType))
	}

	if len(parts) == 0 {
		return ""
	}

	if len(parts) == 1 {
		return "params: { " + parts[0] + " }"
	}

	return "params: {\n    " + strings.Join(parts, ",\n    ") + "\n  }"
}

func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
}
