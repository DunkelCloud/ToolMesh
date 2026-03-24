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
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/dop251/goja"
)

// CodeModeParser extracts tool calls from JavaScript-like code.
// It parses the AST structure but does not execute the JavaScript.
// It maintains a reverse lookup from sanitized JS names back to canonical tool names.
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

// ParsedToolCall represents a tool call extracted from code.
type ParsedToolCall struct {
	ToolName string
	Params   map[string]any
}

// toolCallPattern matches expressions like: toolmesh.toolName("arg", { key: value })
// or: await toolmesh.toolName("arg", { key: "value" })
var toolCallPattern = regexp.MustCompile(`(?:await\s+)?toolmesh\.(\w+)\(([^)]*)\)`)

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

// ParseCode extracts tool calls from JavaScript code.
func (p *CodeModeParser) ParseCode(code string) ([]ParsedToolCall, error) {
	matches := toolCallPattern.FindAllStringSubmatch(code, -1)
	if len(matches) == 0 {
		return nil, fmt.Errorf("no tool calls found in code")
	}

	calls := make([]ParsedToolCall, 0, len(matches))
	for _, match := range matches {
		toolName := match[1]
		argsStr := strings.TrimSpace(match[2])

		params, err := parseArgs(argsStr)
		if err != nil {
			return nil, fmt.Errorf("parse args for %s: %w", toolName, err)
		}

		// Reverse-map sanitized JS name back to canonical tool name
		if canonical, ok := p.nameMap[toolName]; ok {
			toolName = canonical
		}

		calls = append(calls, ParsedToolCall{
			ToolName: toolName,
			Params:   params,
		})
	}

	return calls, nil
}

// parseArgs attempts to parse function arguments.
// Supports: "string", number, { json objects }, and JavaScript object literals
// with unquoted keys (e.g. { query: "hello", top_k: 5 }).
func parseArgs(argsStr string) (map[string]any, error) { //nolint:unparam // error kept for future use
	if argsStr == "" {
		return map[string]any{}, nil
	}

	argsStr = strings.TrimSpace(argsStr)

	// Try strict JSON first (fastest path)
	if strings.HasPrefix(argsStr, "{") {
		var params map[string]any
		if err := json.Unmarshal([]byte(argsStr), &params); err == nil {
			return params, nil
		}
		// JSON failed — try JavaScript object literal via goja
		if parsed, err := parseJSObject(argsStr); err == nil {
			return parsed, nil
		}
	}

	// Split by commas (respecting braces and quotes)
	params := make(map[string]any)
	args := splitArgs(argsStr)

	for i, arg := range args {
		arg = strings.TrimSpace(arg)

		// String literal
		if (strings.HasPrefix(arg, "\"") && strings.HasSuffix(arg, "\"")) ||
			(strings.HasPrefix(arg, "'") && strings.HasSuffix(arg, "'")) {
			params[fmt.Sprintf("arg%d", i)] = arg[1 : len(arg)-1]
			continue
		}

		// JSON or JS object
		if strings.HasPrefix(arg, "{") {
			var obj map[string]any
			if err := json.Unmarshal([]byte(arg), &obj); err == nil {
				for k, v := range obj {
					params[k] = v
				}
				continue
			}
			if obj, err := parseJSObject(arg); err == nil {
				for k, v := range obj {
					params[k] = v
				}
				continue
			}
		}

		// Number or other literal
		params[fmt.Sprintf("arg%d", i)] = arg
	}

	return params, nil
}

// parseJSObject evaluates a JavaScript object literal via goja and returns
// the resulting map. This handles unquoted keys, trailing commas, and other
// JS syntax that is not valid JSON.
func parseJSObject(s string) (map[string]any, error) {
	vm := goja.New()
	v, err := vm.RunString("(" + s + ")")
	if err != nil {
		return nil, fmt.Errorf("js eval: %w", err)
	}
	exported := v.Export()
	m, ok := exported.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not an object: %T", exported)
	}
	return m, nil
}

// splitArgs splits a comma-separated argument string respecting nested braces and quotes.
func splitArgs(s string) []string {
	var args []string
	var current strings.Builder
	depth := 0
	inQuote := rune(0)

	for _, ch := range s {
		switch {
		case inQuote != 0:
			current.WriteRune(ch)
			if ch == inQuote {
				inQuote = 0
			}
		case ch == '"' || ch == '\'':
			current.WriteRune(ch)
			inQuote = ch
		case ch == '{' || ch == '[':
			current.WriteRune(ch)
			depth++
		case ch == '}' || ch == ']':
			current.WriteRune(ch)
			depth--
		case ch == ',' && depth == 0:
			args = append(args, current.String())
			current.Reset()
		default:
			current.WriteRune(ch)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
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
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
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

	return "params: { " + strings.Join(parts, ", ") + " }"
}

func sanitizeName(name string) string {
	// Replace colons and other invalid chars with underscores
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, name)
}
