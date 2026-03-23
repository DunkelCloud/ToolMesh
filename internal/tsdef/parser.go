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

// Package tsdef parses TypeScript interface files as canonical tool definitions
// and provides JSON Schema generation and LLM type coercion.
package tsdef

import (
	"regexp"
	"strings"
)

// ToolDef represents a tool definition parsed from a TypeScript file.
type ToolDef struct {
	Name        string
	Description string
	Params      []ParamDef
	Namespace   string // optional, from "export namespace X { ... }"
	SourceFile  string
}

// ParamDef represents a single parameter in a tool definition.
type ParamDef struct {
	Name        string
	Description string
	Type        ParamType
	Required    bool
	Enum        []string // for "a" | "b" style unions
}

// ParamType describes the type of a parameter.
type ParamType struct {
	Kind       string     // "string", "number", "boolean", "array", "object", "any"
	ItemKind   string     // for arrays: element type
	Properties []ParamDef // for inline objects: nested properties
}

var (
	funcPattern    = regexp.MustCompile(`(?s)/\*\*(.*?)\*/\s*export\s+function\s+(\w+)\s*\((.*?)\)\s*:\s*Promise<any>`)
	jsdocPattern   = regexp.MustCompile(`/\*\*\s*(.*?)\s*\*/`)
	propPattern    = regexp.MustCompile(`(?s)(?:/\*\*\s*(.*?)\s*\*/\s*)?(\w+)(\?)?:\s*([^;,]+)`)
	enumValPattern = regexp.MustCompile(`"([^"]+)"`)
)

// ParseSource parses TypeScript source code and returns tool definitions.
func ParseSource(source, filename string) ([]ToolDef, error) {
	var defs []ToolDef

	matches := funcPattern.FindAllStringSubmatch(source, -1)
	for _, m := range matches {
		jsdoc := cleanJSDoc(m[1])
		name := m[2]
		paramsBlock := strings.TrimSpace(m[3])

		var params []ParamDef
		if paramsBlock != "" {
			params = parseParamsBlock(paramsBlock)
		}

		defs = append(defs, ToolDef{
			Name:        name,
			Description: jsdoc,
			Params:      params,
			SourceFile:  filename,
		})
	}

	return defs, nil
}

// parseParamsBlock parses "params: { ... }" or "params: Type" blocks.
func parseParamsBlock(block string) []ParamDef {
	// Strip outer "params: { ... }" wrapper
	block = strings.TrimSpace(block)
	if strings.HasPrefix(block, "params:") {
		block = strings.TrimPrefix(block, "params:")
		block = strings.TrimSpace(block)
	}
	if strings.HasPrefix(block, "{") && strings.HasSuffix(block, "}") {
		block = block[1 : len(block)-1]
	}

	return parseProperties(block)
}

// parseProperties parses property definitions from an object body.
func parseProperties(body string) []ParamDef {
	var params []ParamDef

	// Split into individual property entries by semicolons
	entries := splitBySemicolon(body)

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		m := propPattern.FindStringSubmatch(entry)
		if m == nil {
			continue
		}

		desc := cleanJSDoc(m[1])
		name := m[2]
		optional := m[3] == "?"
		typeStr := strings.TrimSpace(m[4])

		param := ParamDef{
			Name:        name,
			Description: desc,
			Required:    !optional,
			Type:        parseType(typeStr),
		}

		// Check for string literal union enums
		if strings.Contains(typeStr, "|") && strings.Contains(typeStr, "\"") {
			vals := enumValPattern.FindAllStringSubmatch(typeStr, -1)
			for _, v := range vals {
				param.Enum = append(param.Enum, v[1])
			}
			param.Type.Kind = "string"
		}

		params = append(params, param)
	}

	return params
}

// parseType converts a TypeScript type string to a ParamType.
func parseType(ts string) ParamType {
	ts = strings.TrimSpace(ts)

	switch ts {
	case "string":
		return ParamType{Kind: "string"}
	case "number":
		return ParamType{Kind: "number"}
	case "boolean":
		return ParamType{Kind: "boolean"}
	case "any":
		return ParamType{Kind: "any"}
	case "string[]":
		return ParamType{Kind: "array", ItemKind: "string"}
	case "number[]":
		return ParamType{Kind: "array", ItemKind: "number"}
	case "boolean[]":
		return ParamType{Kind: "array", ItemKind: "boolean"}
	case "any[]":
		return ParamType{Kind: "array", ItemKind: "any"}
	case "Record<string, any>":
		return ParamType{Kind: "object"}
	}

	// Inline object type: { key: type; ... }
	if strings.HasPrefix(ts, "{") && strings.HasSuffix(ts, "}") {
		inner := ts[1 : len(ts)-1]
		return ParamType{
			Kind:       "object",
			Properties: parseProperties(inner),
		}
	}

	// String literal union: "a" | "b" | "c"
	if strings.Contains(ts, "|") && strings.Contains(ts, "\"") {
		return ParamType{Kind: "string"}
	}

	return ParamType{Kind: "any"}
}

// splitBySemicolon splits a string by semicolons at depth 0.
func splitBySemicolon(s string) []string {
	var parts []string
	var current strings.Builder
	depth := 0

	for _, ch := range s {
		switch ch {
		case '{':
			depth++
			current.WriteRune(ch)
		case '}':
			depth--
			current.WriteRune(ch)
		case ';':
			if depth == 0 {
				parts = append(parts, current.String())
				current.Reset()
			} else {
				current.WriteRune(ch)
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		parts = append(parts, current.String())
	}
	return parts
}

// cleanJSDoc removes JSDoc comment formatting (* prefix, whitespace).
func cleanJSDoc(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	var cleaned []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "* ")
		line = strings.TrimPrefix(line, "*")
		line = strings.TrimSpace(line)
		if line != "" {
			cleaned = append(cleaned, line)
		}
	}
	return strings.Join(cleaned, " ")
}
