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
	"fmt"
	"sort"
	"strings"
)

// GenerateTypeScript produces TypeScript interface definitions from a DADL Spec.
// This is used for Code Mode: the LLM sees these interfaces and writes typed code.
// Output format: a declare namespace block with method signatures.
func GenerateTypeScript(spec *Spec) string {
	var sb strings.Builder

	b := &spec.Backend
	if b.Description != "" {
		fmt.Fprintf(&sb, "  // %s — %s\n\n", b.Name, b.Description)
	}

	// Sort tool names for deterministic output
	names := make([]string, 0, len(b.Tools))
	for name := range b.Tools {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		tool := b.Tools[name]
		fullName := b.Name + "_" + name

		// JSDoc comment
		if tool.Description != "" {
			fmt.Fprintf(&sb, "  /** %s */\n", tool.Description)
		}

		// Build parameter type
		params := buildParamType(tool)
		fmt.Fprintf(&sb, "  function %s(params: { %s }): Promise<any>;\n\n", fullName, params)
	}

	// Composites appear identically to primitive tools
	compNames := make([]string, 0, len(b.Composites))
	for name := range b.Composites {
		compNames = append(compNames, name)
	}
	sort.Strings(compNames)

	for _, name := range compNames {
		comp := b.Composites[name]
		fullName := b.Name + "_" + name

		if comp.Description != "" {
			fmt.Fprintf(&sb, "  /** %s */\n", comp.Description)
		}

		params := buildCompositeParamType(comp)
		fmt.Fprintf(&sb, "  function %s(params: { %s }): Promise<any>;\n\n", fullName, params)
	}

	return sb.String()
}

func buildCompositeParamType(comp CompositeDef) string {
	if len(comp.Params) == 0 {
		return ""
	}

	type paramEntry struct {
		name string
		def  ParamDef
	}
	var required, optional []paramEntry
	for name, def := range comp.Params {
		if def.Required {
			required = append(required, paramEntry{name, def})
		} else {
			optional = append(optional, paramEntry{name, def})
		}
	}
	sort.Slice(required, func(i, j int) bool { return required[i].name < required[j].name })
	sort.Slice(optional, func(i, j int) bool { return optional[i].name < optional[j].name })

	var parts []string
	for _, p := range required {
		parts = append(parts, fmt.Sprintf("%s: %s", p.name, dadlTypeToTS(p.def.Type)))
	}
	for _, p := range optional {
		parts = append(parts, fmt.Sprintf("%s?: %s", p.name, dadlTypeToTS(p.def.Type)))
	}

	return strings.Join(parts, ", ")
}

func buildParamType(tool ToolDef) string {
	if len(tool.Params) == 0 {
		return ""
	}

	// Sort params: required first, then optional
	type paramEntry struct {
		name string
		def  ParamDef
	}
	var required, optional []paramEntry
	for name, def := range tool.Params {
		if def.Required || def.In == "path" {
			required = append(required, paramEntry{name, def})
		} else {
			optional = append(optional, paramEntry{name, def})
		}
	}
	sort.Slice(required, func(i, j int) bool { return required[i].name < required[j].name })
	sort.Slice(optional, func(i, j int) bool { return optional[i].name < optional[j].name })

	var parts []string
	for _, p := range required {
		parts = append(parts, fmt.Sprintf("%s: %s", p.name, dadlTypeToTS(p.def.Type)))
	}
	for _, p := range optional {
		parts = append(parts, fmt.Sprintf("%s?: %s", p.name, dadlTypeToTS(p.def.Type)))
	}

	return strings.Join(parts, ", ")
}

func dadlTypeToTS(t string) string {
	switch t {
	case "string":
		return "string"
	case "integer", "number":
		return "number"
	case "boolean":
		return "boolean"
	case "array":
		return "any[]"
	case "object":
		return "Record<string, any>"
	default:
		return "any"
	}
}
