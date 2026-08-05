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

	// Emit type aliases for every named type a returns declaration
	// references, transitively (spec §6.5). Aliases (not interfaces) stay
	// valid for non-object shapes.
	referenced := make(map[string]bool)
	for _, tool := range b.Tools {
		collectReferencedTypes(tool.Returns, b.Types, referenced)
	}
	typeNames := make([]string, 0, len(referenced))
	for name := range referenced {
		typeNames = append(typeNames, name)
	}
	sort.Strings(typeNames)
	for _, name := range typeNames {
		ts, err := schemaToTS(b.Types[name], b.Types, 0)
		if err != nil {
			continue // validated at load; skip defensively for hand-built specs
		}
		fmt.Fprintf(&sb, "  type %s = %s;\n", name, ts)
	}
	if len(typeNames) > 0 {
		sb.WriteString("\n")
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

		writeToolJSDoc(&sb, &tool)

		// Build parameter type and result type
		params := buildParamType(tool)
		returnsTS, err := ReturnsToTS(tool.Returns, b.Types)
		if err != nil {
			returnsTS = tsAny // validated at load; defensive for hand-built specs
		}
		fmt.Fprintf(&sb, "  function %s(params: { %s }): Promise<%s>;\n\n", fullName, params, returnsTS)
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

// writeToolJSDoc renders the JSDoc block for a tool: description, the
// spec §6.7 @deprecated tag (with reason and successor), and the
// informational depends_on hint (spec §6).
func writeToolJSDoc(sb *strings.Builder, tool *ToolDef) {
	var lines []string
	if tool.Description != "" {
		lines = append(lines, tool.Description)
	}
	reason, deprecated := tool.DeprecationInfo()
	if deprecated {
		tag := "@deprecated"
		if reason != "" {
			tag += " " + reason
		}
		if tool.ReplacedBy != "" {
			tag += " — use " + tool.ReplacedBy + " instead"
		}
		lines = append(lines, tag)
	} else if tool.ReplacedBy != "" {
		lines = append(lines, "Prefer "+tool.ReplacedBy+".")
	}
	if len(tool.DependsOn) > 0 {
		lines = append(lines, "Call first: "+strings.Join(tool.DependsOn, ", "))
	}

	switch len(lines) {
	case 0:
	case 1:
		fmt.Fprintf(sb, "  /** %s */\n", lines[0])
	default:
		sb.WriteString("  /**\n")
		for _, line := range lines {
			fmt.Fprintf(sb, "   * %s\n", line)
		}
		sb.WriteString("   */\n")
	}
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
		if def.Required || def.In == paramInPath {
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

// JSON Schema type strings recognized by DADL → TypeScript generation.
const (
	jsTypeString  = "string"
	jsTypeInteger = "integer"
	jsTypeNumber  = "number"
	jsTypeBoolean = "boolean"
	jsTypeArray   = "array"
	jsTypeObject  = "object"
)

// TypeScript type literals shared by the generators.
const (
	tsAny       = "any"
	tsAnyArray  = "any[]"
	tsRecordAny = "Record<string, any>"
)

// JSON Schema keys walked by the returns renderer.
const (
	schemaKeyType       = "type"
	schemaKeyItems      = "items"
	schemaKeyRequired   = "required"
	schemaKeyProperties = "properties"
)

func dadlTypeToTS(t string) string {
	switch t {
	case jsTypeString:
		return jsTypeString
	case jsTypeInteger, jsTypeNumber:
		return jsTypeNumber
	case jsTypeBoolean:
		return jsTypeBoolean
	case jsTypeArray:
		return tsAnyArray
	case jsTypeObject:
		return tsRecordAny
	case ParamTypeFileURL, "file":
		// file_url is a URL string; the legacy "file" type is a local path string.
		return jsTypeString
	default:
		return tsAny
	}
}
