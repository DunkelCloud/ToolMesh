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
	"sort"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/toolindex"
)

// discover_tools detail tiers. "auto" picks a tier from the number of
// matched tools so a broad search degrades to a cheaper representation
// instead of flooding the caller's context with full signatures.
const (
	detailAuto     = "auto"
	detailFull     = "full"
	detailSummary  = "summary"
	detailNames    = "names"
	detailOverview = "overview"
)

// Auto-tier thresholds and output limits. Calibrated against a production
// instance with ~4,800 tools where full TypeScript declarations average
// ~530 bytes each: 608 matches ("netbox") render to ~320 KB — far beyond
// any sane context budget. The cap is a fail-safe applied to every tier.
const (
	discoverFullMax    = 25
	discoverSummaryMax = 250
	discoverNamesMax   = 2000
	discoverMaxBytes   = 50_000
	discoverQueryLimit = 25
	summaryDescMax     = 140
)

// autoDetail maps a result count to the output tier used when the caller
// did not request an explicit detail level.
func autoDetail(count int) string {
	switch {
	case count <= discoverFullMax:
		return detailFull
	case count <= discoverSummaryMax:
		return detailSummary
	case count <= discoverNamesMax:
		return detailNames
	default:
		return detailOverview
	}
}

// JSON Schema "type" keyword values, also reused as labels in debug_echo
// output. Centralized so they are referenced by constant rather than as
// repeated string literals across the package.
const (
	jsonTypeString  = "string"
	jsonTypeNumber  = "number"
	jsonTypeInteger = "integer"
	jsonTypeBoolean = "boolean"
	jsonTypeArray   = "array"
	jsonTypeObject  = "object"
	jsonTypeNull    = "null"
)

// CodeModeParser maintains a reverse lookup from sanitized JS names back to
// canonical tool names. Used by CodeRunner for name resolution and by
// GenerateToolDefinitions for discover_tools output.
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

// GenerateToolDefinitions creates TypeScript-like interface definitions for discover_tools.
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

// GenerateToolSummaries renders one line per tool: the JS-callable name and
// the first sentence of its description. Roughly 70 bytes per tool versus
// ~530 for a full declaration.
func GenerateToolSummaries(tools []backend.ToolDescriptor) string {
	var sb strings.Builder
	sb.WriteString("// ToolMesh tools — one-line summaries\n")
	for _, tool := range tools {
		fmt.Fprintf(&sb, "%s — %s\n", sanitizeName(tool.Name), firstSentence(tool.Description))
	}
	return sb.String()
}

// GenerateToolNames renders only the JS-callable tool names, one per line.
func GenerateToolNames(tools []backend.ToolDescriptor) string {
	var sb strings.Builder
	sb.WriteString("// ToolMesh tools — names only\n")
	for _, tool := range tools {
		sb.WriteString(sanitizeName(tool.Name))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// GenerateBackendOverview renders per-backend tool counts, largest first.
// Used when even a names-only list would flood the caller's context.
func GenerateBackendOverview(tools []backend.ToolDescriptor) string {
	counts := make(map[string]int)
	for _, tool := range tools {
		counts[tool.Backend]++
	}

	type entry struct {
		backend string
		count   int
	}
	entries := make([]entry, 0, len(counts))
	for b, c := range counts {
		entries = append(entries, entry{backend: b, count: c})
	}
	sort.Slice(entries, func(a, b int) bool {
		if entries[a].count != entries[b].count {
			return entries[a].count > entries[b].count
		}
		return entries[a].backend < entries[b].backend
	})

	var sb strings.Builder
	sb.WriteString("// ToolMesh tools — per-backend overview\n")
	for _, e := range entries {
		fmt.Fprintf(&sb, "%s — %d tools\n", e.backend, e.count)
	}
	return sb.String()
}

// firstSentence returns the text up to the first sentence boundary,
// truncated to summaryDescMax bytes on a rune boundary.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	for _, sep := range []string{". ", "! ", "? ", "\n"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i+1]
			break
		}
	}
	if len(s) > summaryDescMax {
		cut := summaryDescMax
		for cut > 0 && !isRuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return strings.TrimSpace(s)
}

// isRuneStart reports whether b can begin a UTF-8 encoded rune.
func isRuneStart(b byte) bool {
	return b&0xC0 != 0x80
}

// descriptorDoc converts a tool descriptor into a searchable toolindex doc
// under the given display name. Parameter names from the input schema are
// indexed as extra terms so queries like "rack_id" find the right tool.
func descriptorDoc(t backend.ToolDescriptor, name string) toolindex.Doc {
	doc := toolindex.Doc{Name: name, Description: t.Description}
	if props, ok := t.InputSchema[schemaKeyProperties].(map[string]any); ok {
		for param := range props {
			doc.Extra = append(doc.Extra, param)
		}
	}
	return doc
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
				case jsonTypeString:
					tsType = jsonTypeString
				case jsonTypeNumber, jsonTypeInteger:
					tsType = jsonTypeNumber
				case jsonTypeBoolean:
					tsType = jsonTypeBoolean
				case jsonTypeArray:
					tsType = "any[]"
				case jsonTypeObject:
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
