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

package backend

// reservedClientToolNames is the set of bare tool names that some upstream
// LLM clients reserve for their own built-in tool types. When a backend's
// expose_tools entry would publish a tool under one of these names at the
// MCP root, the composite layer falls back to the canonical "<backend>_<tool>"
// form so the client does not reject the entire tools/list response.
//
// Background: OpenAI's Responses API exposes a small set of built-in tool
// types (web_search, code_interpreter, file_search, computer_use) that
// occupy the function-calling namespace. An MCP tool advertised with the
// same bare name collides with the built-in and the ChatGPT MCP connector
// rejects it as "Invalid MCP tool schema" — the error message is misleading
// (the schema itself is fine), but the effect is hard: the connector
// abandons the entire tools/list and surfaces a generic
// "connection to toolmesh failed" error to the user.
//
// Anthropic / Claude clients do not reserve these names — their built-ins
// live in a separate CamelCase namespace (WebSearch, WebFetch, …) or carry
// versioned type identifiers (bash_20250124, …). The fallback therefore
// trades a slightly less elegant tool name in OpenAI clients for guaranteed
// compatibility across all known MCP consumers.
//
// Maintenance: extend this set when an upstream client adds a new built-in
// tool type that occupies a name an operator might plausibly choose via
// expose_tools. The list ships with the toolmesh binary so every operator
// inherits the update on the next release — no per-deployment config.
// Names of upstream-client built-in tool types currently reserved.
// Kept as named constants so callers (especially tests) can reference
// them by symbol instead of duplicated string literals.
const (
	reservedWebSearch       = "web_search"
	reservedCodeInterpreter = "code_interpreter"
	reservedFileSearch      = "file_search"
	reservedComputerUse     = "computer_use"
)

var reservedClientToolNames = map[string]struct{}{
	reservedWebSearch:       {},
	reservedCodeInterpreter: {},
	reservedFileSearch:      {},
	reservedComputerUse:     {},
}

// IsReservedClientToolName reports whether name collides with a built-in
// tool type reserved by a known upstream LLM client. Used by the composite
// backend to decide when a bare expose_tools alias must fall back to the
// canonical "<backend>_<tool>" form for the public MCP surface.
func IsReservedClientToolName(name string) bool {
	_, ok := reservedClientToolNames[name]
	return ok
}
