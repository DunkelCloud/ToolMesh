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

// Package backend defines the core abstractions for tool execution backends.
package backend

import "context"

// ToolDescriptor describes a single tool exposed by a backend.
type ToolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Backend     string         `json:"backend"` // e.g. "mcp:memorizer", "mcp:brave"
	// Access is the DADL-declared access classification for this tool.
	// Well-known values: "read", "write", "admin", "dangerous"; custom
	// strings are allowed. Empty means unclassified (e.g. tools sourced
	// from upstream MCP servers that do not provide an access tag).
	Access string `json:"access,omitempty"`
}

// ToolResult holds the result of a tool execution.
type ToolResult struct {
	Content  []any          `json:"content"` // MCP content blocks
	IsError  bool           `json:"isError"`
	Metadata map[string]any `json:"metadata"` // latency, backend name, etc.
}

// ToolBackend is the interface that all tool execution backends must implement.
type ToolBackend interface {
	// Execute runs a tool by name with the given parameters.
	Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error)

	// ListTools returns all tools available from this backend.
	ListTools(ctx context.Context) ([]ToolDescriptor, error)

	// Healthy checks if the backend is reachable and functional.
	Healthy(ctx context.Context) error
}

// BackendSummarizer provides backend metadata for MCP tool description enrichment.
// Backends that implement this interface contribute their name and hint to the
// dynamic tool descriptions shown to LLMs.
type BackendSummarizer interface {
	BackendSummaries() []BackendInfo
}

// ToolMetadataLookup is an optional interface for backends that can resolve
// a single tool's descriptor by name without iterating ListTools. Used by
// the executor to enrich the gate context and audit trail with the tool's
// access classification on every call. Backends that do not implement this
// interface simply yield an empty Access on the gate context — policies
// that depend on the value should treat empty as "unclassified".
type ToolMetadataLookup interface {
	// LookupTool returns the descriptor for the given tool name. The bool
	// is false if the backend does not own this tool. Implementations must
	// be safe for concurrent use.
	LookupTool(toolName string) (ToolDescriptor, bool)
}

// Promotion is the structured form of a single tool surfaced as a direct
// top-level MCP tool. Descriptor.Name is the bare tool name as it should
// appear on the MCP wire by default; Canonical is the "<backend>_<tool>"
// form used by the composite to dispatch the call to the owning backend.
//
// Keeping both names explicit (instead of deriving Canonical from
// Descriptor.Name) is necessary because backend names can themselves
// contain underscores — a heuristic split would be ambiguous for backends
// like "web_search" that also expose a tool named "web_search".
type Promotion struct {
	Descriptor ToolDescriptor
	Canonical  string
}

// ToolPromoter is implemented by backends that opt to expose specific tools
// as direct top-level MCP tools (in addition to discover_tools / execute_code).
//
// The exposed surface is intended for high-frequency tools (web_search,
// fetch_url, ...) where forcing an LLM through discover_tools + execute_code
// burns context and round-trips for no benefit. Tools not listed here remain
// reachable only via discover_tools, keeping the default surface minimal.
//
// Implementations resolve the listed names lazily against current backend
// state on every call so hot-reload / late MCP discovery work transparently.
// A name that does not (yet) match any known tool is silently skipped here —
// backends are expected to log a startup warning when applicable.
type ToolPromoter interface {
	// PromotedTools returns one Promotion per advertised tool. May be nil.
	PromotedTools() []Promotion
}

// ToolAliasResolver maps a public promoted tool name to its routing
// canonical "<backend>_<tool>" form. Returns the input unchanged when no
// alias is registered for it. Used by the MCP handler to canonicalize tool
// names before passing them through the executor / authz / audit pipeline,
// so internal observability always references the same key regardless of
// whether the caller used the bare or prefixed form.
type ToolAliasResolver interface {
	ResolveAlias(name string) string
}
