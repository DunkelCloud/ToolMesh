// Package backend defines the core abstractions for tool execution backends.
package backend

import "context"

// ToolDescriptor describes a single tool exposed by a backend.
type ToolDescriptor struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
	Backend     string         `json:"backend"` // e.g. "mcp:memorizer", "mcp:brave"
}

// ToolResult holds the result of a tool execution.
type ToolResult struct {
	Content  []any          `json:"content"`  // MCP content blocks
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
