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
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
)

// Handler processes incoming MCP tool calls and routes them through the executor.
type Handler struct {
	executor   *executor.Executor
	backend    backend.ToolBackend
	codeParser *CodeModeParser // kept for GenerateToolDefinitions / list_tools
	codeRunner *CodeRunner
	coercer    *tsdef.Coercer
	rawTS      string // raw TypeScript content for built-in tools
	logger     *slog.Logger
}

// NewHandler creates a new MCP tool call handler.
func NewHandler(exec *executor.Executor, back backend.ToolBackend, coercer *tsdef.Coercer, rawTS string, logger *slog.Logger) *Handler {
	// Build the code mode parser with reverse name lookup from all registered tools
	tools, _ := back.ListTools(context.Background())
	parser := NewCodeModeParser(tools)
	for sanitized, canonical := range parser.nameMap {
		logger.Debug("codeParser nameMap entry", "sanitized", sanitized, "canonical", canonical)
	}
	logger.Info("codeParser initialized", "nameMapSize", len(parser.nameMap), "toolCount", len(tools))

	runner := NewCodeRunner(parser.nameMap, exec, coercer, logger)

	return &Handler{
		executor:   exec,
		backend:    back,
		codeParser: parser,
		codeRunner: runner,
		coercer:    coercer,
		rawTS:      rawTS,
		logger:     logger,
	}
}

// HandleToolCall processes a single tool call through the execution pipeline.
func (h *Handler) HandleToolCall(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	h.logger.InfoContext(ctx, "handling tool call", "tool", toolName)
	h.logger.DebugContext(ctx, "tool call params", "tool", toolName, "params", params)

	switch toolName {
	case "list_tools":
		return h.handleListTools(ctx, params)
	case "execute_code":
		return h.handleExecuteCode(ctx, params)
	default:
		// Apply type coercion before execution
		if h.coercer != nil {
			coerced, err := h.coercer.Coerce(toolName, params)
			if err != nil {
				h.logger.DebugContext(ctx, "coercion failed", "tool", toolName, "error", err)
				return &backend.ToolResult{
					IsError: true,
					Content: []any{map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Parameter coercion failed: %s", err),
					}},
				}, nil
			}
			if fmt.Sprintf("%v", coerced) != fmt.Sprintf("%v", params) {
				h.logger.DebugContext(ctx, "params after coercion", "tool", toolName, "coerced", coerced)
			}
			params = coerced
		}

		result, err := h.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
			ToolName: toolName,
			Params:   params,
		})
		if err != nil {
			h.logger.DebugContext(ctx, "tool execution error", "tool", toolName, "error", err)
			return nil, err
		}
		h.logger.DebugContext(ctx, "tool execution result", "tool", toolName, "isError", result.IsError)
		return result, nil
	}
}

func (h *Handler) handleListTools(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
	patternStr, _ := params["pattern"].(string)
	if patternStr == "" {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "Missing required parameter: pattern (regex to filter tool names, e.g. \"github\" or \".*\" for all)",
			}},
		}, nil
	}

	re, err := regexp.Compile("(?i)" + patternStr)
	if err != nil {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": fmt.Sprintf("Invalid regex pattern %q: %s", patternStr, err),
			}},
		}, nil
	}

	tools, err := h.backend.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	// Filter tools by pattern (matched against name and description)
	filtered := make([]backend.ToolDescriptor, 0, len(tools))
	for _, t := range tools {
		if re.MatchString(t.Name) || re.MatchString(t.Description) {
			filtered = append(filtered, t)
		}
	}

	// Include raw TypeScript for built-in tools only when pattern matches their content
	var definitions string
	if h.rawTS != "" && re.MatchString(h.rawTS) {
		definitions = h.rawTS + "\n\n"
	}
	definitions += GenerateToolDefinitions(filtered)

	h.logger.InfoContext(ctx, "list_tools",
		"pattern", patternStr,
		"matched", len(filtered),
		"total", len(tools),
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": definitions,
		}},
	}, nil
}

func (h *Handler) handleExecuteCode(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
	codeRaw, ok := params["code"]
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "Missing required parameter: code",
			}},
		}, nil
	}

	code, ok := codeRaw.(string)
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "Parameter 'code' must be a string",
			}},
		}, nil
	}

	h.logger.DebugContext(ctx, "execute_code input", "code", code)

	result, err := h.codeRunner.Execute(ctx, code)
	if err != nil {
		h.logger.WarnContext(ctx, "execute_code failed", "error", err)
		// If we got a partial result (e.g. some calls succeeded before error), return it
		if result != nil {
			result.IsError = true
			return result, nil
		}
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": fmt.Sprintf("execute_code failed: %s", err),
			}},
		}, nil
	}

	return result, nil
}

// BuildToolList returns all tools including Code Mode tools.
// Tool descriptions are dynamically enriched with available backend names and hints.
func (h *Handler) BuildToolList(ctx context.Context) ([]ToolDefinition, error) {
	backendDesc := h.buildBackendDescription()

	listToolsDesc := "Returns a machine-readable list of all available tools with TypeScript interface definitions. Call this BEFORE execute_code to discover the correct function names and parameter types — without it you will not know the correct API signatures and your calls will fail. The pattern parameter is a regex matched against tool names and descriptions (case-insensitive). Use \".*\" for all tools, or a specific pattern like \"github\" or \"pull\" to filter"
	executeCodeDesc := "Accepts JavaScript code containing tool calls and executes them through the ToolMesh pipeline. IMPORTANT: You MUST call list_tools first to discover available function signatures before using this tool. Do not guess function names or parameters from the hints below"
	if backendDesc != "" {
		listToolsDesc += ". " + backendDesc
		executeCodeDesc += ". " + backendDesc
	}

	tools := []ToolDefinition{
		{
			Name:        "list_tools",
			Description: listToolsDesc,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern": map[string]any{
						"type":        "string",
						"description": "Regex pattern to filter tools by name or description (case-insensitive). Use \".*\" for all tools.",
					},
				},
				"required": []string{"pattern"},
			},
		},
		{
			Name:        "execute_code",
			Description: executeCodeDesc,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"code": map[string]any{
						"type":        "string",
						"description": "JavaScript code with toolmesh.* function calls",
					},
				},
				"required": []string{"code"},
			},
		},
	}

	// Backend tools are intentionally NOT exposed as individual MCP tools.
	// They are only accessible via execute_code (Code Mode) and list_tools.
	// This keeps the MCP surface minimal and avoids tool name validation issues.

	return tools, nil
}

// buildBackendDescription generates a summary of available backends and their hints
// for inclusion in MCP tool descriptions.
func (h *Handler) buildBackendDescription() string {
	summarizer, ok := h.backend.(backend.BackendSummarizer)
	if !ok {
		return ""
	}

	infos := summarizer.BackendSummaries()
	if len(infos) == 0 {
		return ""
	}

	// Build "Available backends: name1, name2, ..." line
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.Name)
	}
	desc := "Available backends: " + strings.Join(names, ", ") + ", and more — call list_tools to discover all current backends and their tool signatures"

	// Collect hints from backends that have them
	var hints []string
	for _, info := range infos {
		if info.Hint != "" {
			hints = append(hints, info.Name+": "+info.Hint)
		}
	}
	if len(hints) > 0 {
		desc += ". Hints: " + strings.Join(hints, "; ")
	}

	return desc
}

// ToolDefinition represents a tool exposed by the MCP server.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}
