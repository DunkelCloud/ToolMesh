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
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
)

// Handler processes incoming MCP tool calls and routes them through the executor.
type Handler struct {
	executor   *executor.Executor
	backend    backend.ToolBackend
	codeParser *CodeModeParser
	coercer    *tsdef.Coercer
	rawTS      string // raw TypeScript content for built-in tools
	logger     *slog.Logger
}

// NewHandler creates a new MCP tool call handler.
func NewHandler(exec *executor.Executor, back backend.ToolBackend, coercer *tsdef.Coercer, rawTS string, logger *slog.Logger) *Handler {
	// Build the code mode parser with reverse name lookup from all registered tools
	tools, _ := back.ListTools(context.Background())
	return &Handler{
		executor:   exec,
		backend:    back,
		codeParser: NewCodeModeParser(tools),
		coercer:    coercer,
		rawTS:      rawTS,
		logger:     logger,
	}
}

// HandleToolCall processes a single tool call through the execution pipeline.
func (h *Handler) HandleToolCall(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	h.logger.InfoContext(ctx, "handling tool call", "tool", toolName)

	switch toolName {
	case "list_tools":
		return h.handleListTools(ctx)
	case "execute_code":
		return h.handleExecuteCode(ctx, params)
	default:
		// Apply type coercion before execution
		if h.coercer != nil {
			coerced, err := h.coercer.Coerce(toolName, params)
			if err != nil {
				return &backend.ToolResult{
					IsError: true,
					Content: []any{map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Parameter coercion failed: %s", err),
					}},
				}, nil
			}
			params = coerced
		}

		return h.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
			ToolName: toolName,
			Params:   params,
		})
	}
}

func (h *Handler) handleListTools(ctx context.Context) (*backend.ToolResult, error) {
	tools, err := h.backend.ListTools(ctx)
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	// Serve raw TypeScript for built-in tools + generated TS for external tools
	var definitions string
	if h.rawTS != "" {
		definitions = h.rawTS + "\n\n"
	}
	definitions += GenerateToolDefinitions(tools)

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

	calls, err := h.codeParser.ParseCode(code)
	if err != nil {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": fmt.Sprintf("Failed to parse code: %s", err),
			}},
		}, nil
	}

	var results []any
	for _, call := range calls {
		// Apply coercion for each parsed call
		callParams := call.Params
		if h.coercer != nil {
			coerced, err := h.coercer.Coerce(call.ToolName, callParams)
			if err != nil {
				results = append(results, map[string]any{
					"tool":  call.ToolName,
					"error": fmt.Sprintf("coercion failed: %s", err),
				})
				continue
			}
			callParams = coerced
		}

		result, err := h.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
			ToolName: call.ToolName,
			Params:   callParams,
		})
		if err != nil {
			results = append(results, map[string]any{
				"tool":  call.ToolName,
				"error": err.Error(),
			})
			continue
		}
		results = append(results, map[string]any{
			"tool":   call.ToolName,
			"result": result,
		})
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("marshal execute_code results: %w", err)
	}

	return &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": string(resultJSON),
		}},
	}, nil
}

// BuildToolList returns all tools including Code Mode tools.
func (h *Handler) BuildToolList(ctx context.Context) ([]ToolDefinition, error) {
	tools := []ToolDefinition{
		{
			Name:        "list_tools",
			Description: "Returns a machine-readable list of all available tools with TypeScript interface definitions",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "execute_code",
			Description: "Accepts JavaScript code containing tool calls and executes them through the ToolMesh pipeline",
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

	backendTools, err := h.backend.ListTools(ctx)
	if err != nil {
		h.logger.WarnContext(ctx, "failed to list backend tools", "error", err)
	} else {
		for _, bt := range backendTools {
			tools = append(tools, ToolDefinition{
				Name:        bt.Name,
				Description: bt.Description,
				InputSchema: bt.InputSchema,
			})
		}
	}

	return tools, nil
}

// ToolDefinition represents a tool exposed by the MCP server.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}
