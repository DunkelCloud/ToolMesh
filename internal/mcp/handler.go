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
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Built-in MCP meta-tool names. These do not pass through the executor and
// are dispatched directly inside [Handler.HandleToolCall].
const (
	toolDiscoverTools = "discover_tools"
	toolExecuteCode   = "execute_code"
	toolDebugEcho     = "debug_echo"
	toolDebugGenerate = "debug_generate"
)

// Handler processes incoming MCP tool calls and routes them through the executor.
type Handler struct {
	executor   *executor.Executor
	backend    backend.ToolBackend
	codeParser *CodeModeParser // kept for GenerateToolDefinitions / discover_tools
	codeRunner *CodeRunner
	coercer    *tsdef.Coercer
	rawTS      string // raw TypeScript content for built-in tools
	metrics    *metrics.Registry
	logger     *slog.Logger
	debugTools bool // when true, expose debug_echo and debug_generate
}

// NewHandler creates a new MCP tool call handler. The metrics registry is
// optional; pass nil to disable instrumentation. Set debugTools to true to
// expose the diagnostic tools (debug_echo, debug_generate); off in production.
func NewHandler(exec *executor.Executor, back backend.ToolBackend, coercer *tsdef.Coercer, rawTS string, m *metrics.Registry, logger *slog.Logger, debugTools bool) *Handler {
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
		metrics:    m,
		logger:     logger,
		debugTools: debugTools,
	}
}

// isBuiltinTool reports whether a tool name is dispatched directly by the
// handler instead of through the executor.
func (h *Handler) isBuiltinTool(name string) bool {
	switch name {
	case toolDiscoverTools, toolExecuteCode:
		return true
	case toolDebugEcho, toolDebugGenerate:
		return h.debugTools
	}
	return false
}

// HandleToolCall processes a single tool call through the execution pipeline.
func (h *Handler) HandleToolCall(ctx context.Context, toolName string, params map[string]any) (result *backend.ToolResult, err error) {
	h.logger.InfoContext(ctx, "handling tool call", "tool", toolName)
	h.logger.DebugContext(ctx, "tool call params", "tool", toolName, "params", params)

	// Instrument only the built-in meta-tools here. Real tool calls — both
	// direct ones from the default branch and individual calls extracted from
	// inside execute_code's JS body — are recorded by the executor with their
	// actual backend/tool labels, so instrumenting them here too would double-count.
	if h.isBuiltinTool(toolName) {
		start := time.Now()
		defer func() {
			outcome := "success"
			if err != nil || (result != nil && result.IsError) {
				outcome = "error"
			}
			h.metrics.RecordToolCall("builtin", toolName, outcome, time.Since(start))
		}()
	}

	switch toolName {
	case toolDiscoverTools:
		return h.handleDiscoverTools(ctx, params)
	case toolExecuteCode:
		return h.handleExecuteCode(ctx, params), nil
	case toolDebugEcho:
		if !h.debugTools {
			return debugDisabledResult(toolName), nil
		}
		return h.handleDebugEcho(params), nil
	case toolDebugGenerate:
		if !h.debugTools {
			return debugDisabledResult(toolName), nil
		}
		return h.handleDebugGenerate(params), nil
	default:
		// Apply type coercion before execution
		if h.coercer != nil {
			coerced, cerr := h.coercer.Coerce(toolName, params)
			if cerr != nil {
				h.logger.DebugContext(ctx, "coercion failed", "tool", toolName, "error", cerr)
				return &backend.ToolResult{
					IsError: true,
					Content: []any{map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Parameter coercion failed: %s", cerr),
					}},
				}, nil
			}
			if fmt.Sprintf("%v", coerced) != fmt.Sprintf("%v", params) {
				h.logger.DebugContext(ctx, "params after coercion", "tool", toolName, "coerced", coerced)
			}
			params = coerced
		}

		result, err = h.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
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

func (h *Handler) handleDiscoverTools(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
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

	// Filter through authorization — only return tools the caller can execute
	if h.executor != nil {
		uc := userctx.FromContext(ctx)
		if uc != nil {
			filtered = h.executor.FilterAuthorizedTools(ctx, uc.UserID, filtered)
		}
	}

	// Include raw TypeScript for built-in tools only when pattern matches their content
	var definitions string
	if h.rawTS != "" && re.MatchString(h.rawTS) {
		definitions = h.rawTS + "\n\n"
	}
	definitions += GenerateToolDefinitions(filtered)

	h.logger.InfoContext(ctx, "discover_tools",
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

func (h *Handler) handleExecuteCode(ctx context.Context, params map[string]any) *backend.ToolResult {
	codeRaw, ok := params["code"]
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "Missing required parameter: code",
			}},
		}
	}

	code, ok := codeRaw.(string)
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "Parameter 'code' must be a string",
			}},
		}
	}

	h.logger.DebugContext(ctx, "execute_code input", "code", code)

	result, err := h.codeRunner.Execute(ctx, code)
	if err != nil {
		h.logger.WarnContext(ctx, "execute_code failed", "error", err)
		// If we got a partial result (e.g. some calls succeeded before error),
		// keep it and append the real error so the caller doesn't only see the
		// runner's "no tool calls found in code" placeholder.
		if result != nil {
			result.IsError = true
			result.Content = append(result.Content, map[string]any{
				"type": "text",
				"text": fmt.Sprintf("execute_code failed: %s", err),
			})
			return result
		}
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": fmt.Sprintf("execute_code failed: %s", err),
			}},
		}
	}

	return result
}

// BuildToolList returns all tools including Code Mode tools.
// The execute_code description is dynamically enriched with available backend
// names and hints so an LLM scanning the MCP tool list sees the discovery
// surface immediately. The discover_tools description stays intentionally
// short: duplicating the backend block in both descriptions wastes thousands
// of context tokens for no information gain — the same content is reachable
// by calling discover_tools itself.
func (h *Handler) BuildToolList(ctx context.Context) ([]ToolDefinition, error) {
	backendDesc := h.buildBackendDescription()

	discoverToolsDesc := "Discovery tool for ToolMesh. Pattern is a case-insensitive regex matched against tool names and descriptions. Use \".*\" for all tools, or a specific pattern like \"github\" or \"dokuwiki\" to filter. Returns TypeScript namespace declarations with full function signatures. Call this before execute_code to discover correct function names and parameter types."
	executeCodeDesc := "Accepts JavaScript code containing tool calls and executes them through the ToolMesh pipeline. IMPORTANT: You MUST call discover_tools first to discover available function signatures before using this tool. Do not guess function names or parameters from the hints below"
	if backendDesc != "" {
		executeCodeDesc += ". " + backendDesc
	}

	tools := []ToolDefinition{
		{
			Name:        "discover_tools",
			Description: discoverToolsDesc,
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
	// They are only accessible via execute_code (Code Mode) and discover_tools.
	// This keeps the MCP surface minimal and avoids tool name validation issues.

	if h.debugTools {
		tools = append(tools, debugToolDefinitions()...)
	}

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
	desc := "Available backends: " + strings.Join(names, ", ") + ", and more — call discover_tools to discover all current backends and their tool signatures"

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
