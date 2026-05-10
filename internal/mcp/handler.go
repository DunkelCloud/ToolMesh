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
	"sort"
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
	h.logger.InfoContext(ctx, "handling tool call", logKeyTool, toolName)
	h.logger.DebugContext(ctx, "tool call params", logKeyTool, toolName, "params", params)

	// Instrument only the built-in meta-tools here. Real tool calls — both
	// direct ones from the default branch and individual calls extracted from
	// inside execute_code's JS body — are recorded by the executor with their
	// actual backend/tool labels, so instrumenting them here too would double-count.
	if h.isBuiltinTool(toolName) {
		start := time.Now()
		defer func() {
			outcome := "success"
			if err != nil || (result != nil && result.IsError) {
				outcome = outcomeError
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
				h.logger.DebugContext(ctx, "coercion failed", logKeyTool, toolName, outcomeError, cerr)
				return &backend.ToolResult{
					IsError: true,
					Content: []any{map[string]any{
						contentKeyType: contentKeyText,
						contentKeyText: fmt.Sprintf("Parameter coercion failed: %s", cerr),
					}},
				}, nil
			}
			if fmt.Sprintf("%v", coerced) != fmt.Sprintf("%v", params) {
				h.logger.DebugContext(ctx, "params after coercion", logKeyTool, toolName, "coerced", coerced)
			}
			params = coerced
		}

		result, err = h.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
			ToolName: toolName,
			Params:   params,
		})
		if err != nil {
			h.logger.DebugContext(ctx, "tool execution error", logKeyTool, toolName, outcomeError, err)
			return nil, err
		}
		h.logger.DebugContext(ctx, "tool execution result", logKeyTool, toolName, "isError", result.IsError)
		return result, nil
	}
}

func (h *Handler) handleDiscoverTools(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
	// pattern is optional. An empty or missing pattern is treated as ".*"
	// (return every authorized tool) — making the common "list everything"
	// case work without an explicit magic-string argument.
	patternStr, _ := params[argNamePattern].(string)
	if patternStr == "" {
		patternStr = ".*"
	}

	re, err := regexp.Compile("(?i)" + patternStr)
	if err != nil {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: fmt.Sprintf("Invalid regex pattern %q: %s", patternStr, err),
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
		argNamePattern, patternStr,
		"matched", len(filtered),
		"total", len(tools),
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: definitions,
		}},
	}, nil
}

func (h *Handler) handleExecuteCode(ctx context.Context, params map[string]any) *backend.ToolResult {
	codeRaw, ok := params[argNameCode]
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: "Missing required parameter: code",
			}},
		}
	}

	code, ok := codeRaw.(string)
	if !ok {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: "Parameter 'code' must be a string",
			}},
		}
	}

	h.logger.DebugContext(ctx, "execute_code input", argNameCode, code)

	result, err := h.codeRunner.Execute(ctx, code)
	if err != nil {
		h.logger.WarnContext(ctx, "execute_code failed", outcomeError, err)
		// If we got a partial result (e.g. some calls succeeded before error),
		// keep it and append the real error so the caller doesn't only see the
		// runner's "no tool calls found in code" placeholder.
		if result != nil {
			result.IsError = true
			result.Content = append(result.Content, map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: fmt.Sprintf("execute_code failed: %s", err),
			})
			return result
		}
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: fmt.Sprintf("execute_code failed: %s", err),
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

	discoverToolsDesc := "Discovery tool for ToolMesh. Returns TypeScript namespace declarations with full function signatures for the available backend tools. Pattern is an OPTIONAL case-insensitive regex matched against tool names and descriptions; omit it (or pass \".*\") to list all tools. Filter examples: \"github\" returns GitHub-related tools, \"pull\" finds pull-related tools across all backends. Call this as a SEPARATE MCP tool before execute_code — discover_tools is NOT a toolmesh.* member and must NOT be invoked from inside execute_code's `code` parameter."
	executeCodeDesc := "Executes JavaScript that calls backend tools via toolmesh.<backend>.<function>(...). Example: `const repos = await toolmesh.github.list_user_repos({username: \"octocat\"}); return repos.slice(0, 5);`. The last expression or an explicit `return` is sent back; tool calls are recorded in order. IMPORTANT: Call discover_tools as a SEPARATE MCP tool first to learn current function names and parameter types — discover_tools is NOT a toolmesh.* member and must NOT be invoked from inside this `code` parameter. Do not guess function names or parameters from the hints below"
	if backendDesc != "" {
		executeCodeDesc += ". " + backendDesc
	}

	tools := []ToolDefinition{
		{
			Name:        toolDiscoverTools,
			Description: discoverToolsDesc,
			InputSchema: map[string]any{
				contentKeyType: jsonTypeObject,
				schemaKeyProperties: map[string]any{
					argNamePattern: map[string]any{
						contentKeyType:       jsonTypeString,
						schemaKeyDescription: "Optional case-insensitive regex matched against tool names and descriptions. Defaults to \".*\" (all tools) when omitted or empty.",
					},
				},
			},
		},
		{
			Name:        toolExecuteCode,
			Description: executeCodeDesc,
			InputSchema: map[string]any{
				contentKeyType: jsonTypeObject,
				schemaKeyProperties: map[string]any{
					argNameCode: map[string]any{
						contentKeyType:       jsonTypeString,
						schemaKeyDescription: "JavaScript body that calls toolmesh.<backend>.<function>(...). Top-level await is supported. Example: `const r = await toolmesh.github.list_user_repos({username: \"octocat\"}); return r[0].name;`",
					},
				},
				schemaKeyRequired: []string{argNameCode},
			},
		},
	}

	// Append backend-promoted tools (configured per-backend via the YAML
	// `expose_tools` field). These are reachable via Code Mode and
	// discover_tools too — listing them at the MCP root is purely a
	// convenience for high-frequency tools where the discovery round-trip
	// would waste context.
	tools = append(tools, h.promotedToolDefinitions(ctx)...)

	if h.debugTools {
		tools = append(tools, debugToolDefinitions()...)
	}

	return tools, nil
}

// promotedToolDefinitions returns the direct tool definitions for backends
// that opted in via expose_tools, filtered through the executor's
// authorization check just like discover_tools so callers never see entries
// they cannot invoke.
func (h *Handler) promotedToolDefinitions(ctx context.Context) []ToolDefinition {
	promoter, ok := h.backend.(backend.ToolPromoter)
	if !ok {
		return nil
	}
	descs := promoter.PromotedTools()
	if len(descs) == 0 {
		return nil
	}

	if h.executor != nil {
		if uc := userctx.FromContext(ctx); uc != nil {
			descs = h.executor.FilterAuthorizedTools(ctx, uc.UserID, descs)
		}
	}

	out := make([]ToolDefinition, 0, len(descs))
	for _, d := range descs {
		out = append(out, ToolDefinition{
			Name:        d.Name,
			Description: d.Description,
			InputSchema: d.InputSchema,
		})
	}
	return out
}

// buildBackendDescription generates a summary of available backends and their hints
// for inclusion in the execute_code tool description. Backends that share a
// DADL spec (matched by BackendInfo.SpecID) are grouped into a single hint
// line so multiple instances of one API do not bloat the description with
// duplicate text.
func (h *Handler) buildBackendDescription() string {
	summarizer, ok := h.backend.(backend.BackendSummarizer)
	if !ok {
		return ""
	}

	infos := summarizer.BackendSummaries()
	if len(infos) == 0 {
		return ""
	}

	// "Available backends" line keeps every instance name — the grouping is
	// only an optimization for the hints block. Listing every name here is
	// what lets the LLM address each instance individually via execute_code.
	names := make([]string, 0, len(infos))
	for _, info := range infos {
		names = append(names, info.Name)
	}
	desc := "Available backends: " + strings.Join(names, ", ") + ", and more — call discover_tools to discover all current backends and their tool signatures"

	hints := buildGroupedHints(infos)
	if hints != "" {
		desc += ". Hints: " + hints
	}

	return desc
}

// buildGroupedHints renders a "name1: hint; name2, name3: hint; ..." line by
// collapsing infos that share a non-empty SpecID into one entry. Backends with
// an empty SpecID are rendered individually. Group ordering follows the
// position of the first member in the input slice; instance names within a
// group are sorted alphabetically. Infos with no hint are skipped entirely.
func buildGroupedHints(infos []backend.BackendInfo) string {
	type hintGroup struct {
		names []string
		hint  string
	}

	groups := make([]*hintGroup, 0, len(infos))
	groupBySpec := make(map[string]*hintGroup) // populated only for non-empty SpecID

	for _, info := range infos {
		if info.Hint == "" {
			continue
		}
		if info.SpecID != "" {
			if g, ok := groupBySpec[info.SpecID]; ok {
				g.names = append(g.names, info.Name)
				continue
			}
			g := &hintGroup{names: []string{info.Name}, hint: info.Hint}
			groupBySpec[info.SpecID] = g
			groups = append(groups, g)
			continue
		}
		groups = append(groups, &hintGroup{names: []string{info.Name}, hint: info.Hint})
	}

	if len(groups) == 0 {
		return ""
	}

	parts := make([]string, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.names)
		parts = append(parts, strings.Join(g.names, ", ")+": "+g.hint)
	}
	return strings.Join(parts, "; ")
}

// ToolDefinition represents a tool exposed by the MCP server.
type ToolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}
