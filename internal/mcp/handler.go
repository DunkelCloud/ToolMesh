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
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/toolindex"
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
	executor      *executor.Executor
	backend       backend.ToolBackend
	aliasResolver backend.ToolAliasResolver // resolves promoted bare tool names → canonical
	codeParser    *CodeModeParser           // kept for GenerateToolDefinitions / discover_tools
	codeRunner    *CodeRunner
	coercer       *tsdef.Coercer
	rawTS         string // raw TypeScript content for built-in tools
	metrics       *metrics.Registry
	logger        *slog.Logger
	debugTools    bool          // when true, expose debug_echo and debug_generate
	hints         *hintNotifier // first-use backend hint delivery; nil = disabled

	// File broker plumbing for the upload_file built-in (nil = tool hidden).
	blobStore         *blob.Store
	uploadLimits      blob.UploadLimits
	uploadFetchClient *http.Client
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

	runner := NewCodeRunner(parser.nameMap, tools, exec, coercer, logger)

	h := &Handler{
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
	if r, ok := back.(backend.ToolAliasResolver); ok {
		h.aliasResolver = r
	}
	// One notifier shared with the code runner, so a backend's hint is
	// delivered once per principal no matter which surface the call came
	// through — a direct tool call or one made from inside execute_code.
	h.hints = newHintNotifier(back)
	runner.hints = h.hints
	return h
}

// SetCodeTimeout overrides the wall-clock budget for a single execute_code
// run (default codeTimeout). A non-positive duration keeps the default.
func (h *Handler) SetCodeTimeout(d time.Duration) {
	if h.codeRunner != nil {
		h.codeRunner.SetTimeout(d)
	}
}

// isBuiltinTool reports whether a tool name is dispatched directly by the
// handler instead of through the executor.
func (h *Handler) isBuiltinTool(name string) bool {
	switch name {
	case toolDiscoverTools, toolExecuteCode:
		return true
	case toolUploadFile:
		return h.blobStore != nil
	case toolDebugEcho, toolDebugGenerate:
		return h.debugTools
	}
	return false
}

// HandleToolCall processes a single tool call through the execution pipeline.
func (h *Handler) HandleToolCall(ctx context.Context, toolName string, params map[string]any) (result *backend.ToolResult, err error) {
	h.logger.InfoContext(ctx, "handling tool call", logKeyTool, toolName)
	h.logger.DebugContext(ctx, "tool call params", logKeyTool, toolName, "params", params)

	// Resolve promoted bare-name aliases (e.g. "web_search") to their
	// canonical "<backend>_<tool>" form before anything downstream sees the
	// name. This keeps authz, gate, audit, and metrics consistently keyed on
	// the canonical identifier regardless of which surface the caller used.
	// Built-in meta-tools (discover_tools, execute_code, ...) never have
	// aliases registered, so the resolver is a no-op for them.
	if h.aliasResolver != nil {
		if canonical := h.aliasResolver.ResolveAlias(toolName); canonical != toolName {
			h.logger.DebugContext(ctx, "resolved promoted tool alias",
				"alias", toolName,
				"canonical", canonical,
			)
			toolName = canonical
		}
	}

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
	case toolUploadFile:
		// handleUploadFile reports a clear "not configured" error itself when
		// no blob store is set; the tool is only advertised when one is.
		return h.handleUploadFile(ctx, params)
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
		h.attachBackendHint(ctx, toolName, result)
		h.logger.DebugContext(ctx, "tool execution result", logKeyTool, toolName, "isError", result.IsError)
		return result, nil
	}
}

// attachBackendHint prepends the owning backend's configured hint to a result
// the first time a principal calls into that backend.
//
// The notice rides as its own text content block ahead of the payload, never
// merged into it: consumers read the response body as a unit — response
// transforms and the code sandbox both parse the first text block as JSON —
// so text mixed into it would corrupt the result rather than annotate it.
// Logged at info level so the delivery can be correlated with what the caller
// did next.
func (h *Handler) attachBackendHint(ctx context.Context, toolName string, result *backend.ToolResult) {
	if result == nil {
		return
	}
	notice := h.hints.noticeFor(ctx, toolName)
	if notice == "" {
		return
	}
	h.logger.InfoContext(ctx, "delivered backend hint on first use", logKeyTool, toolName)
	result.Content = append([]any{map[string]any{
		contentKeyType: contentKeyText,
		contentKeyText: notice,
	}}, result.Content...)
}

func (h *Handler) handleDiscoverTools(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
	// pattern is optional. An empty or missing pattern is treated as ".*"
	// (return every authorized tool) — making the common "list everything"
	// case work without an explicit magic-string argument.
	patternStr, _ := params[argNamePattern].(string)
	if patternStr == "" {
		patternStr = ".*"
	}

	queryStr, _ := params[argNameQuery].(string)

	detail, _ := params[argNameDetail].(string)
	if detail == "" {
		detail = detailAuto
	}
	switch detail {
	case detailAuto, detailFull, detailSummary, detailNames, detailOverview:
	default:
		return discoverErrorResult(fmt.Sprintf(
			"Invalid detail %q: must be one of %q, %q, %q, %q, %q",
			detail, detailAuto, detailFull, detailSummary, detailNames, detailOverview)), nil
	}

	limit := discoverLimitParam(params)

	re, err := regexp.Compile("(?i)" + patternStr)
	if err != nil {
		return discoverErrorResult(fmt.Sprintf("Invalid regex pattern %q: %s", patternStr, err)), nil
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

	// Ranked free-text mode: re-order the (pattern- and authz-filtered)
	// candidates by BM25 relevance. The corpus is small and changes with
	// hot-reload, so the index is built per call — a few milliseconds for
	// a few thousand short docs.
	if queryStr != "" {
		filtered = rankByQuery(filtered, queryStr)
		if limit == 0 {
			limit = discoverQueryLimit
		}
	}

	matched := len(filtered)
	shown := filtered
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}

	effectiveDetail := detail
	if effectiveDetail == detailAuto {
		effectiveDetail = autoDetail(len(shown))
	}

	var body string
	switch effectiveDetail {
	case detailFull:
		// Include raw TypeScript for built-in tools only when the pattern
		// matches their content; skipped in query mode (no regex semantics)
		// and in cheaper tiers (it would dwarf the tool list itself).
		if queryStr == "" && h.rawTS != "" && re.MatchString(h.rawTS) {
			body = h.rawTS + "\n\n"
		}
		body += GenerateToolDefinitions(shown)
	case detailSummary:
		body = GenerateToolSummaries(shown)
	case detailNames:
		body = GenerateToolNames(shown)
	case detailOverview:
		// Counts are computed over every match — cutting them to `limit`
		// would defeat the purpose of an overview.
		body = GenerateBackendOverview(filtered)
	}

	// Fail-safe: no single discovery response may exceed the byte cap,
	// regardless of tier and explicit detail choice.
	truncated := false
	if len(body) > discoverMaxBytes {
		cut := strings.LastIndexByte(body[:discoverMaxBytes], '\n')
		if cut <= 0 {
			cut = discoverMaxBytes
		}
		body = body[:cut] + "\n// [TRUNCATED: output exceeded the " +
			fmt.Sprintf("%d", discoverMaxBytes/1000) + " KB cap — narrow the search or use a coarser detail tier]\n"
		truncated = true
	}

	definitions := body + discoveryFooter(matched, len(tools), len(shown), effectiveDetail, detail == detailAuto, queryStr)

	h.logger.InfoContext(ctx, "discover_tools",
		argNamePattern, patternStr,
		argNameQuery, queryStr,
		argNameDetail, effectiveDetail,
		"matched", matched,
		"shown", len(shown),
		"total", len(tools),
		"truncated", truncated,
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: definitions,
		}},
	}, nil
}

// discoverErrorResult wraps a parameter validation message into an MCP error
// result (the call itself succeeded; the arguments were unusable).
func discoverErrorResult(msg string) *backend.ToolResult {
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: msg,
		}},
	}
}

// discoverLimitParam extracts the optional limit argument. JSON numbers
// arrive as float64; other numeric types are accepted for direct Go callers.
// Numeric strings are accepted too — clients holding a stale tool schema
// serialize unknown parameters as strings. Invalid or negative values fall
// back to 0 (no explicit limit).
func discoverLimitParam(params map[string]any) int {
	switch n := params[argNameLimit].(type) {
	case float64:
		if n > 0 {
			return int(n)
		}
	case int:
		if n > 0 {
			return n
		}
	case int64:
		if n > 0 {
			return int(n)
		}
	case string:
		if v, err := strconv.Atoi(strings.TrimSpace(n)); err == nil && v > 0 {
			return v
		}
	}
	return 0
}

// rankByQuery orders descriptors by BM25 relevance to the free-text query.
// Descriptors that match no query term are dropped.
func rankByQuery(descs []backend.ToolDescriptor, query string) []backend.ToolDescriptor {
	docs := make([]toolindex.Doc, len(descs))
	byName := make(map[string]backend.ToolDescriptor, len(descs))
	for i, d := range descs {
		docs[i] = descriptorDoc(d, d.Name)
		byName[d.Name] = d
	}

	ranked := toolindex.Build(docs).Search(query, 0)
	out := make([]backend.ToolDescriptor, 0, len(ranked))
	for _, r := range ranked {
		if d, ok := byName[r.Doc.Name]; ok {
			out = append(out, d)
		}
	}
	return out
}

// discoveryFooter renders the trailing status line appended to every
// discover_tools response. Always present so the caller can tell how much
// of the catalog it is looking at and how to refine.
func discoveryFooter(matched, total, shown int, detail string, auto bool, query string) string {
	mode := detail
	if auto {
		mode += " (auto)"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "\n// ── %d of %d tools matched", matched, total)
	if shown < matched {
		if query != "" {
			fmt.Fprintf(&sb, ", showing top %d", shown)
		} else {
			fmt.Fprintf(&sb, ", showing first %d", shown)
		}
	}
	fmt.Fprintf(&sb, " — detail: %s.\n", mode)
	sb.WriteString("// Refine: narrower pattern, query:\"<free text>\" for ranked results, detail:\"full\"|\"summary\"|\"names\"|\"overview\", limit:N.\n")
	return sb.String()
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

	// include_results is optional; accept a real boolean or its string form
	// (some clients serialize booleans as strings).
	includeResults := false
	switch v := params[argNameIncludeResults].(type) {
	case bool:
		includeResults = v
	case string:
		if parsed, perr := strconv.ParseBool(v); perr == nil {
			includeResults = parsed
		}
	}

	result, err := h.codeRunner.ExecuteWithOptions(ctx, code, ExecuteOptions{IncludeResults: includeResults})
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

	discoverToolsDesc := "Discovery tool for ToolMesh. Two search modes: `pattern` (case-insensitive regex matched against tool names and descriptions, e.g. \"github\" or \"^netbox_list\") and `query` (free text, BM25-ranked, returns the top 25 most relevant tools — preferred for exploratory searches like \"dns record management\"). Output detail auto-scales with result count: few matches return full TypeScript signatures, more matches return one-line summaries, then names only, then a per-backend overview; override with detail:\"full\"|\"summary\"|\"names\"|\"overview\" and cap results with limit:N. Every response ends with a footer stating matched/shown counts and refine hints. Call this as a SEPARATE MCP tool — inside execute_code use toolmesh.discover(query) and toolmesh.describe(name) instead."
	executeCodeDesc := "Executes JavaScript that calls backend tools via toolmesh.<backend>_<function>(...). Tools are exposed as a flat snake_case namespace — `toolmesh.github_list_user_repos`, NOT `toolmesh.github.list_user_repos`. Example: `const repos = await toolmesh.github_list_user_repos({username: \"octocat\"}); return repos.slice(0, 5);`. The value you `return` is the response — project/filter inside the code and return only what you need; each tool call is then listed as a compact {tool, status, resultBytes} entry (failed calls keep their full error). Without an explicit `return`, the full results of all calls are returned in order; include_results:true forces full results alongside a return value. In-sandbox discovery: `toolmesh.discover(\"<free text>\", limit?)` returns ranked {name, description, backend} matches and `toolmesh.describe(\"<tool_name>\")` returns the full parameter schema — use them instead of guessing function names or parameters. discover_tools is NOT a toolmesh.* member and must NOT be invoked from inside this `code` parameter"
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
					argNameQuery: map[string]any{
						contentKeyType:       jsonTypeString,
						schemaKeyDescription: "Optional free-text search (e.g. \"dns record management\"). Results are BM25-ranked by relevance; the top 25 are returned unless limit is set. Combinable with pattern (pattern filters first, query ranks within).",
					},
					argNameDetail: map[string]any{
						contentKeyType: jsonTypeString,
						"enum":         []string{detailAuto, detailFull, detailSummary, detailNames, detailOverview},
						schemaKeyDescription: "Output detail level. \"auto\" (default) scales with result count: ≤" +
							fmt.Sprintf("%d", discoverFullMax) + " full TypeScript signatures, ≤" +
							fmt.Sprintf("%d", discoverSummaryMax) + " one-line summaries, ≤" +
							fmt.Sprintf("%d", discoverNamesMax) + " names only, above that a per-backend overview.",
					},
					argNameLimit: map[string]any{
						contentKeyType:       jsonTypeInteger,
						schemaKeyDescription: "Optional maximum number of tools to return. Defaults to 25 for query searches, unlimited for pattern searches.",
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
						schemaKeyDescription: "JavaScript body that calls toolmesh.<backend>_<function>(...). Tools are flat snake_case — `toolmesh.github_list_user_repos`, NOT `toolmesh.github.list_user_repos` (the latter throws TypeError because `toolmesh.<backend>` is undefined). Top-level await is supported. Example: `const r = await toolmesh.github_list_user_repos({username: \"octocat\"}); return r[0].name;`",
					},
					argNameIncludeResults: map[string]any{
						contentKeyType:       jsonTypeBoolean,
						schemaKeyDescription: "Include the full result of every tool call in the response even when the code returns a value. Default false: with an explicit return, successful calls are compacted to {tool, status, resultBytes} and only the return value carries data.",
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
	if h.blobStore != nil {
		tools = append(tools, uploadFileToolDefinition())
	}

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
//
// Authz operates on the canonical "<backend>_<tool>" name (matching the
// keys policy tuples and audit logs use), but the advertised tool keeps
// the public Descriptor.Name (bare alias when unambiguous, or canonical
// when a cross-backend bare-name conflict forced a fallback).
func (h *Handler) promotedToolDefinitions(ctx context.Context) []ToolDefinition {
	promoter, ok := h.backend.(backend.ToolPromoter)
	if !ok {
		return nil
	}
	proms := promoter.PromotedTools()
	if len(proms) == 0 {
		return nil
	}

	if h.executor != nil {
		if uc := userctx.FromContext(ctx); uc != nil {
			canonicalDescs := make([]backend.ToolDescriptor, len(proms))
			for i, p := range proms {
				d := p.Descriptor
				d.Name = p.Canonical
				canonicalDescs[i] = d
			}
			allowed := h.executor.FilterAuthorizedTools(ctx, uc.UserID, canonicalDescs)
			allowedSet := make(map[string]struct{}, len(allowed))
			for _, d := range allowed {
				allowedSet[d.Name] = struct{}{}
			}
			filtered := proms[:0]
			for _, p := range proms {
				if _, ok := allowedSet[p.Canonical]; ok {
					filtered = append(filtered, p)
				}
			}
			proms = filtered
		}
	}

	out := make([]ToolDefinition, 0, len(proms))
	for _, p := range proms {
		out = append(out, ToolDefinition{
			Name:        p.Descriptor.Name,
			Description: p.Descriptor.Description,
			InputSchema: p.Descriptor.InputSchema,
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
