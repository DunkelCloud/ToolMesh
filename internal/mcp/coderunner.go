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
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/toolindex"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/dop251/goja"
)

// Names of the in-sandbox discovery helpers exposed on the toolmesh object.
// Installed only when no backend tool has claimed the same sanitized name.
const (
	sandboxDiscoverFn = "discover"
	sandboxDescribeFn = "describe"
)

// maxCodeCalls is the maximum number of toolmesh.* calls allowed per execution.
const maxCodeCalls = 50

// codeTimeout is the default maximum duration for a single execute_code
// invocation. It can be overridden per deployment via SetTimeout (wired to
// TOOLMESH_CODE_TIMEOUT) so an orchestration of several slow backend calls
// (committees, batch evals) is not capped below the backends' own timeouts.
const codeTimeout = 120 * time.Second

// Keys of per-call entries in the wire-format result array. A successful
// call is echoed in full as {tool, result} only when the script does not
// return a value (or include_results is set); otherwise it is compacted to
// {tool, status, resultBytes} — see compactCallResults.
const (
	resultKeyResult = "result"
	resultKeyReturn = "return"
	resultKeyStatus = "status"
	resultKeyBytes  = "resultBytes"
	resultStatusOK  = "ok"
	// resultKeyNotice carries a gateway-level note about the call (currently
	// a backend's first-use hint). It sits beside the result rather than
	// inside it — the script consumes the result as data, so a note folded
	// into it would corrupt the value the script sees.
	resultKeyNotice = "notice"
)

// CodeRunner executes JavaScript code in a sandboxed goja runtime,
// resolving toolmesh.* calls to real tool executions via the executor.
type CodeRunner struct {
	// view is the tool set a new run starts from; see currentView.
	view atomic.Pointer[toolView]
	// toolSource is the backend the tool set comes from when it can change
	// at runtime: a run that starts after its version moved lists the tools
	// again. Set by NewHandler through followToolSet; nil keeps the tool
	// set given to NewCodeRunner.
	toolSource versionedToolSource
	// refreshMu lets one run list the tools after a change while concurrent
	// runs wait for its result instead of each listing them again.
	refreshMu sync.Mutex

	executor *executor.Executor
	coercer  *tsdef.Coercer
	logger   *slog.Logger
	timeout  time.Duration // wall-clock budget for one Execute; 0 → codeTimeout
	// hints delivers a backend's first-use hint alongside the call that
	// triggered it. Set by NewHandler to the handler's own notifier so both
	// surfaces share one ledger; nil is valid and emits nothing.
	hints *hintNotifier
	// metaTools are built-in tools the script may call as toolmesh.<name>,
	// by name, such as tell_me_my_rights and request_grant. They are reached
	// from inside execute_code too because a client may list tools once and
	// keep that list: a meta-tool that is listed only under some
	// configuration would stay out of its reach. A backend tool with the same
	// sanitized name takes precedence. Set by NewHandler.
	metaTools map[string]metaTool
	// metrics counts how scripts end and, for a script that runs to
	// completion, which of its tool calls failed: the script got an error
	// value instead of an exception and may have carried on without the
	// data. Set by NewHandler; nil records nothing.
	metrics *metrics.Registry
	// backends names the backend that owns a tool for the metrics' backend
	// label. Set by NewHandler; nil labels every tool "unknown".
	backends backend.BackendNameResolver
}

// versionedToolSource is a tool listing whose version tells when to list
// again, such as the composite backend that a hot reload of backends.yaml
// swaps.
type versionedToolSource interface {
	ListTools(ctx context.Context) ([]backend.ToolDescriptor, error)
	backend.ToolSetVersioner
}

// toolView is the tool set one execute_code run sees: the sandbox names and
// the descriptors behind toolmesh.discover() and toolmesh.describe(). A view
// never changes once built, so a running script keeps the tool set it
// started with while the next script gets the one a hot reload brought.
type toolView struct {
	version         uint64            // tool source version the tools were listed at
	nameMap         map[string]string // sanitized JS name → canonical tool name
	descBySanitized map[string]backend.ToolDescriptor
	index           *toolindex.Index // BM25 index for toolmesh.discover()
}

// newToolView builds the view of tools, listed at the given version, under
// the name map NewCodeModeParser built from them.
func newToolView(version uint64, nameMap map[string]string, tools []backend.ToolDescriptor) *toolView {
	descBySanitized := make(map[string]backend.ToolDescriptor, len(tools))
	for _, t := range tools {
		// Last entry wins on sanitized-name collisions, matching the
		// nameMap construction in NewCodeModeParser.
		descBySanitized[sanitizeName(t.Name)] = t
	}

	docs := make([]toolindex.Doc, 0, len(descBySanitized))
	for sanitized, t := range descBySanitized {
		docs = append(docs, descriptorDoc(t, sanitized))
	}

	return &toolView{
		version:         version,
		nameMap:         nameMap,
		descBySanitized: descBySanitized,
		index:           toolindex.Build(docs),
	}
}

// metaTool runs a built-in tool with the caller's context.
type metaTool func(ctx context.Context, params map[string]any) *backend.ToolResult

// failedCall is the backend and reason of a tool call that failed inside a
// script, the labels of the swallowed-error counter.
type failedCall struct {
	backend string
	reason  string
}

// SetTimeout overrides the wall-clock budget for a single execute_code run.
// A non-positive duration restores the built-in default (codeTimeout).
func (r *CodeRunner) SetTimeout(d time.Duration) {
	if d <= 0 {
		r.timeout = 0
		return
	}
	r.timeout = d
}

// NewCodeRunner creates a CodeRunner with the given name mapping and executor.
// The descriptors back the in-sandbox toolmesh.discover()/describe() helpers;
// the BM25 index over them is built here, once per tool set. The tool set
// stays fixed unless followToolSet ties the runner to a changing source.
func NewCodeRunner(nameMap map[string]string, tools []backend.ToolDescriptor, exec *executor.Executor, coercer *tsdef.Coercer, logger *slog.Logger) *CodeRunner {
	r := &CodeRunner{
		executor: exec,
		coercer:  coercer,
		logger:   logger,
	}
	r.view.Store(newToolView(0, nameMap, tools))
	return r
}

// followToolSet makes the runner pick up changes of src's tool set, such as
// a hot reload of backends.yaml. version is src's version read before the
// listing given to NewCodeRunner, so a change that landed in between is
// picked up by the first run.
func (r *CodeRunner) followToolSet(src versionedToolSource, version uint64) {
	v := *r.view.Load()
	v.version = version
	r.view.Store(&v)
	r.toolSource = src
}

// currentView returns the tool set a new run starts from. While the tool
// source's version stands still, that is the cached view; after a change,
// the first run lists the tools again and caches the result for the runs
// after it. Should that listing fail, the run keeps the previous view and
// the next run tries again.
func (r *CodeRunner) currentView(ctx context.Context) *toolView {
	v := r.view.Load()
	if r.toolSource == nil {
		return v
	}
	// Versions only grow, and a view's tools are at least as new as its
	// version (see backend.ToolSetVersioner), so a view at or past the
	// current version is fresh.
	version := r.toolSource.ToolSetVersion()
	if v.version >= version {
		return v
	}

	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if v = r.view.Load(); v.version >= version {
		return v // a concurrent run listed the tools meanwhile
	}
	tools, err := r.toolSource.ListTools(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "execute_code: listing tools failed, keeping the previous tool set", outcomeError, err)
		return v
	}
	next := newToolView(version, NewCodeModeParser(tools).nameMap, tools)
	r.view.Store(next)
	r.initSwallowedErrors(tools)
	r.logger.InfoContext(ctx, "execute_code tool set changed",
		"nameMapSize", len(next.nameMap), "toolCount", len(tools))
	return next
}

// ExecuteOptions controls how Execute shapes the wire-format response.
type ExecuteOptions struct {
	// IncludeResults keeps the full result of every tool call in the
	// response even when the script returns a value. Without it, an
	// explicit return value compacts successful call entries to
	// {tool, status, resultBytes}.
	IncludeResults bool
}

// Execute runs code with default options — see ExecuteWithOptions.
func (r *CodeRunner) Execute(ctx context.Context, code string) (*backend.ToolResult, error) {
	return r.ExecuteWithOptions(ctx, code, ExecuteOptions{})
}

// ExecuteWithOptions runs JavaScript code in a sandboxed goja runtime.
// toolmesh.* calls are intercepted and dispatched to the executor.
// Returns a ToolResult listing each tool call in order, followed by the
// script's return value when it produced one. With a return value present,
// successful call entries are compacted unless opts.IncludeResults is set —
// the return value is the caller's projection of the data, so the full echo
// would transport the same payload twice.
func (r *CodeRunner) ExecuteWithOptions(ctx context.Context, code string, opts ExecuteOptions) (*backend.ToolResult, error) {
	// outcome is how the script ended, for the metrics. Every return before
	// the script has run to completion counts as an error.
	outcome := metrics.ScriptOutcomeError
	defer func() { r.metrics.RecordCodeScript(outcome) }()

	// Static analysis: scan code-mode submissions for forbidden patterns
	violations, err := composite.ScanCode(code, "execute_code")
	if err == nil && len(violations) > 0 {
		msgs := make([]string, 0, len(violations))
		for _, v := range violations {
			msgs = append(msgs, fmt.Sprintf("line %d: %s", v.Line, v.Message))
		}
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: fmt.Sprintf("execute_code: static analysis found forbidden patterns:\n%s", strings.Join(msgs, "\n")),
			}},
		}, nil
	}

	timeout := r.timeout
	if timeout <= 0 {
		timeout = codeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		callCount int
		mu        sync.Mutex
		results   []any
		console   []string
		failed    = map[failedCall]struct{}{}
	)

	rt := goja.New()
	// Cap JS call-stack depth so unbounded recursion throws a catchable
	// RangeError instead of growing the runtime stack toward an OOM.
	rt.SetMaxCallStackSize(maxJSCallStackDepth)
	composite.LockdownRuntime(rt)

	// Set up console.log
	consoleObj := rt.NewObject()
	_ = consoleObj.Set("log", func(call goja.FunctionCall) goja.Value {
		parts := make([]string, 0, len(call.Arguments))
		for _, arg := range call.Arguments {
			parts = append(parts, arg.String())
		}
		mu.Lock()
		console = append(console, fmt.Sprint(parts))
		mu.Unlock()
		return goja.Undefined()
	})
	if err := rt.Set("console", consoleObj); err != nil {
		return nil, fmt.Errorf("execute_code: set console: %w", err)
	}

	// The tool set this run sees, taken once: a hot reload while the script
	// runs reaches the next script, not this one.
	view := r.currentView(ctx)

	// Register toolmesh object with one method per tool
	tmObj := rt.NewObject()
	for sanitized, canonical := range view.nameMap {
		sn := sanitized // capture for closure
		cn := canonical // capture for closure
		_ = tmObj.Set(sn, func(call goja.FunctionCall) goja.Value {
			// Check call count limit
			mu.Lock()
			callCount++
			count := callCount
			mu.Unlock()

			if count > maxCodeCalls {
				panic(rt.NewGoError(fmt.Errorf("execute_code: exceeded maximum %d tool calls", maxCodeCalls)))
			}

			// Check context cancellation
			if ctx.Err() != nil {
				panic(rt.NewGoError(fmt.Errorf("execute_code: %w", ctx.Err())))
			}

			// Extract params from the JS call
			var toolParams map[string]any
			if len(call.Arguments) > 0 {
				exported := call.Arguments[0].Export()
				if m, ok := exported.(map[string]any); ok {
					toolParams = m
				}
			}
			if toolParams == nil {
				toolParams = make(map[string]any)
			}

			r.logger.DebugContext(ctx, "execute_code dispatching",
				"jsFn", sn,
				logKeyTool, cn,
				"params", toolParams,
			)

			// Apply coercion
			if r.coercer != nil {
				coerced, err := r.coercer.Coerce(cn, toolParams)
				if err != nil {
					r.logger.DebugContext(ctx, "execute_code coercion failed",
						logKeyTool, cn,
						outcomeError, err,
					)
					mu.Lock()
					results = append(results, map[string]any{
						logKeyTool:   cn,
						outcomeError: fmt.Sprintf("coercion failed: %s", err),
					})
					failed[failedCall{r.backendLabel(cn), metrics.SwallowedCoercion}] = struct{}{}
					mu.Unlock()
					// Return undefined — coercion failure is non-fatal
					return goja.Undefined()
				}
				toolParams = coerced
			}

			// Execute the tool
			result, err := r.executor.ExecuteTool(ctx, executor.ExecuteToolRequest{
				ToolName: cn,
				Params:   toolParams,
			})
			if err != nil {
				r.logger.DebugContext(ctx, "execute_code tool error",
					logKeyTool, cn,
					outcomeError, err.Error(),
				)
				mu.Lock()
				results = append(results, map[string]any{
					logKeyTool:   cn,
					outcomeError: err.Error(),
				})
				failed[failedCall{r.backendLabel(cn), metrics.SwallowedDispatch}] = struct{}{}
				mu.Unlock()
				// Return error object to JS instead of panicking.
				// This lets loops continue and subsequent calls execute.
				errObj := rt.NewObject()
				_ = errObj.Set(outcomeError, err.Error())
				_ = errObj.Set(logKeyTool, cn)
				return rt.ToValue(errObj)
			}

			// Log result
			if contentJSON, merr := json.Marshal(result.Content); merr == nil {
				r.logger.DebugContext(ctx, "execute_code tool result",
					logKeyTool, cn,
					"isError", result.IsError,
					"content", string(contentJSON),
				)
			}

			// Collect result for the wire-format output. A first-use backend
			// hint travels as a sibling key: the script reads the result
			// itself, so the note must not be inside it.
			entry := map[string]any{
				logKeyTool:      cn,
				resultKeyResult: result,
			}
			if notice := r.hints.noticeFor(ctx, cn); notice != "" {
				r.logger.InfoContext(ctx, "delivered backend hint on first use", logKeyTool, cn)
				entry[resultKeyNotice] = notice
			}
			mu.Lock()
			results = append(results, entry)
			if result.IsError {
				failed[failedCall{r.backendLabel(cn), metrics.SwallowedToolError}] = struct{}{}
			}
			mu.Unlock()

			// Return the actual API response content for JS consumption,
			// not the ToolMesh wrapper. This lets JS code use result.field
			// directly instead of result.Content[0].text.
			return extractJSValue(rt, result)
		})
	}

	// Built-in meta-tools, called like backend tools and counted toward the
	// same budget.
	for name, fn := range r.metaTools {
		if _, taken := view.nameMap[name]; taken {
			continue
		}
		mn, mfn := name, fn
		_ = tmObj.Set(mn, func(call goja.FunctionCall) goja.Value {
			mu.Lock()
			callCount++
			count := callCount
			mu.Unlock()
			if count > maxCodeCalls {
				panic(rt.NewGoError(fmt.Errorf("execute_code: exceeded maximum %d tool calls", maxCodeCalls)))
			}
			if ctx.Err() != nil {
				panic(rt.NewGoError(fmt.Errorf("execute_code: %w", ctx.Err())))
			}
			params := map[string]any{}
			if len(call.Arguments) > 0 {
				if m, ok := call.Arguments[0].Export().(map[string]any); ok {
					params = m
				}
			}
			result := mfn(ctx, params)
			mu.Lock()
			results = append(results, map[string]any{logKeyTool: mn, resultKeyResult: result})
			if result == nil || result.IsError {
				failed[failedCall{metricsBackendBuiltin, metrics.SwallowedToolError}] = struct{}{}
			}
			mu.Unlock()
			return extractJSValue(rt, result)
		})
	}

	// In-sandbox discovery helpers: toolmesh.discover(query, limit?) and
	// toolmesh.describe(name). These run locally against the descriptor
	// index — no backend round-trip — so they do not count toward the
	// maxCodeCalls budget.
	r.installDiscovery(ctx, rt, tmObj, view)

	// Guard against the common LLM mistake of invoking discover_tools or
	// execute_code from inside the JS sandbox. Both are top-level MCP tools,
	// not toolmesh.* members. The descriptions say "call discover_tools
	// first" — which is sometimes misread as "call toolmesh.discover_tools()
	// in the code". Without this guard, the JS engine raises a generic
	// "Object has no member 'discover_tools'" TypeError that does not point
	// the caller at the right fix. We only install the guard when no real
	// backend tool has claimed the same sanitized name.
	for _, name := range []string{toolDiscoverTools, toolExecuteCode} {
		if _, taken := view.nameMap[name]; taken {
			continue
		}
		guardName := name
		_ = tmObj.Set(guardName, func(_ goja.FunctionCall) goja.Value {
			panic(rt.NewGoError(fmt.Errorf(
				"toolmesh.%s is not a backend tool — %s is a separate MCP tool. "+
					"For in-sandbox discovery use toolmesh.discover(\"<free text>\") and "+
					"toolmesh.describe(\"<tool_name>\") instead",
				guardName, guardName,
			)))
		})
	}

	if err := rt.Set("toolmesh", tmObj); err != nil {
		return nil, fmt.Errorf("execute_code: set toolmesh: %w", err)
	}

	// Set up context cancellation → interrupt the goja runtime
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rt.Interrupt(fmt.Errorf("execute_code: %w", ctx.Err()))
		case <-done:
		}
	}()

	// Wrap code in async IIFE so `await` works on toolmesh.* calls
	wrappedCode := fmt.Sprintf("(async function() {\n\"use strict\";\n%s\n})()", code)

	val, err := rt.RunString(wrappedCode)
	if err != nil {
		outcome = failedOutcome(ctx)
		var interrupt *goja.InterruptedError
		if errors.As(err, &interrupt) {
			return r.errorResult(results, console),
				fmt.Errorf("execute_code: interrupted: %s", interrupt.Value())
		}
		return r.errorResult(results, console),
			fmt.Errorf("execute_code: %w", err)
	}

	// Resolve promise
	retVal, err := composite.ResolvePromise(val)
	if err != nil {
		outcome = failedOutcome(ctx)
		return r.errorResult(results, console),
			fmt.Errorf("execute_code: %w", err)
	}

	// The script ran to completion. Each failed tool call it saw was handed
	// to it as a value, not thrown, so the script may have carried on
	// without the data; count them, once per backend and reason.
	outcome = metrics.ScriptOutcomeOK
	for f := range failed {
		r.metrics.RecordSwallowedError(f.backend, f.reason)
	}

	// If we have tool call results, return them in the standard format.
	// Include the JS return value if present. An explicit return value is
	// the script's own projection of the data it fetched — echoing every
	// full tool result next to it would transport the same payload twice
	// and defeat Code Mode's token economy, so successful call entries are
	// compacted to {tool, status, resultBytes} unless the caller asked for
	// the full echo via include_results.
	if len(results) > 0 {
		if retVal != nil {
			if !opts.IncludeResults {
				results = compactCallResults(results)
			}
			results = append(results, map[string]any{
				resultKeyReturn: retVal,
			})
		}
		return r.buildResult(results, console), nil
	}

	// No tool calls — if the code returned a value, return it
	if retVal != nil {
		retJSON, err := json.Marshal(retVal)
		if err != nil {
			return nil, fmt.Errorf("execute_code: marshal return value: %w", err)
		}
		return &backend.ToolResult{
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: string(retJSON),
			}},
		}, nil
	}

	// No tool calls, no return value
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: "no tool calls found in code",
		}},
	}, nil
}

// installDiscovery registers the local discovery helpers on the toolmesh
// object, answering from the run's tool set. Real backend tools win
// sanitized-name collisions; in that case the helper is simply not installed.
func (r *CodeRunner) installDiscovery(ctx context.Context, rt *goja.Runtime, tmObj *goja.Object, view *toolView) {
	if _, taken := view.nameMap[sandboxDiscoverFn]; !taken {
		_ = tmObj.Set(sandboxDiscoverFn, func(call goja.FunctionCall) goja.Value {
			query := strings.TrimSpace(call.Argument(0).String())
			if query == "" || query == "undefined" {
				panic(rt.NewGoError(fmt.Errorf(
					"toolmesh.discover: pass a non-empty free-text query, e.g. toolmesh.discover(\"dns record\")")))
			}

			limit := int64(discoverQueryLimit)
			if len(call.Arguments) > 1 {
				if n := call.Argument(1).ToInteger(); n > 0 {
					limit = n
				}
			}

			descs, notes := r.visibleMatches(ctx, view, query)
			if int64(len(descs)) > limit {
				descs = descs[:limit]
			}

			out := make([]map[string]any, len(descs))
			for i, d := range descs {
				out[i] = map[string]any{
					jsonKeyName:          sanitizeName(d.Name),
					schemaKeyDescription: d.Description,
					argNameBackend:       d.Backend,
				}
				if d.Access != "" {
					out[i]["access"] = d.Access
				}
				if kits := notes[d.Name]; len(kits) > 0 {
					out[i][jsonKeyGrantRequired] = kits
				}
			}
			return rt.ToValue(out)
		})
	}

	if _, taken := view.nameMap[sandboxDescribeFn]; !taken {
		_ = tmObj.Set(sandboxDescribeFn, func(call goja.FunctionCall) goja.Value {
			name := call.Argument(0).String()
			d, ok := view.descBySanitized[name]
			if !ok {
				d, ok = view.descBySanitized[sanitizeName(name)]
			}
			var kits []string
			if ok {
				// A tool the caller may neither invoke nor get a kit for is
				// deliberately indistinguishable from "not found", so the
				// sandbox cannot probe for it.
				ok, kits = r.visibleTool(ctx, d)
			}
			if !ok {
				panic(rt.NewGoError(fmt.Errorf(
					"toolmesh.describe: unknown tool %q — use toolmesh.discover(\"<free text>\") to find available tools", name)))
			}

			desc := map[string]any{
				jsonKeyName:          sanitizeName(d.Name),
				schemaKeyDescription: d.Description,
				argNameBackend:       d.Backend,
				"inputSchema":        d.InputSchema,
			}
			if d.Access != "" {
				desc["access"] = d.Access
			}
			if len(kits) > 0 {
				desc[jsonKeyGrantRequired] = kits
			}
			return rt.ToValue(desc)
		})
	}
}

// visibleMatches runs a BM25 search over the view's tools and keeps the
// descriptors the calling user may execute or get through a kit, preserving
// rank order. The notes name the kits of the latter.
func (r *CodeRunner) visibleMatches(ctx context.Context, view *toolView, query string) ([]backend.ToolDescriptor, grantNotes) {
	results := view.index.Search(query, 0)
	descs := make([]backend.ToolDescriptor, 0, len(results))
	for _, res := range results {
		if d, ok := view.descBySanitized[res.Doc.Name]; ok {
			descs = append(descs, d)
		}
	}

	uc := userctx.FromContext(ctx)
	if r.executor == nil || uc == nil {
		return descs, nil
	}
	return visibleTools(ctx, r.executor, uc, descs)
}

// visibleTool reports whether the calling user may see the tool and, when
// it may only get it through a kit, which kits cover it.
func (r *CodeRunner) visibleTool(ctx context.Context, d backend.ToolDescriptor) (visible bool, kits []string) {
	uc := userctx.FromContext(ctx)
	if r.executor == nil || uc == nil {
		return true, nil
	}
	shown, notes := visibleTools(ctx, r.executor, uc, []backend.ToolDescriptor{d})
	return len(shown) == 1, notes[d.Name]
}

// backendLabel names the backend that owns a tool for the metrics, resolved
// the way the call is routed rather than by splitting the name.
func (r *CodeRunner) backendLabel(toolName string) string {
	if r.backends != nil {
		if name, ok := r.backends.ResolveBackendName(toolName); ok {
			return name
		}
	}
	return metricsBackendUnknown
}

// initSwallowedErrors creates the swallowed-error series of every backend a
// script can call at zero, the built-in tools included.
func (r *CodeRunner) initSwallowedErrors(tools []backend.ToolDescriptor) {
	if r.metrics == nil {
		return
	}
	seen := make(map[string]struct{}, len(tools))
	names := make([]string, 0, len(tools)+1)
	add := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	for _, t := range tools {
		add(r.backendLabel(t.Name))
	}
	if len(r.metaTools) > 0 {
		add(metricsBackendBuiltin)
	}
	r.metrics.InitSwallowedErrors(names)
}

// failedOutcome classifies a script that did not run to completion: a timeout
// when its wall-clock budget ran out, an error otherwise (a canceled request
// included).
func failedOutcome(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return metrics.ScriptOutcomeTimeout
	}
	return metrics.ScriptOutcomeError
}

// errorResult is the buildResult variant used in error paths: it surfaces
// partial results when at least one tool call ran before the error, and
// returns nil otherwise. Returning nil tells the handler to emit only the
// real error message instead of also surfacing buildResult's misleading
// "no tool calls found in code" placeholder. The placeholder is appropriate
// when the success path lands on an empty results slice (i.e. the code had
// no toolmesh.* calls at all), but in an error path the actual error is
// the message the caller needs to see.
func (r *CodeRunner) errorResult(results []any, console []string) *backend.ToolResult {
	if len(results) == 0 {
		return nil
	}
	return r.buildResult(results, console)
}

// buildResult marshals collected tool call results into the standard JSON format.
func (r *CodeRunner) buildResult(results []any, console []string) *backend.ToolResult {
	if len(results) == 0 {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: "no tool calls found in code",
			}},
		}
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				contentKeyType: contentKeyText,
				contentKeyText: fmt.Sprintf("marshal results: %s", err),
			}},
		}
	}

	r.logger.Debug("execute_code complete",
		"resultJSON", string(resultJSON),
		"consoleLines", len(console),
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: string(resultJSON),
		}},
	}
}

// compactCallResults replaces each successful full-result entry with a
// compact {tool, status, resultBytes} summary, where resultBytes measures
// the content payload the entry carried before compaction. Entries holding
// an error — dispatch failures ({tool, error}) and tool-level failures
// (result with IsError) — are kept in full so the caller retains the
// diagnostic message without having to re-run side-effectful calls.
func compactCallResults(results []any) []any {
	compacted := make([]any, len(results))
	for i, entry := range results {
		m, ok := entry.(map[string]any)
		if !ok {
			compacted[i] = entry
			continue
		}
		tr, ok := m[resultKeyResult].(*backend.ToolResult)
		if !ok || tr == nil || tr.IsError {
			compacted[i] = entry
			continue
		}
		compact := map[string]any{
			logKeyTool:      m[logKeyTool],
			resultKeyStatus: resultStatusOK,
			resultKeyBytes:  contentBytes(tr),
		}
		// Carry the notice through compaction — it is the one part of the
		// entry the caller cannot recover by re-reading the returned data.
		if notice, ok := m[resultKeyNotice]; ok {
			compact[resultKeyNotice] = notice
		}
		compacted[i] = compact
	}
	return compacted
}

// contentBytes measures the serialized size of a result's content blocks:
// text blocks count their text length, other blocks their JSON encoding.
func contentBytes(tr *backend.ToolResult) int {
	total := 0
	for _, item := range tr.Content {
		if m, ok := item.(map[string]any); ok {
			if text, ok := m[contentKeyText].(string); ok && m[contentKeyType] == contentKeyText {
				total += len(text)
				continue
			}
		}
		if b, err := json.Marshal(item); err == nil {
			total += len(b)
		}
	}
	return total
}

// extractJSValue extracts the actual API response content from a ToolResult
// for use inside JavaScript. It finds the first text content block, attempts
// to parse it as JSON, and returns the parsed value. If parsing fails, it
// returns the raw string. This lets JS code access response fields directly
// (e.g. result.id) instead of navigating the ToolMesh envelope.
func extractJSValue(rt *goja.Runtime, result *backend.ToolResult) goja.Value {
	if result == nil || len(result.Content) == 0 {
		return goja.Undefined()
	}

	// Find the first text content block
	for _, item := range result.Content {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if m[contentKeyType] != contentKeyText {
			continue
		}
		text, ok := m[contentKeyText].(string)
		if !ok {
			continue
		}

		// Try to parse as JSON — most API responses are JSON
		var parsed any
		if err := json.Unmarshal([]byte(text), &parsed); err == nil {
			return rt.ToValue(parsed)
		}

		// Not JSON — return the raw string
		return rt.ToValue(text)
	}

	// No text content found — return the raw result
	return rt.ToValue(result)
}
