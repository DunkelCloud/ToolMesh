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
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/dop251/goja"
)

// maxCodeCalls is the maximum number of toolmesh.* calls allowed per execution.
const maxCodeCalls = 50

// codeTimeout is the maximum duration for a single execute_code invocation.
const codeTimeout = 120 * time.Second

// CodeRunner executes JavaScript code in a sandboxed goja runtime,
// resolving toolmesh.* calls to real tool executions via the executor.
type CodeRunner struct {
	nameMap  map[string]string // sanitized JS name → canonical tool name
	executor *executor.Executor
	coercer  *tsdef.Coercer
	logger   *slog.Logger
}

// NewCodeRunner creates a CodeRunner with the given name mapping and executor.
func NewCodeRunner(nameMap map[string]string, exec *executor.Executor, coercer *tsdef.Coercer, logger *slog.Logger) *CodeRunner {
	return &CodeRunner{
		nameMap:  nameMap,
		executor: exec,
		coercer:  coercer,
		logger:   logger,
	}
}

// Execute runs JavaScript code in a sandboxed goja runtime.
// toolmesh.* calls are intercepted and dispatched to the executor.
// Returns a ToolResult with the collected results in the same JSON format
// as the previous static parser approach.
func (r *CodeRunner) Execute(ctx context.Context, code string) (*backend.ToolResult, error) {
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
				"type": "text",
				"text": fmt.Sprintf("execute_code: static analysis found forbidden patterns:\n%s", strings.Join(msgs, "\n")),
			}},
		}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, codeTimeout)
	defer cancel()

	var (
		callCount int
		mu        sync.Mutex
		results   []any
		console   []string
	)

	rt := goja.New()
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

	// Register toolmesh object with one method per tool
	tmObj := rt.NewObject()
	for sanitized, canonical := range r.nameMap {
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
				"tool", cn,
				"params", toolParams,
			)

			// Apply coercion
			if r.coercer != nil {
				coerced, err := r.coercer.Coerce(cn, toolParams)
				if err != nil {
					r.logger.DebugContext(ctx, "execute_code coercion failed",
						"tool", cn,
						"error", err,
					)
					mu.Lock()
					results = append(results, map[string]any{
						"tool":  cn,
						"error": fmt.Sprintf("coercion failed: %s", err),
					})
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
					"tool", cn,
					"error", err.Error(),
				)
				mu.Lock()
				results = append(results, map[string]any{
					"tool":  cn,
					"error": err.Error(),
				})
				mu.Unlock()
				// Return error object to JS instead of panicking.
				// This lets loops continue and subsequent calls execute.
				errObj := rt.NewObject()
				_ = errObj.Set("error", err.Error())
				_ = errObj.Set("tool", cn)
				return rt.ToValue(errObj)
			}

			// Log result
			if contentJSON, merr := json.Marshal(result.Content); merr == nil {
				r.logger.DebugContext(ctx, "execute_code tool result",
					"tool", cn,
					"isError", result.IsError,
					"content", string(contentJSON),
				)
			}

			// Collect result for the wire-format output
			mu.Lock()
			results = append(results, map[string]any{
				"tool":   cn,
				"result": result,
			})
			mu.Unlock()

			// Return the actual API response content for JS consumption,
			// not the ToolMesh wrapper. This lets JS code use result.field
			// directly instead of result.Content[0].text.
			return extractJSValue(rt, result)
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
		var interrupt *goja.InterruptedError
		if errors.As(err, &interrupt) {
			return r.buildResult(results, console),
				fmt.Errorf("execute_code: interrupted: %s", interrupt.Value())
		}
		return r.buildResult(results, console),
			fmt.Errorf("execute_code: %w", err)
	}

	// Resolve promise
	retVal, err := composite.ResolvePromise(val)
	if err != nil {
		return r.buildResult(results, console),
			fmt.Errorf("execute_code: %w", err)
	}

	// If we have tool call results, return them in the standard format.
	// Include the JS return value if present.
	if len(results) > 0 {
		if retVal != nil {
			results = append(results, map[string]any{
				"return": retVal,
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
				"type": "text",
				"text": string(retJSON),
			}},
		}, nil
	}

	// No tool calls, no return value
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			"type": "text",
			"text": "no tool calls found in code",
		}},
	}, nil
}

// buildResult marshals collected tool call results into the standard JSON format.
func (r *CodeRunner) buildResult(results []any, console []string) *backend.ToolResult {
	if len(results) == 0 {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": "no tool calls found in code",
			}},
		}
	}

	resultJSON, err := json.Marshal(results)
	if err != nil {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{
				"type": "text",
				"text": fmt.Sprintf("marshal results: %s", err),
			}},
		}
	}

	r.logger.Debug("execute_code complete",
		"resultJSON", string(resultJSON),
		"consoleLines", len(console),
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": string(resultJSON),
		}},
	}
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
		if m["type"] != "text" {
			continue
		}
		text, ok := m["text"].(string)
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
