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

// Package composite implements a sandboxed JavaScript execution engine for
// DADL composite tools. Each execution creates a fresh goja runtime with
// only api.* calls, params, and console.log available.
package composite

import (
	"context"
	"fmt"
	"sync"

	"github.com/dop251/goja"
)

// ToolExecutor is the function signature for executing a primitive tool.
// Returns the parsed result (any JSON-compatible value) and an error.
// The backend package wraps ToolBackend.Execute to match this signature.
type ToolExecutor func(ctx context.Context, toolName string, params map[string]any) (any, error)

// AuditEvent records a single api.* call within a composite execution.
type AuditEvent struct {
	ParentTool string `json:"parent_tool"`
	ChildTool  string `json:"child_tool"`
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

// newRuntime creates a fresh goja runtime configured for composite execution.
// It sets up the api object, params, and console.log capture.
func newRuntime(
	ctx context.Context,
	compositeName string,
	toolNames []string,
	executor ToolExecutor,
	params map[string]any,
	callCount *int,
	maxCalls int,
	mu *sync.Mutex,
	auditEvents *[]AuditEvent,
	consoleOutput *[]string,
) (*goja.Runtime, error) {
	rt := goja.New()

	// Lock down the sandbox first
	lockdownRuntime(rt)

	// Set up params object
	if params == nil {
		params = make(map[string]any)
	}
	if err := rt.Set("params", params); err != nil {
		return nil, fmt.Errorf("composite %s: set params: %w", compositeName, err)
	}

	// Set up console.log
	consoleObj := rt.NewObject()
	_ = consoleObj.Set("log", func(call goja.FunctionCall) goja.Value {
		var parts []string
		for _, arg := range call.Arguments {
			parts = append(parts, arg.String())
		}
		mu.Lock()
		*consoleOutput = append(*consoleOutput, fmt.Sprint(parts))
		mu.Unlock()
		return goja.Undefined()
	})
	if err := rt.Set("console", consoleObj); err != nil {
		return nil, fmt.Errorf("composite %s: set console: %w", compositeName, err)
	}

	// Set up api object with one method per primitive tool
	apiObj := rt.NewObject()
	for _, toolName := range toolNames {
		tn := toolName // capture for closure
		_ = apiObj.Set(tn, func(call goja.FunctionCall) goja.Value {
			// Check call count limit
			mu.Lock()
			*callCount++
			count := *callCount
			mu.Unlock()

			if count > maxCalls {
				panic(rt.NewGoError(fmt.Errorf("composite %s: exceeded maximum %d api calls", compositeName, maxCalls)))
			}

			// Check context cancellation
			if ctx.Err() != nil {
				panic(rt.NewGoError(fmt.Errorf("composite %s: %w", compositeName, ctx.Err())))
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

			// Execute the primitive tool
			start := timeNow()
			result, err := executor(ctx, tn, toolParams)
			elapsed := timeSince(start)

			event := AuditEvent{
				ParentTool: compositeName,
				ChildTool:  tn,
				LatencyMs:  elapsed.Milliseconds(),
			}
			if err != nil {
				event.Error = err.Error()
			}
			mu.Lock()
			*auditEvents = append(*auditEvents, event)
			mu.Unlock()

			if err != nil {
				panic(rt.NewGoError(fmt.Errorf("composite %s: api.%s failed: %w", compositeName, tn, err)))
			}

			return rt.ToValue(result)
		})
	}
	if err := rt.Set("api", apiObj); err != nil {
		return nil, fmt.Errorf("composite %s: set api: %w", compositeName, err)
	}

	return rt, nil
}
