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

package composite

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/dop251/goja"
)

// MaxAPICalls is the maximum number of api.* calls allowed in a single composite execution.
const MaxAPICalls = 50

// Result holds the output of a composite execution.
type Result struct {
	Value         any          `json:"value"`
	ConsoleOutput []string     `json:"console_output,omitempty"`
	AuditEvents   []AuditEvent `json:"audit_events,omitempty"`
}

// timeNow and timeSince are variables to allow test overrides.
var (
	timeNow   = time.Now
	timeSince = time.Since
)

// Execute runs a composite tool in a sandboxed goja runtime.
// A fresh runtime is created per call (no reuse for isolation).
// The executor function is used for api.* calls to primitive tools.
func Execute(
	ctx context.Context,
	comp *dadl.CompositeDef,
	compositeName string,
	toolNames []string,
	executor ToolExecutor,
	params map[string]any,
) (*Result, error) {
	if comp == nil {
		return nil, fmt.Errorf("composite %s: definition is nil", compositeName)
	}

	// Apply timeout
	timeout := comp.CompositeTimeout()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var (
		callCount     int
		mu            sync.Mutex
		auditEvents   []AuditEvent
		consoleOutput []string
	)

	rt, err := newRuntime(
		ctx, compositeName, toolNames, executor, params,
		&callCount, MaxAPICalls, &mu, &auditEvents, &consoleOutput,
	)
	if err != nil {
		return nil, err
	}

	// Set up context cancellation → interrupt the goja runtime
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rt.Interrupt(fmt.Errorf("composite %s: %w", compositeName, ctx.Err()))
		case <-done:
		}
	}()

	// Wrap code in an async IIFE so `await` works on api.* calls.
	// goja processes the microtask queue (Promises) in leave() when RunString returns,
	// so the Promise will be resolved by the time we inspect it.
	wrappedCode := fmt.Sprintf("(async function() {\n\"use strict\";\n%s\n})()", comp.Code)

	val, err := rt.RunString(wrappedCode)
	if err != nil {
		var interrupt *goja.InterruptedError
		if errors.As(err, &interrupt) {
			return &Result{
				ConsoleOutput: consoleOutput,
				AuditEvents:   auditEvents,
			}, fmt.Errorf("composite %s: interrupted: %s", compositeName, interrupt.Value())
		}
		return &Result{
			ConsoleOutput: consoleOutput,
			AuditEvents:   auditEvents,
		}, fmt.Errorf("composite %s: %w", compositeName, err)
	}

	// Resolve promise — goja's leave() already drained the microtask queue
	result, err := ResolvePromise(val)
	if err != nil {
		return &Result{
			ConsoleOutput: consoleOutput,
			AuditEvents:   auditEvents,
		}, fmt.Errorf("composite %s: %w", compositeName, err)
	}

	return &Result{
		Value:         result,
		ConsoleOutput: consoleOutput,
		AuditEvents:   auditEvents,
	}, nil
}

// ResolvePromise extracts the resolved value from a goja Promise.
// goja processes its microtask queue before returning from RunString,
// so the Promise should already be fulfilled or rejected.
func ResolvePromise(val goja.Value) (any, error) {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return nil, nil
	}

	promise, ok := val.Export().(*goja.Promise)
	if !ok {
		return val.Export(), nil
	}

	switch promise.State() {
	case goja.PromiseStateFulfilled:
		result := promise.Result()
		if result == nil || goja.IsUndefined(result) || goja.IsNull(result) {
			return nil, nil
		}
		return result.Export(), nil
	case goja.PromiseStateRejected:
		result := promise.Result()
		if result == nil {
			return nil, fmt.Errorf("promise rejected with nil")
		}
		return nil, fmt.Errorf("promise rejected: %s", result.String())
	default:
		return nil, fmt.Errorf("promise still pending after execution")
	}
}
