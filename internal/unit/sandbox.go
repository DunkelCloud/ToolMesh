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

package unit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sync"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/dop251/goja"
)

// identifierRE accepts the same identifier shape as JS plus the dash that
// MCP tool names sometimes use. We disallow dashes for the tool name itself
// (it must be a valid JS identifier so we can call it from RunString) but
// allow them for sub-backend names where lookup goes through map indexing.
var (
	toolNameRE       = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	subBackendNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)
)

// callDescribe loads the JavaScript source into a sandboxed goja runtime
// and invokes the top-level describe() function. The returned descriptors
// have their Name and InputSchema fields populated; Backend stays empty
// here and is stamped by the caller.
func callDescribe(ctx context.Context, unitName, source, sourcePath string, subBackendNames []string) ([]backend.ToolDescriptor, error) {
	rt := newBareRuntime()

	// Wire context cancellation → goja interrupt.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rt.Interrupt(fmt.Errorf("unit %s: %w", unitName, ctx.Err()))
		case <-done:
		}
	}()

	if _, err := rt.RunString(source); err != nil {
		return nil, fmt.Errorf("load %s: %w", sourcePath, err)
	}

	describeVal := rt.Get("describe")
	if describeVal == nil || goja.IsUndefined(describeVal) || goja.IsNull(describeVal) {
		return nil, fmt.Errorf("unit %s: %s must define a top-level describe() function", unitName, sourcePath)
	}
	describeFn, ok := goja.AssertFunction(describeVal)
	if !ok {
		return nil, fmt.Errorf("unit %s: describe is not callable", unitName)
	}

	result, err := describeFn(goja.Undefined())
	if err != nil {
		return nil, fmt.Errorf("unit %s: describe() threw: %w", unitName, err)
	}
	resolved, err := composite.ResolvePromise(result)
	if err != nil {
		return nil, fmt.Errorf("unit %s: describe() promise: %w", unitName, err)
	}

	descs, err := descriptorsFromDescribeResult(resolved)
	if err != nil {
		return nil, fmt.Errorf("unit %s: %w", unitName, err)
	}

	// Ensure no described tool collides with a sub-backend name — that
	// would make the api binding ambiguous to a reader of the JS code,
	// even if Go-side namespacing keeps it unambiguous.
	subSet := make(map[string]struct{}, len(subBackendNames))
	for _, n := range subBackendNames {
		subSet[n] = struct{}{}
	}
	for _, d := range descs {
		if _, clash := subSet[d.Name]; clash {
			return nil, fmt.Errorf("unit %s: tool %q collides with sub-backend name", unitName, d.Name)
		}
	}
	return descs, nil
}

// callExportedFunction runs the unit's source, looks up the exported
// function by toolName, and invokes it with the params object. The api.*
// proxy is installed first so the function can reach its sub-backends. The
// returned value is the resolved Promise result (or the direct value if the
// function is synchronous).
func callExportedFunction(
	ctx context.Context,
	unitName, source, sourcePath, toolName string,
	params map[string]any,
	subBackends map[string]backend.ToolBackend,
	maxCallDepth, maxAPICalls int,
) (any, error) {
	if !toolNameRE.MatchString(toolName) {
		return nil, fmt.Errorf("unit %s: invalid tool name %q", unitName, toolName)
	}

	rt := newBareRuntime()
	if err := installAPI(rt, ctx, unitName, subBackends, maxCallDepth, maxAPICalls); err != nil {
		return nil, fmt.Errorf("unit %s: install api: %w", unitName, err)
	}

	// Provide params via a stable global rather than as a function arg so
	// the wrapper does not have to JSON-encode the params back into JS
	// source.
	if params == nil {
		params = map[string]any{}
	}
	if err := rt.Set("__toolmesh_params", params); err != nil {
		return nil, fmt.Errorf("unit %s: set params: %w", unitName, err)
	}

	// Wire context cancellation → goja interrupt.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			rt.Interrupt(fmt.Errorf("unit %s: %w", unitName, ctx.Err()))
		case <-done:
		}
	}()

	if _, err := rt.RunString(source); err != nil {
		return nil, fmt.Errorf("unit %s: load %s: %w", unitName, sourcePath, err)
	}

	fnVal := rt.Get(toolName)
	if fnVal == nil || goja.IsUndefined(fnVal) || goja.IsNull(fnVal) {
		return nil, fmt.Errorf("unit %s: tool %q is not exported by %s", unitName, toolName, sourcePath)
	}
	if _, ok := goja.AssertFunction(fnVal); !ok {
		return nil, fmt.Errorf("unit %s: %q is not callable", unitName, toolName)
	}

	// Wrap the call in an async IIFE so await works regardless of whether
	// the exported function is async, and so the microtask queue drains
	// before RunString returns.
	wrap := fmt.Sprintf(`(async function(){ "use strict"; return await %s(__toolmesh_params); })()`, toolName)
	val, err := rt.RunString(wrap)
	if err != nil {
		var interrupt *goja.InterruptedError
		if errors.As(err, &interrupt) {
			return nil, fmt.Errorf("unit %s: interrupted: %s", unitName, interrupt.Value())
		}
		return nil, fmt.Errorf("unit %s: %s threw: %w", unitName, toolName, err)
	}
	resolved, err := composite.ResolvePromise(val)
	if err != nil {
		return nil, fmt.Errorf("unit %s: %s: %w", unitName, toolName, err)
	}
	return resolved, nil
}

// newBareRuntime returns a locked-down goja runtime with console.log
// captured into stderr-equivalent (slog at debug level via a no-op stub
// here — wiring to the real logger happens in installAPI when a logger
// is in scope).
func newBareRuntime() *goja.Runtime {
	rt := goja.New()
	composite.LockdownRuntime(rt)

	// Minimal console — discards output. Units that need to log should
	// surface signals via _meta or return values instead.
	consoleObj := rt.NewObject()
	_ = consoleObj.Set("log", func(_ goja.FunctionCall) goja.Value { return goja.Undefined() })
	_ = consoleObj.Set("error", func(_ goja.FunctionCall) goja.Value { return goja.Undefined() })
	_ = consoleObj.Set("warn", func(_ goja.FunctionCall) goja.Value { return goja.Undefined() })
	_ = rt.Set("console", consoleObj)

	return rt
}

// installAPI populates api.<sub>.<tool>(args) bindings for every entry in
// subBackends. A shared depth counter enforces maxCallDepth across all
// api.* calls in this invocation, matching the call-stack-tracking
// semantics required by the unit-backends architecture.
func installAPI(
	rt *goja.Runtime,
	ctx context.Context,
	unitName string,
	subBackends map[string]backend.ToolBackend,
	maxCallDepth, maxAPICalls int,
) error {
	apiObj := rt.NewObject()

	var (
		mu        sync.Mutex
		callDepth int
		callCount int
	)

	for subName, sub := range subBackends {
		if !subBackendNameRE.MatchString(subName) {
			return fmt.Errorf("invalid sub-backend name %q", subName)
		}
		subObj := rt.NewObject()
		subBackend := sub // capture
		owner := subName  // capture

		// Discover the sub-backend's tools so we can bind each one as
		// a callable on the sub-namespace.
		tools, err := subBackend.ListTools(ctx)
		if err != nil {
			return fmt.Errorf("list tools on sub-backend %q: %w", owner, err)
		}
		for _, td := range tools {
			toolName := td.Name // capture
			if !toolNameRE.MatchString(toolName) {
				// Sub-backends may expose tool names with chars we
				// cannot bind as JS identifiers. We still bind via
				// computed property names (apiObj.Set works regardless),
				// but skip if it is an unsafe shape.
				continue
			}
			_ = subObj.Set(toolName, makeAPICall(rt, ctx, unitName, owner, toolName, subBackend, &mu, &callDepth, &callCount, maxCallDepth, maxAPICalls))
		}
		if err := apiObj.Set(subName, subObj); err != nil {
			return fmt.Errorf("bind api.%s: %w", subName, err)
		}
	}

	return rt.Set("api", apiObj)
}

// makeAPICall returns the JS-callable function that, when invoked, executes
// one tool on the named sub-backend. Depth bookkeeping is enforced inside
// the closure so a single invocation budget is shared across every api.*
// call in this run.
func makeAPICall(
	rt *goja.Runtime,
	ctx context.Context,
	unitName, subName, toolName string,
	sub backend.ToolBackend,
	mu *sync.Mutex,
	callDepth, callCount *int,
	maxCallDepth, maxAPICalls int,
) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		mu.Lock()
		*callDepth++
		*callCount++
		depth := *callDepth
		count := *callCount
		mu.Unlock()
		defer func() {
			mu.Lock()
			*callDepth--
			mu.Unlock()
		}()

		if depth > maxCallDepth {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: max call depth %d exceeded", unitName, subName, toolName, maxCallDepth)))
		}
		if count > maxAPICalls {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: exceeded %d api.* calls per invocation", unitName, subName, toolName, maxAPICalls)))
		}
		if err := ctx.Err(); err != nil {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: %w", unitName, subName, toolName, err)))
		}

		var params map[string]any
		if len(call.Arguments) > 0 {
			exp := call.Arguments[0].Export()
			if m, ok := exp.(map[string]any); ok {
				params = m
			}
		}
		if params == nil {
			params = map[string]any{}
		}

		result, err := sub.Execute(ctx, toolName, params)
		if err != nil {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: %w", unitName, subName, toolName, err)))
		}
		// Marshal result through JSON so the JS side sees a plain object
		// rather than a Go-typed wrapper that goja exposes inconsistently.
		raw, err := json.Marshal(result)
		if err != nil {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: marshal result: %w", unitName, subName, toolName, err)))
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			panic(rt.NewGoError(fmt.Errorf("unit %s: api.%s.%s: unmarshal result: %w", unitName, subName, toolName, err)))
		}
		return rt.ToValue(generic)
	}
}

// descriptorsFromDescribeResult validates the JS-side describe() output
// and converts it to ToolDescriptors. The expected shape is
// { tools: [{ name, description?, params?, access? }, ...] } — see the
// dice unit for a canonical example.
func descriptorsFromDescribeResult(v any) ([]backend.ToolDescriptor, error) {
	root, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("describe() must return an object")
	}
	rawTools, ok := root["tools"].([]any)
	if !ok {
		return nil, fmt.Errorf("describe().tools must be an array")
	}
	descs := make([]backend.ToolDescriptor, 0, len(rawTools))
	for i, rt := range rawTools {
		tm, ok := rt.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("describe().tools[%d] must be an object", i)
		}
		name, _ := tm["name"].(string)
		if !toolNameRE.MatchString(name) {
			return nil, fmt.Errorf("describe().tools[%d].name=%q is not a valid identifier", i, name)
		}
		desc, _ := tm["description"].(string)
		access, _ := tm["access"].(string)
		params, _ := tm["params"].(map[string]any)
		schema, err := paramsToSchema(params)
		if err != nil {
			return nil, fmt.Errorf("describe().tools[%d] %s: %w", i, name, err)
		}
		descs = append(descs, backend.ToolDescriptor{
			Name:        name,
			Description: desc,
			InputSchema: schema,
			Access:      access,
		})
	}
	return descs, nil
}

// paramsToSchema converts the describe()-style params block into a JSON
// Schema object. Recognized keys per parameter: type, description, required,
// enum. Anything else is passed through verbatim so the unit author can
// supply richer JSON Schema fragments when needed.
func paramsToSchema(params map[string]any) (map[string]any, error) {
	schema := map[string]any{schemaKeyType: schemaTypeObject}
	if len(params) == 0 {
		schema["properties"] = map[string]any{}
		return schema, nil
	}
	props := make(map[string]any, len(params))
	var required []any
	for paramName, raw := range params {
		pm, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("params[%s] must be an object", paramName)
		}
		entry := map[string]any{}
		for k, v := range pm {
			if k == "required" {
				if isTrue(v) {
					required = append(required, paramName)
				}
				continue
			}
			entry[k] = v
		}
		if _, hasType := entry["type"]; !hasType {
			entry["type"] = "string"
		}
		props[paramName] = entry
	}
	schema["properties"] = props
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema, nil
}

func isTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	default:
		return false
	}
}

// toolResultFromJS converts the JS-side return value from an exported unit
// function into the canonical ToolResult shape. Three forms are accepted:
//
//   - { content: [...], _meta?: {...} }  — already in MCP shape
//   - { ... }                            — any other object, wrapped as a single
//     JSON text block
//   - any non-object value               — stringified via fmt.Sprint and
//     wrapped as a text block.
func toolResultFromJS(v any) *backend.ToolResult {
	if v == nil {
		return &backend.ToolResult{Content: []any{}}
	}
	if m, ok := v.(map[string]any); ok {
		if rawContent, hasContent := m["content"].([]any); hasContent {
			res := &backend.ToolResult{Content: rawContent}
			if meta, ok := m["_meta"].(map[string]any); ok {
				res.Metadata = meta
			}
			return res
		}
		// Fall through: treat as a structured payload.
	}
	raw, err := json.Marshal(v)
	if err != nil {
		raw = []byte(fmt.Sprintf("%v", v))
	}
	return &backend.ToolResult{
		Content: []any{map[string]any{
			schemaKeyType:   contentTypeText,
			contentTypeText: string(raw),
		}},
	}
}
