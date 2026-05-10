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

package backend

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
)

// compositeState holds an immutable snapshot of the composite backend's state.
// All reads use a single atomic load with zero lock contention.
type compositeState struct {
	backends     map[string]ToolBackend
	passthroughs []ToolBackend
}

// CompositeBackend aggregates multiple ToolBackend instances.
// Named backends get tool names prefixed: "backendName_toolName".
// Passthrough backends already manage their own prefixes (e.g. MCPAdapter).
//
// State is stored behind an atomic.Pointer for lock-free reads on the hot path
// (Execute, ListTools). Mutations create a shallow copy and atomically swap.
type CompositeBackend struct {
	state atomic.Pointer[compositeState]
}

// NewCompositeBackend creates a CompositeBackend from named backends.
func NewCompositeBackend(backends map[string]ToolBackend) *CompositeBackend {
	c := &CompositeBackend{}
	c.state.Store(&compositeState{
		backends:     backends,
		passthroughs: nil,
	})
	return c
}

// AddPassthrough adds a backend that manages its own tool name prefixes.
// Tool calls are delegated to passthrough backends when no named backend matches.
func (c *CompositeBackend) AddPassthrough(b ToolBackend) {
	for {
		old := c.state.Load()
		next := &compositeState{
			backends:     old.backends,
			passthroughs: append(append([]ToolBackend(nil), old.passthroughs...), b),
		}
		if c.state.CompareAndSwap(old, next) {
			return
		}
	}
}

// Execute routes the tool call to the correct backend based on the name prefix.
// Tool names use underscore as separator: "backend_toolname".
// We match against known backend names (longest prefix wins).
//
// Collapse fallback: when the tool name exactly equals a registered backend
// name, the call is routed to that backend's same-named tool. This supports
// the expose_tools convention where a backend named after its single primary
// tool advertises the bare name (e.g. backend "web_search" exposes tool
// "web_search" as just "web_search", not "web_search_web_search"). Standard
// prefix routing still wins when both apply.
func (c *CompositeBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	s := c.state.Load()

	// Check named backends by prefix match
	var collapseTarget ToolBackend
	for name, b := range s.backends {
		prefix := name + "_"
		if strings.HasPrefix(toolName, prefix) {
			realTool := strings.TrimPrefix(toolName, prefix)
			return b.Execute(ctx, realTool, params)
		}
		if toolName == name {
			// Defer the collapse dispatch until after the prefix loop so a
			// real prefix match elsewhere still wins.
			collapseTarget = b
		}
	}
	if collapseTarget != nil {
		return collapseTarget.Execute(ctx, toolName, params)
	}

	// Try passthrough backends (they handle their own routing)
	for _, b := range s.passthroughs {
		result, err := b.Execute(ctx, toolName, params)
		if err == nil {
			return result, nil
		}
		// If the passthrough recognized the tool but execution failed,
		// return the actual error instead of "no backend found".
		if !strings.Contains(err.Error(), "no backend found") {
			return nil, err
		}
	}

	return nil, fmt.Errorf("no backend found for tool %q", toolName)
}

// ListTools aggregates tools from all backends.
func (c *CompositeBackend) ListTools(ctx context.Context) ([]ToolDescriptor, error) {
	s := c.state.Load()

	var all []ToolDescriptor

	// Named backends — prefix tool names with underscore separator
	// (MCP spec requires tool names to match [a-zA-Z0-9_-])
	for name, b := range s.backends {
		tools, err := b.ListTools(ctx)
		if err != nil {
			continue
		}
		for _, t := range tools {
			all = append(all, ToolDescriptor{
				Name:        name + "_" + t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
				Backend:     t.Backend,
			})
		}
	}

	// Passthrough backends — tools already have prefixes
	for _, b := range s.passthroughs {
		tools, err := b.ListTools(ctx)
		if err != nil {
			continue
		}
		all = append(all, tools...)
	}

	return all, nil
}

// AddNamed adds a named backend after construction.
func (c *CompositeBackend) AddNamed(name string, b ToolBackend) {
	for {
		old := c.state.Load()
		newMap := make(map[string]ToolBackend, len(old.backends)+1)
		for k, v := range old.backends {
			newMap[k] = v
		}
		newMap[name] = b
		next := &compositeState{
			backends:     newMap,
			passthroughs: old.passthroughs,
		}
		if c.state.CompareAndSwap(old, next) {
			return
		}
	}
}

// Swap atomically replaces the entire composite state (named backends and
// passthroughs) with the provided values. Concurrent readers see either the
// old or the new state — never a mix. Use this for hot-reload scenarios.
func (c *CompositeBackend) Swap(backends map[string]ToolBackend, passthroughs []ToolBackend) {
	c.state.Store(&compositeState{
		backends:     backends,
		passthroughs: passthroughs,
	})
}

// LookupTool routes the lookup to the matching named backend (by tool name
// prefix) or falls back to passthrough backends. Returns the descriptor with
// the Access classification when available, or false if no backend owns the
// tool. Backends that do not implement ToolMetadataLookup are skipped silently.
//
// Mirrors [CompositeBackend.Execute] in honoring the collapse fallback: a
// bare tool name that exactly matches a backend name resolves to that
// backend's same-named tool, supporting the expose_tools collapse convention.
func (c *CompositeBackend) LookupTool(toolName string) (ToolDescriptor, bool) {
	s := c.state.Load()

	for name, b := range s.backends {
		prefix := name + "_"
		switch {
		case strings.HasPrefix(toolName, prefix):
			lookup, ok := b.(ToolMetadataLookup)
			if !ok {
				return ToolDescriptor{}, false
			}
			realTool := strings.TrimPrefix(toolName, prefix)
			desc, found := lookup.LookupTool(realTool)
			if !found {
				return ToolDescriptor{}, false
			}
			// Re-apply the public prefix so callers receive the same name they
			// passed in (named backends store tools under their bare names).
			desc.Name = toolName
			return desc, true
		case toolName == name:
			lookup, ok := b.(ToolMetadataLookup)
			if !ok {
				continue
			}
			if desc, found := lookup.LookupTool(toolName); found {
				desc.Name = toolName
				return desc, true
			}
		}
	}

	for _, b := range s.passthroughs {
		lookup, ok := b.(ToolMetadataLookup)
		if !ok {
			continue
		}
		if desc, found := lookup.LookupTool(toolName); found {
			return desc, true
		}
	}

	return ToolDescriptor{}, false
}

// BackendSummaries collects summaries from all backends that implement BackendSummarizer.
func (c *CompositeBackend) BackendSummaries() []BackendInfo {
	s := c.state.Load()

	var all []BackendInfo
	for _, b := range s.backends {
		if sum, ok := b.(BackendSummarizer); ok {
			all = append(all, sum.BackendSummaries()...)
		}
	}
	for _, b := range s.passthroughs {
		if sum, ok := b.(BackendSummarizer); ok {
			all = append(all, sum.BackendSummaries()...)
		}
	}
	return all
}

// PromotedTools aggregates direct-exposed tools from all child backends that
// implement [ToolPromoter]. Each child returns descriptors with public,
// prefixed MCP names already applied so the composite's only job is to merge
// and de-duplicate by name (last writer wins for a given name — collisions
// would indicate a configuration bug, not normal operation).
func (c *CompositeBackend) PromotedTools() []ToolDescriptor {
	s := c.state.Load()

	collect := func(b ToolBackend) []ToolDescriptor {
		if p, ok := b.(ToolPromoter); ok {
			return p.PromotedTools()
		}
		return nil
	}

	seen := make(map[string]struct{})
	var all []ToolDescriptor
	add := func(descs []ToolDescriptor) {
		for _, d := range descs {
			if _, dup := seen[d.Name]; dup {
				continue
			}
			seen[d.Name] = struct{}{}
			all = append(all, d)
		}
	}

	for _, b := range s.backends {
		add(collect(b))
	}
	for _, b := range s.passthroughs {
		add(collect(b))
	}
	return all
}

// Healthy returns nil if at least one backend is healthy.
func (c *CompositeBackend) Healthy(ctx context.Context) error {
	s := c.state.Load()

	for _, b := range s.backends {
		if err := b.Healthy(ctx); err == nil {
			return nil
		}
	}
	for _, b := range s.passthroughs {
		if err := b.Healthy(ctx); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no healthy backends")
}
