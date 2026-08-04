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
	"log/slog"
	"strings"
	"sync"
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

	// logger receives WARN events when bare expose_tools aliases collide
	// with names reserved by upstream LLM clients (see reserved.go). nil
	// disables logging entirely. Set via SetLogger after construction.
	logger atomic.Pointer[slog.Logger]
	// warnedReservedAlias deduplicates the reserved-name WARN so the
	// message appears at most once per canonical name even though
	// PromotedTools is called on every tools/list request.
	warnedReservedAlias sync.Map // key: canonical "<backend>_<tool>", value: struct{}
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

// SetLogger configures the slog logger used to surface promotion-aliasing
// warnings. Pass nil to disable. Safe to call any time; the next
// PromotedTools call picks the new logger up.
func (c *CompositeBackend) SetLogger(logger *slog.Logger) {
	c.logger.Store(logger)
}

// SetChildGuard propagates a ChildGuard to every child backend that supports
// one (currently the REST adapters, which run composites). Call it after the
// executor is built so composite child api.* calls are authorized and gated.
func (c *CompositeBackend) SetChildGuard(g ChildGuard) {
	s := c.state.Load()
	for _, b := range s.backends {
		if setter, ok := b.(childGuardSetter); ok {
			setter.SetChildGuard(g)
		}
	}
	for _, b := range s.passthroughs {
		if setter, ok := b.(childGuardSetter); ok {
			setter.SetChildGuard(g)
		}
	}
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
//
// Routing rule: **longest matching prefix wins, across both layers**.
// Both directly-named backends and passthrough sub-backends (advertised via
// BackendSummarizer) contribute candidate prefixes; the longest match
// determines the target. This matters when one backend's name is itself a
// prefix of another's — e.g. unit "netdata" alongside an MCP sub-backend
// "netdata-raw": without longest-match the call "netdata_raw_query" would
// hit the unit, since Go map iteration is randomized. With longest-match
// it always lands on netdata-raw via the passthrough that owns it.
//
// Bare-name promoted tools (configured via backends.yaml expose_tools) are
// resolved to their canonical "<backend>_<tool>" form by the MCP handler
// before this method is called, so Execute itself only needs the standard
// prefix dispatch.
func (c *CompositeBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	s := c.state.Load()

	if match, ok := c.longestPrefix(toolName, s); ok && match.isNamed {
		realTool := strings.TrimPrefix(toolName, match.name+"_")
		return match.backend.Execute(ctx, realTool, params)
	}

	// Either no prefix matched at all, or a passthrough sub-backend
	// owns the longest prefix. Passthroughs handle their own routing,
	// so hand them the full tool name in their registered order.
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

// prefixMatch is the result of CompositeBackend.longestPrefix.
type prefixMatch struct {
	// isNamed is true when the matched backend is a directly-named entry
	// that the composite can dispatch to itself; false when the matched
	// prefix belongs to a passthrough sub-backend (the passthrough owns
	// the actual routing).
	isNamed bool
	// name is the backend name (the part before the underscore separator),
	// useful for trimming the prefix off the tool name.
	name string
	// backend is the named backend to dispatch to; only set when isNamed.
	backend ToolBackend
	// length is the byte length of the matching prefix including the
	// trailing underscore. Used as the tie-breaker key.
	length int
}

// longestPrefix scans every candidate prefix — both directly-named
// backends and passthrough sub-backends advertised via BackendSummarizer
// — and returns the longest match for toolName. Ties prefer named
// backends so explicit registration wins over aggregated discovery.
func (c *CompositeBackend) longestPrefix(toolName string, s *compositeState) (prefixMatch, bool) {
	var best prefixMatch
	found := false

	for name, b := range s.backends {
		prefix := name + "_"
		if !strings.HasPrefix(toolName, prefix) {
			continue
		}
		if !found || len(prefix) > best.length {
			best = prefixMatch{isNamed: true, name: name, backend: b, length: len(prefix)}
			found = true
		}
	}

	for _, b := range s.passthroughs {
		sum, ok := b.(BackendSummarizer)
		if !ok {
			continue
		}
		for _, info := range sum.BackendSummaries() {
			if info.Name == "" {
				continue
			}
			prefix := info.Name + "_"
			if !strings.HasPrefix(toolName, prefix) {
				continue
			}
			// Strict > so a named backend with equal-length prefix wins
			// the tie (named registration is explicit; passthrough
			// surfacing is derivative).
			if !found || len(prefix) > best.length {
				best = prefixMatch{isNamed: false, name: info.Name, length: len(prefix)}
				found = true
			}
		}
	}

	return best, found
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
// Uses the same longest-prefix-wins rule as Execute so AuthZ/Gate
// classification observes the same routing decision as the actual call.
//
// As with Execute, callers are expected to pass canonical "<backend>_<tool>"
// names; the handler resolves bare-name aliases ahead of this call.
func (c *CompositeBackend) LookupTool(toolName string) (ToolDescriptor, bool) {
	s := c.state.Load()

	if match, ok := c.longestPrefix(toolName, s); ok && match.isNamed {
		lookup, ok := match.backend.(ToolMetadataLookup)
		if !ok {
			return ToolDescriptor{}, false
		}
		realTool := strings.TrimPrefix(toolName, match.name+"_")
		desc, found := lookup.LookupTool(realTool)
		if !found {
			return ToolDescriptor{}, false
		}
		// Re-apply the public prefix so callers receive the same name they
		// passed in (named backends store tools under their bare names).
		desc.Name = toolName
		return desc, true
	}

	// Either no prefix matched, or a passthrough owns the longest prefix.
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

// ResolveBackendName reports which backend owns toolName, resolved with the
// same longest-prefix routing [CompositeBackend.Execute] uses, so the answer
// always matches where the call would actually go. Both directly-named
// backends and passthrough sub-backends are covered.
func (c *CompositeBackend) ResolveBackendName(toolName string) (string, bool) {
	match, ok := c.longestPrefix(toolName, c.state.Load())
	if !ok || match.name == "" {
		return "", false
	}
	return match.name, true
}

// BackendNames returns the names under which this CompositeBackend will
// route tool calls — both directly-named entries and the sub-backends
// surfaced via passthrough BackendSummaries. Use this for collision
// detection before registering a new named backend so a name conflict can
// be rejected at startup rather than silently overwriting state.
func (c *CompositeBackend) BackendNames() []string {
	s := c.state.Load()
	seen := make(map[string]struct{}, len(s.backends))
	for name := range s.backends {
		seen[name] = struct{}{}
	}
	for _, b := range s.passthroughs {
		sum, ok := b.(BackendSummarizer)
		if !ok {
			continue
		}
		for _, info := range sum.BackendSummaries() {
			if info.Name != "" {
				seen[info.Name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	return out
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
// implement [ToolPromoter] and resolves bare-name conflicts.
//
// Each child returns Promotions with bare Descriptor.Name (e.g. "web_search")
// and an explicit Canonical "<backend>_<tool>" routing form. The composite
// demotes a bare name to its Canonical form when either:
//
//  1. two backends would advertise the same bare name, or
//  2. the bare name collides with a built-in tool type reserved by a known
//     upstream LLM client (see [IsReservedClientToolName]).
//
// Non-conflicting bare names pass through unchanged. Case (2) emits a WARN
// log once per canonical name so operators can see that their expose_tools
// configuration triggered the reserved-name fallback.
//
// Returns Promotions in their resolved form so the handler can advertise
// Descriptor directly. Use [CompositeBackend.ResolveAlias] to translate the
// advertised name back to the canonical routing form on dispatch.
func (c *CompositeBackend) PromotedTools() []Promotion {
	s := c.state.Load()

	collect := func(b ToolBackend) []Promotion {
		if p, ok := b.(ToolPromoter); ok {
			return p.PromotedTools()
		}
		return nil
	}

	all := make([]Promotion, 0, len(s.backends)+len(s.passthroughs))
	for _, b := range s.backends {
		all = append(all, collect(b)...)
	}
	for _, b := range s.passthroughs {
		all = append(all, collect(b)...)
	}

	// Count bare names so we can detect cross-backend collisions.
	bareCounts := make(map[string]int, len(all))
	for _, p := range all {
		bareCounts[p.Descriptor.Name]++
	}

	// Resolve: conflicting bare names AND names reserved by upstream LLM
	// clients get demoted to their canonical form. De-dup by final advertised
	// name in case two backends both ended up with the same canonical
	// (shouldn't happen — backend names are unique — but a cheap safeguard
	// keeps the public surface well-defined).
	out := make([]Promotion, 0, len(all))
	seen := make(map[string]struct{}, len(all))
	for _, p := range all {
		bareName := p.Descriptor.Name
		switch {
		case bareCounts[bareName] > 1:
			p.Descriptor.Name = p.Canonical
		case IsReservedClientToolName(bareName):
			p.Descriptor.Name = p.Canonical
			c.warnReservedAlias(bareName, p.Canonical)
		}
		if _, dup := seen[p.Descriptor.Name]; dup {
			continue
		}
		seen[p.Descriptor.Name] = struct{}{}
		out = append(out, p)
	}
	return out
}

// warnReservedAlias emits a one-shot WARN log when a bare expose_tools
// alias collides with a name reserved by an upstream LLM client. The
// dedup keys on the canonical name, so each backend's reserved-name
// promotion logs at most once per process lifetime — PromotedTools may
// be called per tools/list request and we do not want to spam.
func (c *CompositeBackend) warnReservedAlias(bareName, canonical string) {
	if _, already := c.warnedReservedAlias.LoadOrStore(canonical, struct{}{}); already {
		return
	}
	logger := c.logger.Load()
	if logger == nil {
		return
	}
	logger.Warn("expose_tools alias collides with a reserved upstream tool name; promoting under canonical form to keep the MCP surface compatible with OpenAI's Responses API",
		"bare_name", bareName,
		"canonical_name", canonical,
	)
}

// ResolveAlias maps a bare promoted-tool name to its routing canonical
// "<backend>_<tool>" form, returning the input unchanged when no alias
// applies (i.e. the caller already used the canonical name, or the name is
// not a promoted tool at all). Computed against the live state on every
// call — no caching — so hot-reload of backends takes effect immediately.
func (c *CompositeBackend) ResolveAlias(name string) string {
	for _, p := range c.PromotedTools() {
		if p.Descriptor.Name == name && p.Descriptor.Name != p.Canonical {
			return p.Canonical
		}
	}
	return name
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
