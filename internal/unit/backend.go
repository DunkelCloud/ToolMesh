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
	"fmt"
	"log/slog"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// Backend implements backend.ToolBackend for a single Unit. Each call to
// Execute opens a fresh goja runtime with api.<sub>.<tool> bindings derived
// from the unit's private sub-backend map.
type Backend struct {
	name         string                         // public unit name, also the global prefix
	source       string                         // JavaScript source loaded from Implementation
	sourcePath   string                         // for error messages
	subBackends  map[string]backend.ToolBackend // private dependencies, addressable via api.<name>
	descriptors  []backend.ToolDescriptor       // populated by describe() at load time
	expose       ExposeConfig
	maxCallDepth int
	maxAPICalls  int
	logger       *slog.Logger
}

// New constructs a Unit backend. It does NOT call describe() — callers must
// invoke Init to populate the descriptor list once all sub-backends are
// ready. Splitting construction and initialization keeps the registry/loader
// flow explicit and lets tests pre-stub sub-backends.
func New(
	name, source, sourcePath string,
	subBackends map[string]backend.ToolBackend,
	expose ExposeConfig,
	logger *slog.Logger,
) *Backend {
	if logger == nil {
		logger = slog.Default()
	}
	return &Backend{
		name:         name,
		source:       source,
		sourcePath:   sourcePath,
		subBackends:  subBackends,
		expose:       expose,
		maxCallDepth: DefaultMaxCallDepth,
		maxAPICalls:  DefaultMaxAPICalls,
		logger:       logger,
	}
}

// Name returns the unit's public name (the prefix under which its tools are
// exposed to LLMs).
func (b *Backend) Name() string { return b.name }

// Init runs the unit's JavaScript describe() function once and stores the
// resulting ToolDescriptors. Call once after construction, before exposing
// the unit to the rest of the system.
func (b *Backend) Init(ctx context.Context) error {
	descs, err := callDescribe(ctx, b.name, b.source, b.sourcePath, b.subBackendNames())
	if err != nil {
		return fmt.Errorf("unit %s: describe: %w", b.name, err)
	}
	// Stamp every descriptor's Backend field so audit and metrics see
	// "unit:<name>" rather than an empty string.
	for i := range descs {
		descs[i].Backend = "unit:" + b.name
	}
	b.descriptors = descs

	// Surface expose.tools typos once, at load time, rather than letting a
	// misspelled name silently produce no promotion. PromotedTools skips the
	// same unknown entries on every request.
	for _, name := range b.expose.Tools {
		if _, ok := b.LookupTool(name); !ok {
			b.logger.Warn("unit expose.tools names an unknown tool; it will not be promoted",
				"unit", b.name, "tool", name)
		}
	}
	return nil
}

// ListTools returns the descriptors populated by Init. Returns an empty slice
// if Init has not been called or returned no tools.
func (b *Backend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	out := make([]backend.ToolDescriptor, len(b.descriptors))
	copy(out, b.descriptors)
	return out, nil
}

// LookupTool resolves a tool by its bare (un-prefixed) name. Implements
// backend.ToolMetadataLookup so the executor can attach the Access tag to
// the gate context.
func (b *Backend) LookupTool(toolName string) (backend.ToolDescriptor, bool) {
	for _, d := range b.descriptors {
		if d.Name == toolName {
			return d, true
		}
	}
	return backend.ToolDescriptor{}, false
}

// Compile-time proof that a unit participates in root-level tool promotion.
// The composite backend type-asserts every child against backend.ToolPromoter;
// without this a unit would silently never promote.
var _ backend.ToolPromoter = (*Backend)(nil)

// PromotedTools implements backend.ToolPromoter. It returns one Promotion per
// expose.tools entry that matches a describe()-declared tool, so the MCP
// handler can advertise those tools at the root in addition to
// discover_tools / execute_code.
//
// Both Descriptor.Name and Canonical are the full "<unit>_<tool>" form: unit
// tools are never promoted under a bare alias (see ExposeConfig.Tools for why),
// so the composite's bare-name conflict handling is a no-op for them and the
// advertised name equals the routing name. Unknown entries are skipped — Init
// has already logged them once — so a stale name never produces a phantom tool.
func (b *Backend) PromotedTools() []backend.Promotion {
	if len(b.expose.Tools) == 0 {
		return nil
	}
	out := make([]backend.Promotion, 0, len(b.expose.Tools))
	for _, name := range b.expose.Tools {
		desc, ok := b.LookupTool(name)
		if !ok {
			continue
		}
		canonical := b.name + "_" + name
		desc.Name = canonical
		out = append(out, backend.Promotion{
			Descriptor: desc,
			Canonical:  canonical,
		})
	}
	return out
}

// Healthy always returns nil for the unit itself; sub-backend health is
// reported separately by each sub-backend's Healthy() method (and is exposed
// through the global health endpoints when sub-backends are visible there).
func (b *Backend) Healthy(_ context.Context) error { return nil }

// Execute invokes the named exported function in the unit's JavaScript
// module. The function is invoked with a single argument: the params object
// passed by the caller. api.<sub>.<tool>(args) bindings are available inside
// the sandbox for every sub-backend declared in unit.yaml.
func (b *Backend) Execute(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	if _, ok := b.LookupTool(toolName); !ok {
		return nil, fmt.Errorf("unit %s: unknown tool %q", b.name, toolName)
	}
	value, err := callExportedFunction(ctx, b.name, b.source, b.sourcePath, toolName, params, b.subBackends, b.maxCallDepth, b.maxAPICalls)
	if err != nil {
		return nil, err
	}
	return toolResultFromJS(value), nil
}

// subBackendNames returns the deterministic list of sub-backend names for
// sandbox setup; sorted ordering keeps describe-time logs stable.
func (b *Backend) subBackendNames() []string {
	names := make([]string, 0, len(b.subBackends))
	for name := range b.subBackends {
		names = append(names, name)
	}
	return names
}
