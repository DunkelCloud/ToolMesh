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
)

// CompositeBackend aggregates multiple ToolBackend instances.
// Named backends get tool names prefixed: "backendName:toolName".
// Passthrough backends already manage their own prefixes (e.g. MCPAdapter).
type CompositeBackend struct {
	backends     map[string]ToolBackend
	passthroughs []ToolBackend
}

// NewCompositeBackend creates a CompositeBackend from named backends.
func NewCompositeBackend(backends map[string]ToolBackend) *CompositeBackend {
	return &CompositeBackend{backends: backends}
}

// AddPassthrough adds a backend that manages its own tool name prefixes.
// Tool calls are delegated to passthrough backends when no named backend matches.
func (c *CompositeBackend) AddPassthrough(b ToolBackend) {
	c.passthroughs = append(c.passthroughs, b)
}

// Execute routes the tool call to the correct backend based on the name prefix.
func (c *CompositeBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	backendName, realTool, err := splitToolName(toolName)
	if err != nil {
		return nil, err
	}

	// Check named backends first
	if b, ok := c.backends[backendName]; ok {
		return b.Execute(ctx, realTool, params)
	}

	// Try passthrough backends (they handle their own routing)
	for _, b := range c.passthroughs {
		result, err := b.Execute(ctx, toolName, params)
		if err == nil {
			return result, nil
		}
	}

	return nil, fmt.Errorf("backend %q not found", backendName)
}

// ListTools aggregates tools from all backends.
func (c *CompositeBackend) ListTools(ctx context.Context) ([]ToolDescriptor, error) {
	var all []ToolDescriptor

	// Named backends — prefix tool names
	for name, b := range c.backends {
		tools, err := b.ListTools(ctx)
		if err != nil {
			continue
		}
		for _, t := range tools {
			all = append(all, ToolDescriptor{
				Name:        name + ":" + t.Name,
				Description: t.Description,
				InputSchema: t.InputSchema,
				Backend:     t.Backend,
			})
		}
	}

	// Passthrough backends — tools already have prefixes
	for _, b := range c.passthroughs {
		tools, err := b.ListTools(ctx)
		if err != nil {
			continue
		}
		all = append(all, tools...)
	}

	return all, nil
}

// Healthy returns nil if at least one backend is healthy.
func (c *CompositeBackend) Healthy(ctx context.Context) error {
	for _, b := range c.backends {
		if err := b.Healthy(ctx); err == nil {
			return nil
		}
	}
	for _, b := range c.passthroughs {
		if err := b.Healthy(ctx); err == nil {
			return nil
		}
	}
	return fmt.Errorf("no healthy backends")
}

func splitToolName(toolName string) (backendName, tool string, err error) {
	parts := strings.SplitN(toolName, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid tool name %q: expected format \"backend:tool_name\"", toolName)
	}
	return parts[0], parts[1], nil
}
