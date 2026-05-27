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
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// mcpSubBackend is a ToolBackend view over a single backend inside a
// shared MCPAdapter. The unit-local name (e.g. "randombit") is also the
// prefix the underlying MCPAdapter uses for tool routing.
type mcpSubBackend struct {
	adapter *backend.MCPAdapter
	subName string
}

// Execute forwards the call to the underlying MCPAdapter with the unit-local
// prefix re-applied. The unit's sandbox calls Execute with the bare tool
// name (e.g. "flip"); the MCPAdapter is reached as "randombit_flip".
func (s *mcpSubBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	return s.adapter.Execute(ctx, s.subName+"_"+toolName, params)
}

// ListTools returns the unit-local view of the sub-backend's tools — i.e.
// the MCPAdapter tools whose name starts with "<subName>_", with the prefix
// stripped. The sandbox uses this list to decide which tool names to bind
// under api.<subName>.*.
func (s *mcpSubBackend) ListTools(ctx context.Context) ([]backend.ToolDescriptor, error) {
	all, err := s.adapter.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	prefix := s.subName + "_"
	out := make([]backend.ToolDescriptor, 0, len(all))
	for _, t := range all {
		if !strings.HasPrefix(t.Name, prefix) {
			continue
		}
		t.Name = strings.TrimPrefix(t.Name, prefix)
		out = append(out, t)
	}
	return out, nil
}

// Healthy delegates to the underlying MCPAdapter.
func (s *mcpSubBackend) Healthy(ctx context.Context) error {
	return s.adapter.Healthy(ctx)
}
