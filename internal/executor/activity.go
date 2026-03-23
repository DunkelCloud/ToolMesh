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

package executor

import (
	"context"
	"fmt"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// ExecuteToolActivity is a Temporal activity that wraps ExecuteTool.
// The Executor is injected via activity options (struct method).
func (e *Executor) ExecuteToolActivity(ctx context.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	result, err := e.ExecuteTool(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("execute tool activity: %w", err)
	}
	return result, nil
}
