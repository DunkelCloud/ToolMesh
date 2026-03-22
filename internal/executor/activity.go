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
