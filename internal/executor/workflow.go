package executor

import (
	"fmt"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ToolExecutionWorkflow is a Temporal workflow that executes a tool call
// through the full pipeline. It provides durability guarantees and an
// audit trail via workflow history.
func ToolExecutionWorkflow(ctx workflow.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	activityOpts := workflow.ActivityOptions{
		StartToCloseTimeout: 30 * time.Second,
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
		},
	}

	ctx = workflow.WithActivityOptions(ctx, activityOpts)

	var result backend.ToolResult
	err := workflow.ExecuteActivity(ctx, "ExecuteToolActivity", req).Get(ctx, &result)
	if err != nil {
		return nil, fmt.Errorf("tool execution workflow: %w", err)
	}

	return &result, nil
}
