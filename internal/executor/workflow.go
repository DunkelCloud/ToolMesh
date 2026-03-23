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
