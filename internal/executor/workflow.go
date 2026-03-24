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
	"os"
	"strconv"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// Temporal custom search attribute keys for audit queries.
var (
	SAKeyUserID      = temporal.NewSearchAttributeKeyKeyword("ToolMeshUserID")
	SAKeyCompanyID   = temporal.NewSearchAttributeKeyKeyword("ToolMeshCompanyID")
	SAKeyCallerID    = temporal.NewSearchAttributeKeyKeyword("ToolMeshCallerID")
	SAKeyCallerClass = temporal.NewSearchAttributeKeyKeyword("ToolMeshCallerClass")
	SAKeyToolName    = temporal.NewSearchAttributeKeyKeyword("ToolMeshToolName")
)

// ToolExecutionWorkflow is a Temporal workflow that executes a tool call
// through the full pipeline. It provides durability guarantees and an
// audit trail via workflow history.
func ToolExecutionWorkflow(ctx workflow.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	activityOpts := workflow.ActivityOptions{
		StartToCloseTimeout: envDuration("TOOLMESH_ACTIVITY_TIMEOUT", 120*time.Second),
		RetryPolicy: &temporal.RetryPolicy{
			InitialInterval:    time.Second,
			BackoffCoefficient: 2.0,
			MaximumAttempts:    3,
		},
	}

	ctx = workflow.WithActivityOptions(ctx, activityOpts)

	// Set search attributes for audit queries.
	// UserID, CompanyID etc. are passed via the request for workflow visibility.
	if req.UserID != "" {
		_ = workflow.UpsertTypedSearchAttributes(ctx,
			SAKeyUserID.ValueSet(req.UserID),
			SAKeyCompanyID.ValueSet(req.CompanyID),
			SAKeyCallerID.ValueSet(req.CallerID),
			SAKeyCallerClass.ValueSet(req.CallerClass),
			SAKeyToolName.ValueSet(req.ToolName),
		)
	}

	var result backend.ToolResult
	err := workflow.ExecuteActivity(ctx, "ExecuteToolActivity", req).Get(ctx, &result)
	if err != nil {
		return nil, fmt.Errorf("tool execution workflow: %w", err)
	}

	return &result, nil
}

// envDuration reads a duration in seconds from an environment variable,
// falling back to the provided default if unset or unparsable.
func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return fallback
}
