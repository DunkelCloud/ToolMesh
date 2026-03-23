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

// Package executor implements the core ExecuteTool pipeline that orchestrates
// authorization, credential injection, backend execution, and output gating.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Executor orchestrates the full tool execution pipeline.
type Executor struct {
	authorizer *authz.Authorizer
	creds      credentials.CredentialStore
	backend    backend.ToolBackend
	gate       *gate.Pipeline
	logger     *slog.Logger
}

// New creates a new Executor with all required dependencies.
func New(
	authorizer *authz.Authorizer,
	creds credentials.CredentialStore,
	backend backend.ToolBackend,
	gatePipeline *gate.Pipeline,
	logger *slog.Logger,
) *Executor {
	return &Executor{
		authorizer: authorizer,
		creds:      creds,
		backend:    backend,
		gate:       gatePipeline,
		logger:     logger,
	}
}

// ExecuteToolRequest holds the parameters for a tool execution.
type ExecuteToolRequest struct {
	ToolName string         `json:"toolName"`
	Params   map[string]any `json:"params"`
}

// ExecuteTool runs the full pipeline: AuthZ → Credentials → Backend → Gate.
func (e *Executor) ExecuteTool(ctx context.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	start := time.Now()

	uc := userctx.FromContext(ctx)
	if uc == nil {
		return nil, fmt.Errorf("no user context found")
	}

	e.logger.InfoContext(ctx, "executing tool",
		"tool", req.ToolName,
		"user", uc.UserID,
		"company", uc.CompanyID,
	)

	// Step 1: AuthZ check via OpenFGA
	if e.authorizer != nil {
		allowed, err := e.authorizer.Check(ctx, uc.UserID, req.ToolName)
		if err != nil {
			return nil, fmt.Errorf("authz check failed: %w", err)
		}
		if !allowed {
			e.logger.WarnContext(ctx, "authorization denied",
				"tool", req.ToolName,
				"user", uc.UserID,
			)
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					"type": "text",
					"text": fmt.Sprintf("User %s is not authorized to execute tool %s", uc.UserID, req.ToolName),
				}},
			}, nil
		}
	}

	// Step 2: Credential injection (credentials are used by the backend internally)
	// The backend handles credential lookup via its configuration.

	// Step 3: Backend execution
	result, err := e.backend.Execute(ctx, req.ToolName, req.Params)
	if err != nil {
		return nil, fmt.Errorf("backend execution failed for %s: %w", req.ToolName, err)
	}

	// Step 4: Output Gate evaluation
	if e.gate != nil {
		gctx := gate.GateContext{
			User:     *uc,
			Tool:     req.ToolName,
			Response: result,
		}
		if err := e.gate.Evaluate(gctx); err != nil {
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					"type": "text",
					"text": fmt.Sprintf("Output gate rejected: %s", err),
				}},
			}, nil
		}
	}

	// Record metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]any)
	}
	result.Metadata["latencyMs"] = time.Since(start).Milliseconds()
	result.Metadata["user"] = uc.UserID

	e.logger.InfoContext(ctx, "tool execution complete",
		"tool", req.ToolName,
		"user", uc.UserID,
		"latencyMs", result.Metadata["latencyMs"],
		"isError", result.IsError,
	)

	return result, nil
}
