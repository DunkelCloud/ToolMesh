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
// authorization, credential injection, backend execution, output gating,
// and audit recording.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// Audit status constants.
const (
	statusSuccess = "success"
	statusError   = "error"
	statusDenied  = "denied"
)

// Executor orchestrates the full tool execution pipeline.
type Executor struct {
	authorizer *authz.Authorizer
	creds      credentials.CredentialStore
	backend    backend.ToolBackend
	gate       *gate.Pipeline
	audit      audit.AuditStore
	timeout    time.Duration
	logger     *slog.Logger
}

// New creates a new Executor with all required dependencies.
func New(
	authorizer *authz.Authorizer,
	creds credentials.CredentialStore,
	be backend.ToolBackend,
	gatePipeline *gate.Pipeline,
	auditStore audit.AuditStore,
	timeout time.Duration,
	logger *slog.Logger,
) *Executor {
	return &Executor{
		authorizer: authorizer,
		creds:      creds,
		backend:    be,
		gate:       gatePipeline,
		audit:      auditStore,
		timeout:    timeout,
		logger:     logger,
	}
}

// ExecuteToolRequest holds the parameters for a tool execution.
type ExecuteToolRequest struct {
	ToolName string         `json:"toolName"`
	Params   map[string]any `json:"params"`
	// Caller context (set by executor from UserContext).
	UserID      string `json:"userId,omitempty"`
	CompanyID   string `json:"companyId,omitempty"`
	CallerID    string `json:"callerId,omitempty"`
	CallerClass string `json:"callerClass,omitempty"`
}

// ExecuteTool runs the full pipeline: AuthZ → Credentials → Gate pre → Backend → Gate post → Audit.
func (e *Executor) ExecuteTool(ctx context.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	uc := userctx.FromContext(ctx)
	if uc == nil {
		return nil, fmt.Errorf("no user context found")
	}

	// Populate caller context on the request.
	req.UserID = uc.UserID
	req.CompanyID = uc.CompanyID
	req.CallerID = uc.CallerID
	req.CallerClass = uc.CallerClass

	traceID := uuid.New().String()
	start := time.Now()

	e.logger.InfoContext(ctx, "executing tool",
		"tool", req.ToolName,
		"traceId", traceID,
		"user", uc.UserID,
		"company", uc.CompanyID,
		"callerId", uc.CallerID,
		"callerClass", uc.CallerClass,
	)

	e.logger.DebugContext(ctx, "executor pipeline start",
		"tool", req.ToolName,
		"params", req.Params,
	)

	// Build the audit entry — populated at each exit point.
	entry := audit.AuditEntry{
		TraceID:     traceID,
		Timestamp:   start,
		UserID:      uc.UserID,
		CompanyID:   uc.CompanyID,
		CallerID:    uc.CallerID,
		CallerClass: uc.CallerClass,
		Tool:        req.ToolName,
		Params:      req.Params,
		Backend:     splitToolPrefix(req.ToolName)[0],
	}

	// Step 1: AuthZ check via OpenFGA
	if e.authorizer != nil {
		e.logger.DebugContext(ctx, "authz check", "tool", req.ToolName, "user", uc.UserID)
		allowed, err := e.authorizer.Check(ctx, uc.UserID, req.ToolName)
		if err != nil {
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusError
			entry.Error = fmt.Sprintf("authz check failed: %v", err)
			e.recordAudit(ctx, entry)
			return nil, fmt.Errorf("authz check failed: %w", err)
		}
		if !allowed {
			e.logger.WarnContext(ctx, "authorization denied",
				"tool", req.ToolName,
				"user", uc.UserID,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusDenied
			e.recordAudit(ctx, entry)
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					"type": "text",
					"text": fmt.Sprintf("User %s is not authorized to execute tool %s", uc.UserID, req.ToolName),
				}},
			}, nil
		}
	}

	// Step 2: Credential injection via context
	if e.creds != nil {
		tenant := credentials.TenantInfo{
			CompanyID:   uc.CompanyID,
			UserID:      uc.UserID,
			CallerID:    uc.CallerID,
			CallerClass: uc.CallerClass,
		}
		if parts := splitToolPrefix(req.ToolName); parts[0] != "" {
			creds := e.resolveCredentials(ctx, parts[0], tenant)
			if len(creds) > 0 {
				ctx = credentials.WithCredentials(ctx, creds)
				e.logger.InfoContext(ctx, "credentials injected",
					"backend", parts[0],
					"count", len(creds),
				)
			}
		}
	}

	// Step 3: Pre-execution gate — validate tool + params before calling backend
	if e.gate != nil {
		e.logger.DebugContext(ctx, "gate pre-execution start", "tool", req.ToolName)
		gctx := gate.GateContext{
			User:   *uc,
			Tool:   req.ToolName,
			Params: req.Params,
		}
		if err := e.gate.EvaluatePre(gctx); err != nil {
			e.logger.WarnContext(ctx, "gate pre-execution rejected",
				"tool", req.ToolName,
				"user", uc.UserID,
				"error", err,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusDenied
			entry.Error = fmt.Sprintf("gate rejected (pre-execution): %v", err)
			e.recordAudit(ctx, entry)
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					"type": "text",
					"text": fmt.Sprintf("Gate rejected (pre-execution): %s", err),
				}},
			}, nil
		}
		e.logger.DebugContext(ctx, "gate pre-execution passed", "tool", req.ToolName)
	}

	// Step 4: Backend execution (with context timeout)
	e.logger.DebugContext(ctx, "backend execution start", "tool", req.ToolName)

	execCtx, execCancel := context.WithTimeout(ctx, e.timeout)
	defer execCancel()

	result, err := e.backend.Execute(execCtx, req.ToolName, req.Params)
	if err != nil {
		e.logger.DebugContext(ctx, "backend execution failed", "tool", req.ToolName, "error", err)
		entry.DurationMs = time.Since(start).Milliseconds()
		entry.Status = statusError
		entry.Error = err.Error()
		e.recordAudit(ctx, entry)
		return nil, fmt.Errorf("backend execution failed for %s: %w", req.ToolName, err)
	}
	if contentJSON, err := json.Marshal(result.Content); err == nil {
		e.logger.DebugContext(ctx, "backend execution complete",
			"tool", req.ToolName,
			"isError", result.IsError,
			"contentItems", len(result.Content),
			"content", string(contentJSON),
		)
	}

	// Step 5: Post-execution gate — filter/mask response
	if e.gate != nil {
		e.logger.DebugContext(ctx, "gate post-execution start", "tool", req.ToolName)
		gctx := gate.GateContext{
			User:     *uc,
			Tool:     req.ToolName,
			Params:   req.Params,
			Response: result,
		}
		if err := e.gate.EvaluatePost(gctx); err != nil {
			e.logger.WarnContext(ctx, "gate post-execution rejected",
				"tool", req.ToolName,
				"user", uc.UserID,
				"error", err,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusDenied
			entry.Error = fmt.Sprintf("gate rejected (post-execution): %v", err)
			e.recordAudit(ctx, entry)
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					"type": "text",
					"text": fmt.Sprintf("Gate rejected (post-execution): %s", err),
				}},
			}, nil
		}
		e.logger.DebugContext(ctx, "gate post-execution passed", "tool", req.ToolName)
	}

	// Record metadata
	if result.Metadata == nil {
		result.Metadata = make(map[string]any)
	}
	duration := time.Since(start).Milliseconds()
	result.Metadata["latencyMs"] = duration
	result.Metadata["user"] = uc.UserID
	result.Metadata["traceId"] = traceID

	// Step 6: Record audit entry (success)
	entry.DurationMs = duration
	if result.IsError {
		entry.Status = statusError
	} else {
		entry.Status = statusSuccess
	}
	e.recordAudit(ctx, entry)

	e.logger.InfoContext(ctx, "tool execution complete",
		"tool", req.ToolName,
		"traceId", traceID,
		"user", uc.UserID,
		"latencyMs", duration,
		"isError", result.IsError,
	)

	return result, nil
}

// recordAudit persists an audit entry, logging any store errors.
func (e *Executor) recordAudit(ctx context.Context, entry audit.AuditEntry) {
	if e.audit == nil {
		return
	}
	if err := e.audit.Record(ctx, entry); err != nil {
		e.logger.ErrorContext(ctx, "failed to record audit entry",
			"traceId", entry.TraceID,
			"tool", entry.Tool,
			"error", err,
		)
	}
}

// resolveCredentials loads all credentials for a backend. It first tries
// PrefixLister (convention: CREDENTIAL_<BACKEND>_*) to inject multiple
// credentials per backend. Falls back to a single <BACKEND>_API_KEY lookup.
func (e *Executor) resolveCredentials(ctx context.Context, backendPrefix string, tenant credentials.TenantInfo) map[string]string {
	prefix := strings.ToUpper(backendPrefix) + "_"

	// Try prefix-based listing first (e.g. CREDENTIAL_GITHUB_API_KEY, CREDENTIAL_GITHUB_TOKEN)
	if lister, ok := e.creds.(credentials.PrefixLister); ok {
		creds, err := lister.ListByPrefix(ctx, prefix, tenant)
		if err == nil && len(creds) > 0 {
			return creds
		}
	}

	// Fallback: single <BACKEND>_API_KEY credential
	credName := strings.ToUpper(backendPrefix) + "_API_KEY"
	if cred, err := e.creds.Get(ctx, credName, tenant); err == nil {
		return map[string]string{credName: cred}
	}

	return nil
}

// splitToolPrefix extracts the backend prefix from a tool name like "backend_tool".
func splitToolPrefix(toolName string) [2]string {
	if idx := strings.Index(toolName, "_"); idx > 0 {
		return [2]string{toolName[:idx], toolName[idx+1:]}
	}
	return [2]string{"", toolName}
}
