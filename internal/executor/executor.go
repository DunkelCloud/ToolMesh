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
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/telemetry"
	"github.com/DunkelCloud/ToolMesh/internal/urlredact"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// Audit status constants.
const (
	statusSuccess = "success"
	statusError   = "error"
	statusDenied  = "denied"
)

// MCP content-block keys reused in error result payloads.
const (
	contentKeyType = "type"
	contentKeyText = "text"
)

// paramPassword is the well-known sensitive parameter name extracted to keep
// it consistent across the redaction list and the regression tests.
const paramPassword = "password"

// Executor orchestrates the full tool execution pipeline.
type Executor struct {
	authorizer authz.Authorizer
	backend    backend.ToolBackend
	gate       *gate.Pipeline
	audit      audit.AuditStore
	telemetry  *telemetry.Collector
	metrics    *metrics.Registry
	timeout    time.Duration
	logger     *slog.Logger
	// kitHolder tells which kits a caller has been granted; nil when kits
	// cannot be granted.
	kitHolder KitHolder
}

// KitHolder tells which kits a caller holds at the moment, whole and in part:
// the user as the connection it is bound to
// ([userctx.UserContext.GrantBinding]).
type KitHolder interface {
	HeldKits(ctx context.Context, userID, binding string) (whole []string, parts []authz.KitPart)
}

// SetKitHolder makes every check pass the kits the caller holds according to
// h. Without it, callers hold no kits.
func (e *Executor) SetKitHolder(h KitHolder) { e.kitHolder = h }

// held is what a caller holds of kits at the time of a check.
type held struct {
	kits  []string
	parts []authz.KitPart
}

// names lists the kits held for the audit trail, a kit held in part marked
// as such.
func (h held) names() string {
	out := slices.Clone(h.kits)
	for _, p := range h.parts {
		out = append(out, p.Kit+" (part)")
	}
	return strings.Join(out, ",")
}

// kitNames lists the kits held, whole and in part, for the gate context. It
// is never nil, so that policies always see an array.
func (h held) kitNames() []string { return kitNames(h.kits, h.parts) }

// heldKits returns the kits the caller holds now. Only an authenticated
// caller can hold kits.
func (e *Executor) heldKits(ctx context.Context, uc *userctx.UserContext) held {
	if e.kitHolder == nil || e.authorizer == nil || uc == nil || !uc.Authenticated {
		return held{}
	}
	kits, parts := e.kitHolder.HeldKits(ctx, uc.UserID, uc.GrantBinding())
	return held{kits: kits, parts: parts}
}

// appliedKit returns the name of a kit the caller holds that covers the call
// in req, "" when none does. A kit held whole covers what its definition
// covers, a kit held in part only what its granted entries cover. With such
// a kit an approver granted the call, and that decision replaces the
// pre-execution gate: only policies that declare enforce-with-kit still
// run. The answer comes from the definitions alone; whether a deny blocks
// the call regardless is for the authorizer, which decides first.
func (e *Executor) appliedKit(req authz.Request) string {
	if len(req.Kits)+len(req.KitParts) == 0 {
		return ""
	}
	kits := e.Kits()
	find := func(name string) (authz.Kit, bool) {
		i := slices.IndexFunc(kits, func(k authz.Kit) bool { return k.Name == name })
		if i < 0 {
			return authz.Kit{}, false
		}
		return kits[i], true
	}
	for _, name := range req.Kits {
		if k, ok := find(name); ok && k.Covers(req.Tool, req.Backend, req.Access) {
			return name
		}
	}
	for _, p := range req.KitParts {
		if k, ok := find(p.Kit); ok && k.PartCovers(p, req.Tool, req.Backend, req.Access) {
			return p.Kit
		}
	}
	return ""
}

// Audit metadata keys of a call that a held kit covers.
const (
	// metaKitApplied names the kit that covered the call.
	metaKitApplied = "kit_applied"
	// metaGateSkipped lists the pre-execution policies the kit replaced.
	metaGateSkipped = "gate_skipped"
	// metaRemedyKits lists the kits that would have allowed a denied call.
	metaRemedyKits = "remedy_kits"
)

// addMetadata sets one metadata value of the audit entry.
func addMetadata(entry *audit.AuditEntry, key, value string) {
	if entry.Metadata == nil {
		entry.Metadata = map[string]string{}
	}
	entry.Metadata[key] = value
}

// New creates a new Executor with all required dependencies. The metrics
// registry is optional; pass nil to disable Prometheus instrumentation. A nil
// authorizer disables authorization (TOOLMESH_AUTHZ_MODE=disabled). The
// credential store is not used: every backend reads its own credentials,
// within its credential binding, when it sends a request.
func New(
	authorizer authz.Authorizer,
	_ credentials.CredentialStore,
	be backend.ToolBackend,
	gatePipeline *gate.Pipeline,
	auditStore audit.AuditStore,
	timeout time.Duration,
	logger *slog.Logger,
	tc *telemetry.Collector,
	m *metrics.Registry,
) *Executor {
	return &Executor{
		authorizer: authorizer,
		backend:    be,
		gate:       gatePipeline,
		audit:      auditStore,
		telemetry:  tc,
		metrics:    m,
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
	CallerName  string `json:"callerName,omitempty"`
	CallerClass string `json:"callerClass,omitempty"`
}

// ExecuteTool runs the full pipeline: AuthZ → Credentials → Gate pre → Backend → Gate post → Audit.
//
// When a kit the caller holds covers the tool, an approver granted the call:
// the pre-execution gate then runs only the policies that declare
// enforce-with-kit and skips the rest, which the audit entry records
// (kit_applied, gate_skipped). Denies decide before that, in the
// authorization step, and the post-execution gate runs in full.
func (e *Executor) ExecuteTool(ctx context.Context, req ExecuteToolRequest) (*backend.ToolResult, error) {
	uc := userctx.FromContext(ctx)
	if uc == nil {
		return nil, fmt.Errorf("no user context found")
	}

	// Populate caller context on the request.
	req.UserID = uc.UserID
	req.CompanyID = uc.CompanyID
	req.CallerID = uc.CallerID
	req.CallerName = uc.CallerName
	req.CallerClass = uc.CallerClass

	traceID := uuid.New().String()
	start := time.Now()

	e.logger.InfoContext(ctx, "executing tool",
		"tool", req.ToolName,
		"traceId", traceID,
		"user", uc.UserID,
		"company", uc.CompanyID,
		"callerId", uc.CallerID,
		"callerName", uc.CallerName,
		"callerClass", uc.CallerClass,
	)

	e.logger.DebugContext(ctx, "executor pipeline start",
		"tool", req.ToolName,
		"params", SanitizeParams(req.Params),
	)

	// Resolve the tool's access classification once. The lookup is best-effort —
	// backends that do not implement ToolMetadataLookup yield an empty string,
	// in which case gate policies that depend on the value treat the tool as
	// unclassified. Resolution happens before AuthZ so the access tag is
	// available on every audit entry, including denied calls.
	toolAccess := e.lookupToolAccess(req.ToolName)

	// Build the audit entry — populated at each exit point.
	// Redact sensitive parameter values before persisting to the audit store.
	entry := audit.AuditEntry{
		TraceID:     traceID,
		Timestamp:   start,
		UserID:      uc.UserID,
		CompanyID:   uc.CompanyID,
		CallerID:    uc.CallerID,
		CallerName:  uc.CallerName,
		CallerClass: uc.CallerClass,
		Tool:        req.ToolName,
		ToolAccess:  toolAccess,
		Params:      SanitizeParams(req.Params),
		Backend:     e.routedBackend(req.ToolName),
	}

	// Step 1: AuthZ check via OpenFGA
	holding := e.heldKits(ctx, uc)
	authzReq := e.authzRequest(uc, req.ToolName, toolAccess, holding)
	// kit is the kit the caller holds that covers the call, "" when none
	// does. With it the approver's decision replaces the pre-execution gate.
	var kit string
	if e.authorizer != nil {
		e.logger.DebugContext(ctx, "authz check", "tool", req.ToolName, "user", uc.UserID)
		if len(holding.kits)+len(holding.parts) > 0 {
			entry.Metadata = map[string]string{"held_kits": holding.names()}
		}
		allowed, err := e.authorizer.Check(ctx, authzReq)
		if err != nil {
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusError
			entry.Error = fmt.Sprintf("authz check failed: %v", err)
			e.recordAudit(ctx, entry)
			return nil, fmt.Errorf("authz check failed: %w", err)
		}
		if !allowed {
			// Deny with remedy: name the kits that would allow the call, so
			// that the caller asks once for a kit instead of tool by tool.
			kits, remedy := e.denialRemedy(ctx, uc, authzReq, req.Params)
			e.logger.WarnContext(ctx, "authorization denied",
				"tool", req.ToolName,
				"user", uc.UserID,
				"kits", kits,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusDenied
			if len(kits) > 0 {
				addMetadata(&entry, metaRemedyKits, strings.Join(kits, ","))
			}
			e.recordAudit(ctx, entry)
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: fmt.Sprintf("User %s is not authorized to execute tool %s.%s", uc.UserID, req.ToolName, remedy),
				}},
			}, nil
		}
		if kit = e.appliedKit(authzReq); kit != "" {
			addMetadata(&entry, metaKitApplied, kit)
		}
	}

	// Step 2: Argument check against the tool's declaration, before the
	// pre-execution gate. A policy then only sees arguments of the declared
	// types: the string "false" for a boolean would otherwise pass a check
	// for false and still reach the API.
	if pv, ok := e.backend.(backend.ParamValidator); ok {
		effective, err := pv.ValidateToolParams(req.ToolName, req.Params)
		if err != nil {
			e.logger.WarnContext(ctx, "tool call rejected: parameters do not match the declaration",
				"tool", req.ToolName,
				"user", uc.UserID,
				"error", err,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusError
			entry.Error = err.Error()
			e.recordAudit(ctx, entry)
			return backend.ParamErrorResult(err), nil
		}
		// The gate and the backend see the effective arguments: declared
		// defaults filled in, numeric strings as numbers, numbers and
		// booleans of string parameters as the text the request carries.
		req.Params = effective
	}

	// Step 3: Pre-execution gate — validate tool + params before calling backend
	if e.gate != nil {
		e.logger.DebugContext(ctx, "gate pre-execution start", "tool", req.ToolName)
		gctx := gate.GateContext{
			User:       *uc,
			Tool:       req.ToolName,
			ToolAccess: toolAccess,
			Params:     req.Params,
			Kits:       holding.kitNames(),
			KitCovered: kit != "",
		}
		pre, err := e.gate.EvaluatePre(gctx)
		if err != nil {
			// Refusal with remedy, as for an authorization denial: a kit
			// that covers the tool replaces the gate, so name the kits that
			// would lift the refusal.
			kits, remedy := e.gateRemedy(uc, authzReq, req.Params)
			e.logger.WarnContext(ctx, "gate pre-execution rejected",
				"tool", req.ToolName,
				"user", uc.UserID,
				"error", err,
				"kits", kits,
			)
			entry.DurationMs = time.Since(start).Milliseconds()
			entry.Status = statusDenied
			entry.Error = fmt.Sprintf("gate rejected (pre-execution): %v", err)
			if len(kits) > 0 {
				addMetadata(&entry, metaRemedyKits, strings.Join(kits, ","))
			}
			e.recordAudit(ctx, entry)
			msg := "Gate rejected (pre-execution): " + err.Error()
			if remedy != "" {
				msg = strings.TrimSuffix(msg, ".") + "." + remedy
			}
			return &backend.ToolResult{
				IsError: true,
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: msg,
				}},
			}, nil
		}
		if len(pre.Modifications) > 0 {
			entry.Modifications = append(entry.Modifications, pre.Modifications...)
		}
		if len(pre.Skipped) > 0 {
			addMetadata(&entry, metaGateSkipped, strings.Join(pre.Skipped, ","))
			e.logger.InfoContext(ctx, "kit replaces the pre-execution gate",
				"tool", req.ToolName,
				"user", uc.UserID,
				"kit", kit,
				"skipped", pre.Skipped,
			)
		}
		e.logger.DebugContext(ctx, "gate pre-execution passed", "tool", req.ToolName)
	}

	// Step 4: Backend execution (with context timeout)
	e.logger.DebugContext(ctx, "backend execution start", "tool", req.ToolName)

	execCtx, execCancel := context.WithTimeout(ctx, e.timeout)
	defer execCancel()

	result, err := e.backend.Execute(execCtx, req.ToolName, req.Params)
	if err != nil {
		// A transport error can carry the request URL, and with it a
		// query-injected credential; never let that reach the audit log or
		// the caller.
		err = urlredact.URLErrors(err)
		e.logger.DebugContext(ctx, "backend execution failed", "tool", req.ToolName, "error", err)
		entry.DurationMs = time.Since(start).Milliseconds()
		entry.Status = statusError
		entry.Error = err.Error()
		e.recordAudit(ctx, entry)
		return nil, fmt.Errorf("backend execution failed for %s: %w", req.ToolName, err)
	}
	if result != nil && result.IsError {
		redactErrorResult(result)
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
			User:       *uc,
			Tool:       req.ToolName,
			ToolAccess: toolAccess,
			Params:     req.Params,
			Response:   result,
			Kits:       holding.kitNames(),
			KitCovered: kit != "",
		}
		post, err := e.gate.EvaluatePost(gctx)
		if err != nil {
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
					contentKeyType: contentKeyText,
					contentKeyText: fmt.Sprintf("Gate rejected (post-execution): %s", err),
				}},
			}, nil
		}
		if len(post.Modifications) > 0 {
			entry.Modifications = append(entry.Modifications, post.Modifications...)
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

// CheckChild authorizes and pre-gates a nested tool call made from inside a
// composite. Composite api.* calls dispatch directly to the owning adapter and
// never re-enter ExecuteTool, so without this check they would skip the per-tool
// OpenFGA authorization and the pre-execution gate that a direct call goes
// through. It runs ONLY those two checks — no credential re-injection, no
// post-gate, no audit or metrics, which the composite as a whole already
// performs. It fails closed: any authz error, denial, or gate rejection returns
// a non-nil error that aborts the child call. A kit the caller holds that
// covers the child tool replaces the pre-execution gate as on the direct
// path; the composite's audit entry does not show it, the log does.
//
// toolName is the canonical "<backend>_<tool>" name so it matches the
// authorization object and gate classification used on the direct path.
func (e *Executor) CheckChild(ctx context.Context, toolName string, params map[string]any) error {
	uc := userctx.FromContext(ctx)
	if uc == nil {
		return fmt.Errorf("no user context for child tool %s", toolName)
	}

	toolAccess := e.lookupToolAccess(toolName)
	holding := e.heldKits(ctx, uc)
	var kit string
	if e.authorizer != nil {
		authzReq := e.authzRequest(uc, toolName, toolAccess, holding)
		allowed, err := e.authorizer.Check(ctx, authzReq)
		if err != nil {
			return fmt.Errorf("authz check failed for child tool %s: %w", toolName, err)
		}
		if !allowed {
			return fmt.Errorf("user %s is not authorized to execute child tool %s", uc.UserID, toolName)
		}
		kit = e.appliedKit(authzReq)
	}

	if e.gate != nil {
		gctx := gate.GateContext{
			User:       *uc,
			Tool:       toolName,
			ToolAccess: toolAccess,
			Params:     params,
			Kits:       holding.kitNames(),
			KitCovered: kit != "",
		}
		pre, err := e.gate.EvaluatePre(gctx)
		if err != nil {
			return fmt.Errorf("gate rejected child tool %s: %w", toolName, err)
		}
		if len(pre.Skipped) > 0 {
			e.logger.InfoContext(ctx, "kit replaces the pre-execution gate for child tool",
				"tool", toolName,
				"user", uc.UserID,
				"kit", kit,
				"skipped", pre.Skipped,
			)
		}
	}

	return nil
}

// recordAudit persists an audit entry, logging any store errors.
// By design, audit recording failures do not block the tool response — availability
// is prioritized over auditability. The error is logged so operators can detect
// audit store issues. For strict audit requirements, configure an external audit
// pipeline or monitor for these log entries.
func (e *Executor) recordAudit(ctx context.Context, entry audit.AuditEntry) {
	if e.audit != nil {
		if err := e.audit.Record(ctx, entry); err != nil {
			e.logger.ErrorContext(ctx, "failed to record audit entry",
				"traceId", entry.TraceID,
				"tool", entry.Tool,
				"error", err,
			)
		}
	}
	if e.telemetry != nil && entry.Backend != "" {
		e.telemetry.RecordCall(entry.Backend, entry.Status == statusSuccess)
	}
	// Prometheus metric — recorded here (rather than at the MCP handler) so that
	// individual tool calls made from inside execute_code's JS body are counted
	// with their real backend/tool labels, not collapsed under "execute_code".
	// The tool label drops the routed backend's prefix, so the tool
	// "web_search_query" of backend "web_search" is counted as "query".
	if e.metrics != nil {
		backendLabel := entry.Backend
		toolLabel := strings.TrimPrefix(entry.Tool, entry.Backend+"_")
		if backendLabel == "" {
			backendLabel = "unknown"
			toolLabel = entry.Tool
		}
		e.metrics.RecordToolCall(
			backendLabel,
			toolLabel,
			entry.Status,
			time.Duration(entry.DurationMs)*time.Millisecond,
		)
	}
}

// redactErrorResult removes userinfo, query and fragment from every URL in
// the text content of an error result. Such a text is often built from an
// error whose structure is gone (a retry that failed, a token request), and
// a request URL in it can carry a query-injected credential.
func redactErrorResult(result *backend.ToolResult) {
	for _, item := range result.Content {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if text, ok := m[contentKeyText].(string); ok {
			m[contentKeyText] = urlredact.Text(text)
		}
	}
}

// sensitiveParamNames is the set of parameter name patterns that should be redacted in audit logs.
var sensitiveParamNames = map[string]bool{
	paramPassword:   true,
	"secret":        true,
	"token":         true,
	"api_key":       true,
	"apikey":        true,
	"access_token":  true,
	"refresh_token": true,
	"authorization": true,
	"credential":    true,
	"private_key":   true,
}

// SanitizeParams returns a copy of params with the values of secret-looking
// names (password, token, api_key, ...) replaced by "[REDACTED]". It serves
// the audit trail and every other place a call's arguments are shown.
func SanitizeParams(params map[string]any) map[string]any {
	if len(params) == 0 {
		return params
	}
	sanitized := make(map[string]any, len(params))
	for k, v := range params {
		if sensitiveParamNames[strings.ToLower(k)] {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}

// FilterAuthorizedTools filters a list of tools to only those the caller is
// authorized to execute. If no authorizer is configured, all tools are
// returned. A tool whose check fails is left out.
func (e *Executor) FilterAuthorizedTools(ctx context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor) []backend.ToolDescriptor {
	if e.authorizer == nil {
		return tools
	}
	if uc == nil {
		return nil
	}
	allowed := e.checkAll(ctx, e.authzRequests(ctx, uc, tools))

	authorized := make([]backend.ToolDescriptor, 0, len(tools))
	for i, t := range tools {
		if allowed[i] {
			authorized = append(authorized, t)
		}
	}
	return authorized
}

// routedBackend names the backend a call of toolName is routed to. The name
// comes from the same routing the call takes; splitting the name at the first
// underscore would attribute "web_search_query" to a backend "web". It is
// empty when no backend claims the tool or the backend cannot resolve names.
func (e *Executor) routedBackend(toolName string) string {
	r, ok := e.backend.(backend.BackendNameResolver)
	if !ok {
		return ""
	}
	name, _ := r.ResolveBackendName(toolName)
	return name
}

// authzRequest describes a call for the authorizer, with the backend the call
// is routed to. Without a resolver the backend stays empty, so grants on a
// backend do not apply.
func (e *Executor) authzRequest(uc *userctx.UserContext, toolName, toolAccess string, h held) authz.Request {
	return authz.Request{
		UserID:    uc.UserID,
		CompanyID: uc.CompanyID,
		Plan:      uc.Plan,
		Roles:     uc.Roles,
		Kits:      h.kits,
		KitParts:  h.parts,
		Tool:      toolName,
		Backend:   e.routedBackend(toolName),
		Access:    toolAccess,
	}
}

// lookupToolAccess resolves the DADL-declared access classification for the
// given tool, if the underlying backend supports descriptor lookup. Returns
// an empty string when the backend does not implement ToolMetadataLookup or
// does not own the tool — gate policies and audit entries treat empty as
// unclassified.
func (e *Executor) lookupToolAccess(toolName string) string {
	lookup, ok := e.backend.(backend.ToolMetadataLookup)
	if !ok {
		return ""
	}
	desc, found := lookup.LookupTool(toolName)
	if !found {
		return ""
	}
	return desc.Access
}
