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
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// RightsToolName is the built-in meta-tool that tells callers what they may
// do. Denials point to it.
const RightsToolName = "tell_me_my_rights"

// Verdicts of a ToolRight.
const (
	// VerdictAllowed: the caller may execute the tool now.
	VerdictAllowed = "allowed"
	// VerdictEscalatable: the caller may not, but holding one of the kits in
	// ToolRight.Kits would allow it.
	VerdictEscalatable = "escalatable"
	// VerdictDenied: the caller may not, and no kit changes that.
	VerdictDenied = "denied"
)

// ToolRight is what a caller may do with one tool.
type ToolRight struct {
	Tool string
	// Backend the tool is routed to, empty when no backend claims it.
	Backend string
	Verdict string
	// Kits that would allow the tool, for VerdictEscalatable.
	Kits []string
	// Blocked is set for a denied tool that a kit covers but a deny blocks
	// for this caller, so that no kit can help.
	Blocked bool
}

// Authorizes reports whether calls are checked at all; false when
// authorization is disabled.
func (e *Executor) Authorizes() bool { return e.authorizer != nil }

// Kits returns the kits the authorizer knows, nil when it knows none.
func (e *Executor) Kits() []authz.Kit {
	if kc, ok := e.authorizer.(authz.KitCatalog); ok {
		return kc.Kits()
	}
	return nil
}

// AssessTools reports for each tool whether the caller may execute it and,
// if not, which kits would allow it. With verify, a kit counts only when a
// check with the caller holding it allows the tool, which takes denies into
// account; without, a kit counts when its definition covers the tool, which
// costs no checks beyond the one per tool. The answer is information only:
// ExecuteTool checks every call again.
func (e *Executor) AssessTools(ctx context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor, verify bool) []ToolRight {
	reqs := e.authzRequests(uc, tools)
	if e.authorizer == nil {
		out := make([]ToolRight, len(tools))
		for i, r := range reqs {
			out[i] = ToolRight{Tool: r.Tool, Backend: r.Backend, Verdict: VerdictAllowed}
		}
		return out
	}
	return e.assess(ctx, reqs, e.checkAll(ctx, reqs), verify)
}

// assess turns the outcome of the checks of reqs into rights, finding the
// kits that would allow each denied tool.
func (e *Executor) assess(ctx context.Context, reqs []authz.Request, allowed []bool, verify bool) []ToolRight {
	out := make([]ToolRight, len(reqs))
	kits := e.Kits()
	// Indices of the denied tools each kit covers, by kit index.
	covered := make([][]int, len(kits))
	for i, r := range reqs {
		out[i] = ToolRight{Tool: r.Tool, Backend: r.Backend, Verdict: VerdictAllowed}
		if allowed[i] {
			continue
		}
		out[i].Verdict = VerdictDenied
		for k, kit := range kits {
			if kit.Covers(r.Tool, r.Backend, r.Access) {
				covered[k] = append(covered[k], i)
			}
		}
	}

	for k, idx := range covered {
		if len(idx) == 0 {
			continue
		}
		ok := make([]bool, len(idx))
		if verify {
			held := make([]authz.Request, len(idx))
			for j, i := range idx {
				held[j] = reqs[i]
				held[j].Kits = append(slices.Clone(reqs[i].Kits), kits[k].Name)
			}
			ok = e.checkAll(ctx, held)
		} else {
			for j := range ok {
				ok[j] = true
			}
		}
		for j, i := range idx {
			if ok[j] {
				out[i].Kits = append(out[i].Kits, kits[k].Name)
			}
		}
	}

	for _, idx := range covered {
		for _, i := range idx {
			if len(out[i].Kits) == 0 {
				out[i].Blocked = true
			}
		}
	}
	for i := range out {
		if out[i].Verdict == VerdictDenied && len(out[i].Kits) > 0 {
			out[i].Verdict = VerdictEscalatable
		}
	}
	return out
}

// authzRequests describes a call of each tool for the authorizer.
func (e *Executor) authzRequests(uc *userctx.UserContext, tools []backend.ToolDescriptor) []authz.Request {
	reqs := make([]authz.Request, len(tools))
	for i, t := range tools {
		access := t.Access
		if access == "" {
			access = e.lookupToolAccess(t.Name)
		}
		reqs[i] = e.authzRequest(uc, t.Name, access)
	}
	return reqs
}

// checkAll checks every request, in one batch when the authorizer supports
// it. A request whose check fails counts as not allowed.
func (e *Executor) checkAll(ctx context.Context, reqs []authz.Request) []bool {
	if bc, ok := e.authorizer.(authz.BatchChecker); ok {
		allowed, err := bc.CheckBatch(ctx, reqs)
		if err != nil {
			e.logger.DebugContext(ctx, "authz check failed during batch check", "error", err)
		}
		return allowed
	}
	allowed := make([]bool, len(reqs))
	for i, r := range reqs {
		ok, err := e.authorizer.Check(ctx, r)
		if err != nil {
			e.logger.DebugContext(ctx, "authz check failed during batch check", "tool", r.Tool, "error", err)
			continue
		}
		allowed[i] = ok
	}
	return allowed
}

// denialRemedy returns the kits that would allow a denied call and the text
// that points the caller to them, or nil and "" when no kit would.
func (e *Executor) denialRemedy(ctx context.Context, req authz.Request) (kits []string, remedy string) {
	right := e.assess(ctx, []authz.Request{req}, []bool{false}, true)[0]
	if len(right.Kits) == 0 {
		return nil, ""
	}
	descs := make(map[string]string)
	for _, k := range e.Kits() {
		descs[k.Name] = k.Description
	}
	named := make([]string, len(right.Kits))
	for i, name := range right.Kits {
		named[i] = fmt.Sprintf("%q (%s)", name, descs[name])
	}
	subject := "The kit " + named[0] + " covers"
	if len(named) > 1 {
		subject = "The kits " + strings.Join(named, ", ") + " cover"
	}
	return right.Kits, fmt.Sprintf(" %s it. Ask for a kit rather than for this one tool, and check first with %s({tools: [...]}) which other tools your task needs, so that one request covers all of them.",
		subject, RightsToolName)
}

// AuditRightsQuery records a call of tell_me_my_rights in the audit trail.
// Its answer lists what the caller may and may not do, the first thing an
// agent that was taken over would look up, so every call is recorded.
func (e *Executor) AuditRightsQuery(ctx context.Context, params map[string]any, start time.Time, failure string) {
	if e.audit == nil {
		return
	}
	uc := userctx.FromContext(ctx)
	if uc == nil {
		uc = &userctx.UserContext{}
	}
	entry := audit.AuditEntry{
		TraceID:     uuid.New().String(),
		Timestamp:   start,
		UserID:      uc.UserID,
		CompanyID:   uc.CompanyID,
		CallerID:    uc.CallerID,
		CallerName:  uc.CallerName,
		CallerClass: uc.CallerClass,
		Tool:        RightsToolName,
		Backend:     "toolmesh",
		Params:      sanitizeParams(params),
		DurationMs:  time.Since(start).Milliseconds(),
		Status:      statusSuccess,
	}
	if failure != "" {
		entry.Status = statusError
		entry.Error = failure
	}
	if err := e.audit.Record(ctx, entry); err != nil {
		e.logger.ErrorContext(ctx, "failed to record audit entry", "traceId", entry.TraceID, "tool", entry.Tool, "error", err)
	}
}
