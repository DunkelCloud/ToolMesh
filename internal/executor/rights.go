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
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/grants"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// RightsToolName is the built-in meta-tool that tells callers what they may
// do. Denials point to it.
const RightsToolName = "tell_me_my_rights"

// RequestGrantToolName is the built-in meta-tool callers ask for a kit with.
// Denials point to it when kits can be granted.
const RequestGrantToolName = grants.ToolRequestGrant

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
	// PolicyRefusal is what a pre-execution policy answers to a call of the
	// tool, as "policy <file>: <reason>", when that is what stands in the
	// caller's way: for VerdictEscalatable the kits in Kits lift it, for
	// VerdictDenied no kit does. Empty when no policy refuses the call.
	PolicyRefusal string
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
// account, and the pre-execution policies are asked as well (see
// gateRights); without, a kit counts when its definition covers the tool
// and no policy is asked, which costs no checks beyond the one per tool.
// The answer is information only: ExecuteTool checks every call again.
func (e *Executor) AssessTools(ctx context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor, verify bool) []ToolRight {
	reqs := e.authzRequests(ctx, uc, tools)
	var out []ToolRight
	if e.authorizer == nil {
		out = make([]ToolRight, len(tools))
		for i, r := range reqs {
			out[i] = ToolRight{Tool: r.Tool, Backend: r.Backend, Verdict: VerdictAllowed}
		}
	} else {
		out = e.assess(ctx, reqs, e.checkAll(ctx, reqs), verify)
	}
	if verify {
		e.gateRights(uc, reqs, out)
	}
	return out
}

// gateRights asks the pre-execution policies about every tool the caller
// may execute or get through a kit, as ExecuteTool would after the
// authorization step: with the kits the caller holds, no parameters and
// GateContext.Preflight set. A tool the policies refuse becomes escalatable
// through the kits that cover it and with which the gate passes (a held kit
// replaces the gate, except for policies that declare enforce-with-kit), or
// denied when no kit does; an escalatable tool keeps only the kits with
// which the gate passes. Tools the caller may not see are left alone.
func (e *Executor) gateRights(uc *userctx.UserContext, reqs []authz.Request, rights []ToolRight) {
	if e.gate == nil {
		return
	}
	for i := range rights {
		r := &rights[i]
		switch r.Verdict {
		case VerdictAllowed:
			refusal := e.gatePreflight(uc, reqs[i], nil)
			if refusal == "" {
				continue
			}
			r.PolicyRefusal = refusal
			r.Verdict = VerdictDenied
			if r.Kits = e.liftingKits(uc, reqs[i], nil); len(r.Kits) > 0 {
				r.Verdict = VerdictEscalatable
			}
		case VerdictEscalatable:
			var kits []string
			var refusal string
			for _, name := range r.Kits {
				if ref := e.gatePreflight(uc, withKit(reqs[i], name), nil); ref != "" {
					refusal = ref
					continue
				}
				kits = append(kits, name)
			}
			r.Kits = kits
			if len(kits) == 0 {
				r.Verdict, r.PolicyRefusal = VerdictDenied, refusal
			}
		}
	}
}

// liftingKits returns the kits that cover the tool of req and with which
// the pre-execution gate passes a call with params, in the order of the
// catalog: the kits that would lift a refusal of the gate.
func (e *Executor) liftingKits(uc *userctx.UserContext, req authz.Request, params map[string]any) []string {
	var out []string
	for _, kit := range e.Kits() {
		if kit.Covers(req.Tool, req.Backend, req.Access) && e.gatePreflight(uc, withKit(req, kit.Name), params) == "" {
			out = append(out, kit.Name)
		}
	}
	return out
}

// gatePreflight runs the pre-execution gate for a call of the tool of req
// without making it: for the caller uc holding the kits of req, with params
// (none when nil) and GateContext.Preflight set, so that nothing is recorded
// and the policies know. It returns the gate's refusal as "policy <file>:
// <reason>", or "" when the call would pass. A gate that fails counts as a
// refusal, as in ExecuteTool.
func (e *Executor) gatePreflight(uc *userctx.UserContext, req authz.Request, params map[string]any) string {
	// Policies may rewrite the parameters they see; the caller's stay as
	// they are.
	params = maps.Clone(params)
	if params == nil {
		params = map[string]any{}
	}
	var user userctx.UserContext
	if uc != nil {
		user = *uc
	}
	_, err := e.gate.EvaluatePre(gate.GateContext{
		User:       user,
		Tool:       req.Tool,
		ToolAccess: req.Access,
		Params:     params,
		Kits:       kitNames(req.Kits, req.KitParts),
		KitCovered: e.appliedKit(req) != "",
		Preflight:  true,
	})
	if err == nil {
		return ""
	}
	var rej *gate.Rejection
	if errors.As(err, &rej) {
		return rej.Reason
	}
	return err.Error()
}

// withKit is req with the caller holding the kit as well.
func withKit(req authz.Request, kit string) authz.Request {
	req.Kits = append(slices.Clone(req.Kits), kit)
	return req
}

// kitNames lists kits held whole and in part by name, for the gate context:
// never nil, so that policies always see an array.
func kitNames(kits []string, parts []authz.KitPart) []string {
	out := make([]string, 0, len(kits)+len(parts))
	out = append(out, kits...)
	for _, p := range parts {
		if !slices.Contains(out, p.Kit) {
			out = append(out, p.Kit)
		}
	}
	return out
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
				held[j] = withKit(reqs[i], kits[k].Name)
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

// authzRequests describes a call of each tool for the authorizer, with the
// kits the caller holds looked up once for all of them.
func (e *Executor) authzRequests(ctx context.Context, uc *userctx.UserContext, tools []backend.ToolDescriptor) []authz.Request {
	h := e.heldKits(ctx, uc)
	reqs := make([]authz.Request, len(tools))
	for i, t := range tools {
		access := t.Access
		if access == "" {
			access = e.lookupToolAccess(t.Name)
		}
		reqs[i] = e.authzRequest(uc, t.Name, access, h)
	}
	return reqs
}

// KitCoverage tells for each entry of the kit how many of the tools it
// covers, and how many of those the caller may not execute now. It is what
// an approver sees of a request for the kit: computed by ToolMesh with the
// checks AssessTools makes, never taken from the caller.
func (e *Executor) KitCoverage(ctx context.Context, uc *userctx.UserContext, kit authz.Kit, tools []backend.ToolDescriptor) []grants.EntryCoverage {
	reqs := e.authzRequests(ctx, uc, tools)
	allowed := make([]bool, len(reqs))
	if e.authorizer == nil {
		for i := range allowed {
			allowed[i] = true
		}
	} else {
		var covered []int
		for i, r := range reqs {
			if kit.Covers(r.Tool, r.Backend, r.Access) {
				covered = append(covered, i)
			}
		}
		sub := make([]authz.Request, len(covered))
		for j, i := range covered {
			sub[j] = reqs[i]
		}
		for j, ok := range e.checkAll(ctx, sub) {
			allowed[covered[j]] = ok
		}
		// A tool the pre-execution policies refuse now is new to the caller
		// as well, when the kit lifts the refusal.
		if e.gate != nil {
			for _, i := range covered {
				if allowed[i] && e.gatePreflight(uc, reqs[i], nil) != "" && e.gatePreflight(uc, withKit(reqs[i], kit.Name), nil) == "" {
					allowed[i] = false
				}
			}
		}
	}

	out := make([]grants.EntryCoverage, 0, len(kit.Grants)+len(kit.Tools))
	for _, scope := range kit.Grants {
		c := grants.EntryCoverage{Entry: scope}
		for i, r := range reqs {
			if authz.ScopeCovers(scope, r.Backend, r.Access) {
				c.Tools++
				if !allowed[i] {
					c.New++
				}
			}
		}
		out = append(out, c)
	}
	for _, name := range kit.Tools {
		c := grants.EntryCoverage{Entry: name, Tool: true}
		for i, r := range reqs {
			if r.Tool == name {
				c.Access, c.Tools = r.Access, 1
				if !allowed[i] {
					c.New = 1
				}
			}
		}
		out = append(out, c)
	}
	return out
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

// denialRemedy returns the kits that would allow a call the authorizer
// denied and the text that points the caller to them, or nil and "" when no
// kit would. A kit counts when the call with params passes with it, the
// pre-execution gate included.
func (e *Executor) denialRemedy(ctx context.Context, uc *userctx.UserContext, req authz.Request, params map[string]any) (kits []string, remedy string) {
	right := e.assess(ctx, []authz.Request{req}, []bool{false}, true)[0]
	for _, name := range right.Kits {
		if e.gate == nil || e.gatePreflight(uc, withKit(req, name), params) == "" {
			kits = append(kits, name)
		}
	}
	return kits, e.remedyText(kits)
}

// gateRemedy returns the kits that would lift a refusal of the pre-execution
// gate for a call of req with params, and the text that points the caller
// to them: a kit that covers the tool replaces the gate, so with one of
// them the call passes, unless a policy that declares enforce-with-kit
// refuses it. Where kits exist and none lifts the refusal, the text says so.
func (e *Executor) gateRemedy(uc *userctx.UserContext, req authz.Request, params map[string]any) (kits []string, remedy string) {
	kits = e.liftingKits(uc, req, params)
	if len(kits) == 0 && len(e.Kits()) > 0 {
		return nil, " No kit lifts this policy."
	}
	return kits, e.remedyText(kits)
}

// remedyText points the caller to the kits that would allow a call, as a
// sentence that follows the denial; "" without kits.
func (e *Executor) remedyText(kits []string) string {
	if len(kits) == 0 {
		return ""
	}
	descs := make(map[string]string)
	for _, k := range e.Kits() {
		descs[k.Name] = k.Description
	}
	named := make([]string, len(kits))
	for i, name := range kits {
		named[i] = fmt.Sprintf("%q (%s)", name, descs[name])
	}
	subject := "The kit " + named[0] + " covers"
	if len(named) > 1 {
		subject = "The kits " + strings.Join(named, ", ") + " cover"
	}
	if e.kitHolder == nil {
		return fmt.Sprintf(" %s it. Ask for a kit rather than for this one tool, and check first with %s({tools: [...]}) which other tools your task needs, so that one request covers all of them.",
			subject, RightsToolName)
	}
	return fmt.Sprintf(" %s it. Check first with %s({tools: [...]}) which other tools your task needs, then ask once with %s({kit, reason}) for a kit that covers all of them, rather than for this one tool.",
		subject, RightsToolName, RequestGrantToolName)
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
