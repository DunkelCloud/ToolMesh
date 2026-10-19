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

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/grants"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// toolRequestGrant is the meta-tool a caller asks for a kit with.
const toolRequestGrant = grants.ToolRequestGrant

// Arguments of request_grant, besides argNameTTL (shared with upload_file).
const (
	argNameKit    = "kit"
	argNameReason = "reason"
)

// SetGrants lets callers ask for kits with request_grant and shows their
// grants in tell_me_my_rights. Without it, kits cannot be granted.
func (h *Handler) SetGrants(svc *grants.Service) { h.grants = svc }

// offersRequestGrant reports whether request_grant is listed: when kits can
// be granted and at least one is defined.
func (h *Handler) offersRequestGrant() bool {
	return h.grants != nil && len(h.grants.Kits()) > 0
}

// requestGrantToolDefinition is the MCP definition of request_grant.
func requestGrantToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: toolRequestGrant,
		Description: "Asks for a kit: a named bundle of tools granted together for a limited time, once a person approves it. " +
			"Plan first: " + toolTellMeMyRights + "({tools: [...]}) with every tool your task needs names the kits that cover them. " +
			"Then ask once per kit, with the task (and ticket, if any) as reason, instead of asking tool by tool. " +
			"The answer is a request id and, where approvers sign on the approval page, its link and fingerprint: give them to the person you work for, an approver of this ToolMesh decides on it. " +
			"Once approved, the kit's tools work for you from this connection until the grant ends; " + toolTellMeMyRights + " shows your grants and pending requests.",
		InputSchema: map[string]any{
			contentKeyType: jsonTypeObject,
			schemaKeyProperties: map[string]any{
				argNameKit: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "The kit, as " + toolTellMeMyRights + " names it.",
				},
				argNameReason: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: fmt.Sprintf("What the kit is for: the task and, if there is one, the ticket. The approver reads it. At most %d characters.", grants.MaxReasonLen),
				},
				argNameTTL: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "How long you need the kit, such as \"30m\" or \"4h\". Optional: the kit's default applies, and no more than its maximum is granted.",
				},
			},
			schemaKeyRequired: []string{argNameKit, argNameReason},
		},
	}
}

// grantAnswer is the answer of request_grant.
type grantAnswer struct {
	RequestID      string    `json:"request_id"`
	Status         string    `json:"status"`
	Kit            string    `json:"kit"`
	Description    string    `json:"description"`
	Warning        string    `json:"warning,omitempty"`
	TTL            string    `json:"ttl"`
	TTLNote        string    `json:"ttl_note,omitempty"`
	LapsesAt       time.Time `json:"lapses_at"`
	AlreadyPending bool      `json:"already_pending,omitempty"`
	HeldUntil      time.Time `json:"held_until,omitzero"`
	// ApprovalURL is the approval page of the request, where an approver
	// signs; absent when no approver signs or no public URL is configured.
	ApprovalURL string `json:"approval_url,omitempty"`
	// Fingerprint identifies the request; the approval page shows the same.
	Fingerprint string `json:"fingerprint"`
	Note        string `json:"note"`
}

// kitCoverage computes what each entry of the kit would give the caller, for
// the approver. It is nil when the kit or the tool list is unavailable: the
// request goes ahead without it.
func (h *Handler) kitCoverage(ctx context.Context, uc *userctx.UserContext, name string) []grants.EntryCoverage {
	if h.executor == nil || uc == nil {
		return nil
	}
	for _, k := range h.grants.Kits() {
		if k.Name != name {
			continue
		}
		all, err := h.backend.ListTools(ctx)
		if err != nil {
			h.logger.WarnContext(ctx, toolRequestGrant+": list tools for the coverage of the kit", outcomeError, err)
			return nil
		}
		return h.executor.KitCoverage(ctx, uc, k, all)
	}
	return nil
}

// handleRequestGrant answers request_grant. The grant service audits every
// call.
func (h *Handler) handleRequestGrant(ctx context.Context, params map[string]any) *backend.ToolResult {
	if h.grants == nil {
		return discoverErrorResult(toolRequestGrant + ": kits cannot be granted in this ToolMesh")
	}
	var in grants.RequestInput
	for name, dst := range map[string]*string{argNameKit: &in.Kit, argNameReason: &in.Reason, argNameTTL: &in.TTL} {
		switch v := params[name].(type) {
		case nil:
		case string:
			*dst = v
		default:
			return discoverErrorResult(fmt.Sprintf("%s: %s must be a string", toolRequestGrant, name))
		}
	}
	uc := userctx.FromContext(ctx)
	if uc != nil && uc.Authenticated {
		in.Coverage = h.kitCoverage(ctx, uc, strings.TrimSpace(in.Kit))
	}
	res, err := h.grants.Request(ctx, uc, in)
	if err != nil {
		return discoverErrorResult(fmt.Sprintf("%s: %s", toolRequestGrant, err))
	}

	g := res.Grant
	answer := grantAnswer{
		RequestID:      g.ID,
		Status:         g.State,
		Kit:            g.Kit,
		TTL:            grants.FormatTTL(g.TTL),
		LapsesAt:       g.ExpiresAt,
		AlreadyPending: res.Existing,
		HeldUntil:      res.HeldUntil,
		ApprovalURL:    h.grants.ApprovalURL(g.ID),
		Fingerprint:    g.Fingerprint(),
	}
	for _, k := range h.grants.Kits() {
		if k.Name == g.Kit {
			answer.Description, answer.Warning = k.Description, k.Warning
		}
	}
	if res.Capped {
		answer.TTLNote = "more than the kit's maximum was asked for; the request is for the maximum"
	}
	approveAt := fmt.Sprintf("Give them the request id %s and the fingerprint %s: an approver of this ToolMesh approves or denies it on the approver API", g.ID, answer.Fingerprint)
	if answer.ApprovalURL != "" {
		approveAt = fmt.Sprintf("Give them this link exactly as written, %s, and the fingerprint %s: an approver of this ToolMesh opens the link, checks the fingerprint and approves, possibly for less time or fewer tools", answer.ApprovalURL, answer.Fingerprint)
	}
	answer.Note = fmt.Sprintf("Tell the person you work for that request %s asks for the kit %q (%s) for %s, and why. "+
		"%s; unanswered, it lapses at %s. "+
		"Once approved, the kit's tools work for you from this connection until the grant ends, without reconnecting. "+
		"Do not ask again while it is pending; %s shows your grants and pending requests.",
		g.ID, g.Kit, answer.Description, answer.TTL, approveAt, g.ExpiresAt.UTC().Format(time.RFC3339), toolTellMeMyRights)
	if res.Existing {
		answer.Note = "You had asked for this kit already; that request is still pending and unchanged. " + answer.Note
	}
	body, err := json.MarshalIndent(answer, "", "  ")
	if err != nil {
		return discoverErrorResult(fmt.Sprintf("%s: %s", toolRequestGrant, err))
	}
	return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: string(body)}}}
}
