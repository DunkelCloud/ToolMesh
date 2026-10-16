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
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// maxPreflightTools bounds the tools one preflight may name, which bounds
// the checks it costs.
const maxPreflightTools = 500

// rightsNote ends every answer of tell_me_my_rights.
const rightsNote = "Information only: every call is still checked when it runs. " +
	"A kit is a named bundle of tools granted together for a limited time; an administrator of this ToolMesh grants it. " +
	"Tell the person you work for which kit your task needs and why, once, instead of asking tool by tool."

// reasonUnavailable is the reason of a denied tool that is not visible to the
// caller. It does not say whether the tool exists, so that the preflight
// cannot be used to probe for tools the caller may not see.
const reasonUnavailable = "not available to you, and no kit covers it"

// reasonBlocked is the reason of a denied tool that a kit covers but a deny
// blocks for the caller.
const reasonBlocked = "a deny rule blocks it for you; no kit lifts that"

// rightsToolDefinition is the MCP definition of tell_me_my_rights.
func rightsToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: toolTellMeMyRights,
		Description: "Tells you what you may do in ToolMesh. Information only: every call is still checked when it runs. " +
			"Without arguments: per backend, how many tools you may call and how many a kit would add. " +
			"backend:\"<name>\": the verdict for each tool of one backend. " +
			"tools:[...]: preflight. Pass every tool your task will need and get one verdict per tool (allowed; escalatable, with the kits that would allow it; denied) " +
			"plus the smallest set of kits that covers everything escalatable. " +
			"A kit is a named bundle of tools granted together for a limited time. Plan first, then ask once: " +
			"run the preflight before you start a task instead of collecting denials one call at a time.",
		InputSchema: map[string]any{
			contentKeyType: jsonTypeObject,
			schemaKeyProperties: map[string]any{
				argNameTools: map[string]any{
					contentKeyType:       jsonTypeArray,
					"items":              map[string]any{contentKeyType: jsonTypeString},
					schemaKeyDescription: fmt.Sprintf("Preflight: the tools your task will need, as discover_tools names them (at most %d).", maxPreflightTools),
				},
				argNameBackend: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "List the verdict for each tool of this backend. Not together with tools.",
				},
			},
		},
	}
}

// rightsTool is one tool in an answer of tell_me_my_rights.
type rightsTool struct {
	Tool    string   `json:"tool"`
	Verdict string   `json:"verdict"`
	Kits    []string `json:"kits,omitempty"`
	Reason  string   `json:"reason,omitempty"`
}

// rightsBackend is one backend in the overview.
type rightsBackend struct {
	Backend     string   `json:"backend"`
	Allowed     int      `json:"allowed"`
	Escalatable int      `json:"escalatable,omitempty"`
	Kits        []string `json:"kits,omitempty"`
}

// rightsKit describes a kit the answer refers to.
type rightsKit struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Warning     string `json:"warning,omitempty"`
	TTLDefault  string `json:"ttl_default,omitempty"`
	TTLMax      string `json:"ttl_max,omitempty"`
}

// rightsBundle is the smallest set of kits found that covers every
// escalatable tool of a preflight.
type rightsBundle struct {
	Kits   []string `json:"kits"`
	Covers []string `json:"covers"`
}

// rightsAnswer is the answer of tell_me_my_rights.
type rightsAnswer struct {
	Caller        string          `json:"caller"`
	Authorization string          `json:"authorization,omitempty"`
	Backends      []rightsBackend `json:"backends,omitempty"`
	Backend       string          `json:"backend,omitempty"`
	Tools         []rightsTool    `json:"tools,omitempty"`
	Bundle        *rightsBundle   `json:"bundle,omitempty"`
	Kits          []rightsKit     `json:"kits,omitempty"`
	Note          string          `json:"note"`
}

// handleTellMeMyRights answers tell_me_my_rights. Every call is audited.
func (h *Handler) handleTellMeMyRights(ctx context.Context, params map[string]any) *backend.ToolResult {
	start := time.Now()
	answer, failure := h.rights(ctx, params)
	if h.executor != nil {
		h.executor.AuditRightsQuery(ctx, params, start, failure)
	}
	if failure != "" {
		return discoverErrorResult(failure)
	}
	body, err := json.MarshalIndent(answer, "", "  ")
	if err != nil {
		return discoverErrorResult(fmt.Sprintf("%s: %s", toolTellMeMyRights, err))
	}
	h.logger.InfoContext(ctx, toolTellMeMyRights, "tools", len(answer.Tools), "backends", len(answer.Backends), "backend", answer.Backend)
	return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: string(body)}}}
}

// rights computes the answer, or the reason the arguments are unusable.
func (h *Handler) rights(ctx context.Context, params map[string]any) (answer *rightsAnswer, failure string) {
	uc := userctx.FromContext(ctx)
	if uc == nil || h.executor == nil {
		return nil, toolTellMeMyRights + ": no caller identity"
	}
	names, err := stringList(params[argNameTools])
	if err != nil {
		return nil, err.Error()
	}
	backendName, _ := params[argNameBackend].(string)
	backendName = strings.TrimSpace(backendName)
	switch {
	case len(names) > 0 && backendName != "":
		return nil, toolTellMeMyRights + ": pass either tools or backend, not both"
	case len(names) > maxPreflightTools:
		return nil, fmt.Sprintf("%s: at most %d tools per preflight, got %d", toolTellMeMyRights, maxPreflightTools, len(names))
	}

	all, lerr := h.backend.ListTools(ctx)
	if lerr != nil {
		return nil, fmt.Sprintf("%s: list tools: %s", toolTellMeMyRights, lerr)
	}

	answer = &rightsAnswer{Caller: uc.UserID, Note: rightsNote}
	if !h.executor.Authorizes() {
		answer.Authorization = "disabled: every authenticated caller may call every tool"
	}
	kitsUsed := map[string]bool{}
	switch {
	case len(names) > 0:
		h.preflight(ctx, uc, all, names, answer, kitsUsed)
	case backendName != "":
		h.backendRights(ctx, uc, all, backendName, answer, kitsUsed)
	default:
		h.overviewRights(ctx, uc, all, answer, kitsUsed)
	}
	answer.Kits = describeKits(h.executor.Kits(), kitsUsed)
	return answer, ""
}

// preflight gives the verdict for each named tool and the bundle of kits
// that covers the escalatable ones.
func (h *Handler) preflight(ctx context.Context, uc *userctx.UserContext, all []backend.ToolDescriptor, names []string, answer *rightsAnswer, kitsUsed map[string]bool) {
	byName := make(map[string]backend.ToolDescriptor, len(all)*2)
	for _, t := range all {
		byName[t.Name] = t
		if _, taken := byName[sanitizeName(t.Name)]; !taken {
			byName[sanitizeName(t.Name)] = t
		}
	}
	found := make([]backend.ToolDescriptor, 0, len(names))
	at := make([]int, len(names)) // index into found, -1 when unknown
	for i, n := range names {
		name := n
		if h.aliasResolver != nil {
			name = h.aliasResolver.ResolveAlias(name)
		}
		d, ok := byName[name]
		if !ok {
			d, ok = byName[sanitizeName(name)]
		}
		at[i] = -1
		if ok {
			at[i] = len(found)
			found = append(found, d)
		}
	}
	rights := h.executor.AssessTools(ctx, uc, found, true)

	escalatable := map[string][]string{} // tool → kits
	for i, n := range names {
		if at[i] < 0 {
			answer.Tools = append(answer.Tools, rightsTool{Tool: n, Verdict: executor.VerdictDenied, Reason: reasonUnavailable})
			continue
		}
		rt := toRightsTool(n, rights[at[i]])
		if rt.Verdict == executor.VerdictEscalatable {
			escalatable[n] = rt.Kits
		}
		answer.Tools = append(answer.Tools, rt)
	}
	if len(escalatable) > 0 {
		answer.Bundle = smallestBundle(escalatable)
		for _, k := range answer.Bundle.Kits {
			kitsUsed[k] = true
		}
	}
}

// backendRights gives the verdict for each visible tool of one backend.
func (h *Handler) backendRights(ctx context.Context, uc *userctx.UserContext, all []backend.ToolDescriptor, name string, answer *rightsAnswer, kitsUsed map[string]bool) {
	answer.Backend = name
	for _, r := range h.executor.AssessTools(ctx, uc, all, true) {
		if r.Backend != name || !visible(r) {
			continue
		}
		rt := toRightsTool(sanitizeName(r.Tool), r)
		for _, k := range rt.Kits {
			kitsUsed[k] = true
		}
		answer.Tools = append(answer.Tools, rt)
	}
}

// overviewRights counts per backend the tools the caller may call and those
// a kit would add. Backends without either are left out.
func (h *Handler) overviewRights(ctx context.Context, uc *userctx.UserContext, all []backend.ToolDescriptor, answer *rightsAnswer, kitsUsed map[string]bool) {
	byBackend := map[string]*rightsBackend{}
	for _, r := range h.executor.AssessTools(ctx, uc, all, true) {
		if r.Verdict == executor.VerdictDenied {
			continue
		}
		b := byBackend[r.Backend]
		if b == nil {
			b = &rightsBackend{Backend: r.Backend}
			byBackend[r.Backend] = b
		}
		if r.Verdict == executor.VerdictAllowed {
			b.Allowed++
			continue
		}
		b.Escalatable++
		for _, k := range r.Kits {
			if !slices.Contains(b.Kits, k) {
				b.Kits = append(b.Kits, k)
			}
			kitsUsed[k] = true
		}
	}
	for _, b := range byBackend {
		slices.Sort(b.Kits)
		answer.Backends = append(answer.Backends, *b)
	}
	slices.SortFunc(answer.Backends, func(a, b rightsBackend) int { return strings.Compare(a.Backend, b.Backend) })
}

// visibleTools keeps the tools the caller may execute and those a kit
// covers, and returns the kits of the latter for the grant_required marker.
// Kits count by their definition here, as discovery must stay cheap; a deny
// that blocks a kit-covered tool shows when it is called or in a preflight.
func visibleTools(ctx context.Context, exec *executor.Executor, uc *userctx.UserContext, tools []backend.ToolDescriptor) ([]backend.ToolDescriptor, grantNotes) {
	rights := exec.AssessTools(ctx, uc, tools, false)
	out := make([]backend.ToolDescriptor, 0, len(tools))
	var notes grantNotes
	for i, t := range tools {
		r := rights[i]
		if !visible(r) {
			continue
		}
		out = append(out, t)
		if r.Verdict == executor.VerdictEscalatable {
			if notes == nil {
				notes = grantNotes{}
			}
			notes[t.Name] = r.Kits
		}
	}
	return out, notes
}

// visible reports whether a tool is shown to the caller: when it may execute
// it, or when a kit covers it.
func visible(r executor.ToolRight) bool {
	return r.Verdict != executor.VerdictDenied || r.Blocked
}

// toRightsTool renders one tool's right under the given name.
func toRightsTool(name string, r executor.ToolRight) rightsTool {
	rt := rightsTool{Tool: name, Verdict: r.Verdict, Kits: r.Kits}
	if r.Verdict == executor.VerdictDenied {
		rt.Reason = reasonUnavailable
		if r.Blocked {
			rt.Reason = reasonBlocked
		}
	}
	return rt
}

// smallestBundle picks kits until every escalatable tool is covered, each
// time the kit that covers most of the remaining ones (by name on a tie).
// Greedy, so not always minimal, but never more than a few kits off.
func smallestBundle(escalatable map[string][]string) *rightsBundle {
	remaining := map[string]bool{}
	for t := range escalatable {
		remaining[t] = true
	}
	b := &rightsBundle{}
	for len(remaining) > 0 {
		gain := map[string]int{}
		for t := range remaining {
			for _, k := range escalatable[t] {
				gain[k]++
			}
		}
		best := ""
		for k, n := range gain {
			if n > gain[best] || (n == gain[best] && k < best) {
				best = k
			}
		}
		b.Kits = append(b.Kits, best)
		for t := range remaining {
			if slices.Contains(escalatable[t], best) {
				delete(remaining, t)
			}
		}
	}
	for t := range escalatable {
		b.Covers = append(b.Covers, t)
	}
	slices.Sort(b.Covers)
	return b
}

// describeKits returns the kits named in used, in catalog order.
func describeKits(kits []authz.Kit, used map[string]bool) []rightsKit {
	var out []rightsKit
	for _, k := range kits {
		if !used[k.Name] {
			continue
		}
		out = append(out, rightsKit{
			Name:        k.Name,
			Description: k.Description,
			Warning:     k.Warning,
			TTLDefault:  formatTTL(k.TTLDefault),
			TTLMax:      formatTTL(k.TTLMax),
		})
	}
	return out
}

// formatTTL renders a duration without zero units ("4h", "90m"); "" for
// zero.
func formatTTL(d time.Duration) string {
	switch {
	case d <= 0:
		return ""
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// stringList reads an optional list of strings. Clients that serialize
// arrays as strings send a JSON array in a string, or a single name.
func stringList(v any) ([]string, error) {
	var out []string
	switch x := v.(type) {
	case nil:
		return nil, nil
	case []string:
		out = x
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%s: %s must be a list of tool names", toolTellMeMyRights, argNameTools)
			}
			out = append(out, s)
		}
	case string:
		x = strings.TrimSpace(x)
		if strings.HasPrefix(x, "[") {
			if err := json.Unmarshal([]byte(x), &out); err != nil {
				return nil, fmt.Errorf("%s: %s must be a list of tool names", toolTellMeMyRights, argNameTools)
			}
		} else if x != "" {
			out = []string{x}
		}
	default:
		return nil, fmt.Errorf("%s: %s must be a list of tool names", toolTellMeMyRights, argNameTools)
	}
	cleaned := make([]string, 0, len(out))
	for _, s := range out {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(cleaned, s) {
			cleaned = append(cleaned, s)
		}
	}
	return cleaned, nil
}
