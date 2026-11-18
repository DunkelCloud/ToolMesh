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
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/google/uuid"
)

// metaHintRequired names, in the audit entry of a refused call, the backend
// whose hint the caller had yet to show it received.
const metaHintRequired = "hint_required"

// errHintProofMissing is the audit error of a call refused for want of a
// current hint proof.
const errHintProofMissing = "hint proof missing or expired"

// proofValidity is the sentence a refusal ends with.
const proofValidity = "A proof is valid until the end of the day (UTC)."

// SetClock replaces the clock that dates hint proofs. Tests use it to move
// across the end of a day; nil restores the wall clock.
func (e *Executor) SetClock(now func() time.Time) { e.now = now }

// today is the time hint proofs are dated with.
func (e *Executor) today() time.Time {
	if e.now != nil {
		return e.now()
	}
	return time.Now()
}

// hintInfo returns the summary of the backend a tool is routed to. It is
// false when the backend set cannot resolve tools to backends or report
// their hints, or when no backend claims the tool.
func (e *Executor) hintInfo(toolName string) (backend.BackendInfo, bool) {
	name := e.routedBackend(toolName)
	if name == "" {
		return backend.BackendInfo{}, false
	}
	return e.hintInfoByName(name)
}

// hintInfoByName returns the summary of the named backend. The summaries
// are read on every call so that a reloaded backend set applies at once.
func (e *Executor) hintInfoByName(name string) (backend.BackendInfo, bool) {
	summarizer, ok := e.backend.(backend.BackendSummarizer)
	if !ok {
		return backend.BackendInfo{}, false
	}
	for _, info := range summarizer.BackendSummaries() {
		if info.Name == name {
			return info, true
		}
	}
	return backend.BackendInfo{}, false
}

// hintRefusal checks the hint precondition of a call: a tool the operator
// listed under hint_required_for, by name or by access class, runs only
// when the call carries the day's proof that the backend's hint was
// received. It returns the backend name and the text to refuse the call
// with, or two empty strings when the call may proceed.
//
// The refusal is the delivery. A gateway cannot tell one conversation from
// the next, so it cannot keep track of who has been told; a conversation
// that has not been told has no proof, is refused once, and receives the
// hint together with the proof to present from then on.
//
// A script is checked before it runs (HintPreflight), so this refusal meets
// a direct tool call, which cannot carry a proof, and a script that reaches
// the tool under a name it computes.
func (e *Executor) hintRefusal(toolName, toolAccess string, proofs []string) (backendName, text string) {
	info, ok := e.hintInfo(toolName)
	if !ok || !info.HintRequired(toolName, toolAccess) {
		return "", ""
	}
	want := backend.HintProof(info.Name, info.Hint, e.today())
	if slices.Contains(proofs, want) {
		return "", ""
	}
	return info.Name, fmt.Sprintf("%s\n\n"+
		"Not executed: %s needs proof that the above was received. "+
		"Call it in an execute_code script and pass this argument next to \"code\":\n\n"+
		"%s\n\n%s",
		hintNote(info), toolName, proofsArgument(replaceProofs(proofs, map[string]string{info.Name: want})), proofValidity)
}

// HintPreflight checks the hint preconditions of a script before it runs:
// the proofs passed with it and the tools it names. It returns the text to
// refuse the run with, or "" when the script may run.
//
// A script that would be refused at one of its calls is refused here
// instead, with nothing executed: no read runs twice and no write is left
// half done. tools are the tools the script names. A tool it reaches under
// a name it computes is not among them and is refused at the call
// (hintRefusal).
//
// The proofs are an argument of the run and never part of the script, so a
// script cannot present a proof it has just been handed. Between a refusal
// and the run that carries the proof lies a turn of whoever started the
// script, and that is where the hint is read. A script whose text is fixed
// stays as it is.
//
// Three things end a run here: a proof that is not of the form a refusal
// prints; a proof whose day is over or whose hint has changed, which
// delivers the hint in force; and a named tool that needs a proof none was
// passed for. The last counts only for a tool the caller may call: a caller
// without the right is told so at the call, and the hint goes to callers
// that can act on it. A proof for a backend that requires none is accepted,
// so that a caller keeps working after an operator lifts the requirement.
func (e *Executor) HintPreflight(ctx context.Context, tools, proofs []string) string {
	for _, proof := range proofs {
		if _, ok := backend.HintProofBackend(proof); !ok {
			return fmt.Sprintf("Not executed: %q is not a proof. Pass proofs as a refused call prints them, for example %s",
				proof, proofsArgument([]string{"<backend>:<digest>"}))
		}
	}

	var (
		delivered []backend.BackendInfo // backends whose hint the refusal carries
		current   = map[string]string{} // their proofs of the day
		stale     []string              // backends with a proof that no longer holds
	)
	deliver := func(info backend.BackendInfo, want string) {
		if _, seen := current[info.Name]; !seen {
			current[info.Name] = want
			delivered = append(delivered, info)
		}
	}

	for _, proof := range proofs {
		name, _ := backend.HintProofBackend(proof)
		info, known := e.hintInfoByName(name)
		if !known || len(info.HintRequiredFor) == 0 || strings.TrimSpace(info.Hint) == "" {
			continue
		}
		want := backend.HintProof(info.Name, info.Hint, e.today())
		if slices.Contains(proofs, want) {
			continue
		}
		if _, seen := current[info.Name]; !seen {
			stale = append(stale, info.Name)
		}
		deliver(info, want)
	}

	lacking := e.toolsLackingProof(ctx, tools, proofs)
	names := make([]string, 0, len(lacking))
	for _, l := range lacking {
		names = append(names, l.tool)
		deliver(l.info, l.want)
	}

	if len(delivered) == 0 {
		return ""
	}

	userID := ""
	if uc := userctx.FromContext(ctx); uc != nil {
		userID = uc.UserID
	}
	backends := make([]string, 0, len(delivered))
	for _, info := range delivered {
		backends = append(backends, info.Name)
	}
	e.logger.InfoContext(ctx, "script refused before its first call, hint delivered",
		"backends", backends,
		"tools", names,
		"staleProofs", stale,
		"user", userID,
	)

	var b strings.Builder
	for _, info := range delivered {
		b.WriteString(hintNote(info))
		b.WriteString("\n\n")
	}
	b.WriteString("Not executed, and none of the script's calls has run.")
	if len(names) > 0 {
		fmt.Fprintf(&b, " The script calls %s, which %s proof that the above was received.",
			strings.Join(names, ", "), plural(len(names), "needs", "need"))
	}
	if len(stale) > 0 {
		fmt.Fprintf(&b, " The %s passed for %s %s no longer valid: a proof expires at the end of the day (UTC) and when the note changes.",
			plural(len(stale), "proof", "proofs"), strings.Join(stale, ", "), plural(len(stale), "is", "are"))
	}
	b.WriteString(" Run the same code again and pass this argument next to \"code\":\n\n")
	b.WriteString(proofsArgument(replaceProofs(proofs, current)))
	b.WriteString("\n\n")
	b.WriteString(proofValidity)
	return b.String()
}

// lackingProof is a tool a script names that needs a hint proof the run
// does not carry.
type lackingProof struct {
	tool string
	info backend.BackendInfo
	want string
}

// toolsLackingProof returns, of the tools a script names, those that need a
// hint proof the run does not carry and that the caller may call, and
// records each as a refused call. The tools keep their order; a tool named
// twice counts once.
func (e *Executor) toolsLackingProof(ctx context.Context, tools, proofs []string) []lackingProof {
	uc := userctx.FromContext(ctx)
	if uc == nil {
		// Without a caller every call of the script fails on its own.
		return nil
	}

	var (
		candidates []lackingProof
		descs      []backend.ToolDescriptor
		seen       = map[string]struct{}{}
	)
	for _, tool := range tools {
		if _, dup := seen[tool]; dup {
			continue
		}
		seen[tool] = struct{}{}
		info, ok := e.hintInfo(tool)
		if !ok {
			continue
		}
		access := e.lookupToolAccess(tool)
		if !info.HintRequired(tool, access) {
			continue
		}
		want := backend.HintProof(info.Name, info.Hint, e.today())
		if slices.Contains(proofs, want) {
			continue
		}
		candidates = append(candidates, lackingProof{tool: tool, info: info, want: want})
		descs = append(descs, backend.ToolDescriptor{Name: tool, Access: access})
	}
	if len(candidates) == 0 {
		return nil
	}

	rights := e.AssessTools(ctx, uc, descs, false)
	lacking := make([]lackingProof, 0, len(candidates))
	for i, c := range candidates {
		if rights[i].Verdict != VerdictAllowed {
			continue
		}
		lacking = append(lacking, c)

		entry := audit.AuditEntry{
			TraceID:     uuid.New().String(),
			Timestamp:   time.Now(),
			UserID:      uc.UserID,
			CompanyID:   uc.CompanyID,
			CallerID:    uc.CallerID,
			CallerName:  uc.CallerName,
			CallerClass: uc.CallerClass,
			Tool:        c.tool,
			ToolAccess:  descs[i].Access,
			Backend:     c.info.Name,
			Status:      statusDenied,
			Error:       errHintProofMissing,
		}
		addMetadata(&entry, metaHintRequired, c.info.Name)
		e.recordAudit(ctx, entry)
	}
	return lacking
}

// replaceProofs returns the proofs a caller passed with those of the given
// backends set to their current value: proofs of other backends stay, an
// outdated one goes. The current proofs follow in the order of their
// backend names, so that the same refusal always prints the same argument.
func replaceProofs(passed []string, current map[string]string) []string {
	out := make([]string, 0, len(passed)+len(current))
	for _, proof := range passed {
		if name, ok := backend.HintProofBackend(proof); ok {
			if _, replaced := current[name]; replaced {
				continue
			}
		}
		if !slices.Contains(out, proof) {
			out = append(out, proof)
		}
	}
	names := make([]string, 0, len(current))
	for name := range current {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		out = append(out, current[name])
	}
	return out
}

// hintNote renders a backend's hint as the note a caller is shown.
func hintNote(info backend.BackendInfo) string {
	return "[ToolMesh note: " + info.Name + "] " + strings.TrimSpace(info.Hint)
}

// proofsArgument renders proofs as the execute_code argument that presents
// them.
func proofsArgument(proofs []string) string {
	quoted := make([]string, len(proofs))
	for i, proof := range proofs {
		quoted[i] = strconv.Quote(proof)
	}
	return `"proofs": [` + strings.Join(quoted, ", ") + `]`
}

// plural picks the word for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
