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
	"slices"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// metaHintRequired names, in the audit entry of a refused call, the backend
// whose hint the caller had yet to show it received.
const metaHintRequired = "hint_required"

// errHintProofMissing is the audit error of a call refused for want of a
// current hint proof.
const errHintProofMissing = "hint proof missing or expired"

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

// hintRefusal checks the hint precondition of a call: a tool whose access
// class the operator listed under hint_required_for runs only when the call
// carries the day's proof that the backend's hint was received. It returns
// the backend name and the text to refuse the call with, or two empty
// strings when the call may proceed.
//
// The refusal is the delivery. A gateway cannot tell one conversation from
// the next, so it cannot keep track of who has been told; a conversation
// that has not been told has no proof, is refused once, and receives the
// hint together with the proof to present from then on.
func (e *Executor) hintRefusal(toolName, toolAccess string, proofs []string) (backendName, text string) {
	info, ok := e.hintInfo(toolName)
	if !ok || !info.HintRequired(toolAccess) {
		return "", ""
	}
	want := backend.HintProof(info.Name, info.Hint, e.today())
	if slices.Contains(proofs, want) {
		return "", ""
	}
	return info.Name, fmt.Sprintf("%s\n\n"+
		"Not executed: %s needs proof that the note above was received. "+
		"Start every execute_code script that calls such a tool with this line, then run the call again:\n\n"+
		"%s\n\n"+
		"The line is valid until the end of the day (UTC).",
		hintNote(info), toolName, assertProofsLine(want))
}

// CheckHintProofs verifies the proofs a script asserts before it makes its
// calls. A proof for a backend that requires none is accepted, so that a
// script keeps working after an operator lifts the requirement. A stale or
// wrong proof is an error that carries the hint in force and the proof to
// use instead: the script fails before its first call rather than halfway.
func (e *Executor) CheckHintProofs(proofs []string) error {
	for _, proof := range proofs {
		name, ok := backend.HintProofBackend(proof)
		if !ok {
			return fmt.Errorf("assert_proofs: %q is not a proof; expected \"<backend>:<digest>\" as a refused call prints it", proof)
		}
		info, known := e.hintInfoByName(name)
		if !known || len(info.HintRequiredFor) == 0 || strings.TrimSpace(info.Hint) == "" {
			continue
		}
		want := backend.HintProof(info.Name, info.Hint, e.today())
		if proof == want {
			continue
		}
		return fmt.Errorf("assert_proofs: the proof for %s is no longer valid. "+
			"A proof expires at the end of the day (UTC) and when the note changes. The note in force:\n\n"+
			"%s\n\n"+
			"Replace the line with:\n\n%s",
			info.Name, hintNote(info), assertProofsLine(want))
	}
	return nil
}

// hintNote renders a backend's hint as the note a caller is shown.
func hintNote(info backend.BackendInfo) string {
	return "[ToolMesh note: " + info.Name + "] " + strings.TrimSpace(info.Hint)
}

// assertProofsLine is the line a script starts with to present a proof.
func assertProofsLine(proof string) string {
	return fmt.Sprintf("toolmesh.assert_proofs([%q]);", proof)
}
