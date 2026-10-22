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

package gate

import (
	"fmt"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
)

// Pipeline runs a chain of Evaluators in order. If any evaluator rejects
// the request, the pipeline stops and returns the rejection.
type Pipeline struct {
	evaluators []Evaluator
}

// NewPipeline creates a Pipeline from the given evaluators.
func NewPipeline(evaluators []Evaluator) *Pipeline {
	return &Pipeline{evaluators: evaluators}
}

// Outcome is what a run of the pipeline reports when it allows the call.
type Outcome struct {
	// Modifications lists every (policy, target) pair whose JSON
	// representation changed during the run. Nil when no policy mutated
	// the data.
	Modifications []audit.PolicyModification
	// Skipped names the policies that did not run because a kit the caller
	// holds covers the call (GateContext.KitCovered), in the order the
	// evaluators hold them. Nil when every policy ran.
	Skipped []string
}

// Rejection is the error of a run that an evaluator rejected. Callers that
// act on the refusal, such as the preflight of tell_me_my_rights, read the
// policy and the reason from it with errors.As.
type Rejection struct {
	// Evaluator is the name of the evaluator that rejected the call.
	Evaluator string
	// Policy names the rejecting policy when the evaluator told it.
	Policy string
	// Reason is the evaluator's reason, "policy <file>: <reason>" for goja.
	Reason string
}

// Error renders the rejection as the pipeline has always reported it.
func (r *Rejection) Error() string {
	return fmt.Sprintf("evaluator %s rejected: %s", r.Evaluator, r.Reason)
}

// EvaluatePre runs all evaluators in the pre-execution phase. Policies
// receive the tool name and input parameters but no response. The outcome's
// modifications are nil when no policy mutated the data.
func (p *Pipeline) EvaluatePre(ctx GateContext) (Outcome, error) {
	ctx.Phase = PhasePre
	return p.evaluate(ctx)
}

// EvaluatePost runs all evaluators in the post-execution phase. Policies
// receive the tool name, input parameters, and the backend response. The
// outcome's modifications capture every (policy, target) pair where the JSON
// representation changed during the run.
func (p *Pipeline) EvaluatePost(ctx GateContext) (Outcome, error) {
	ctx.Phase = PhasePost
	return p.evaluate(ctx)
}

// Evaluate runs all evaluators in sequence. If Phase is not set, it defaults
// to PhasePost for backward compatibility. Callers that only care about
// reject/allow may discard the returned outcome.
func (p *Pipeline) Evaluate(ctx GateContext) (Outcome, error) {
	if ctx.Phase == "" {
		ctx.Phase = PhasePost
	}
	return p.evaluate(ctx)
}

func (p *Pipeline) evaluate(ctx GateContext) (Outcome, error) {
	var out Outcome
	for _, ev := range p.evaluators {
		result, err := ev.Evaluate(ctx)
		if err != nil {
			return Outcome{}, fmt.Errorf("evaluator %s: %w", ev.Name(), err)
		}
		if !result.Allowed {
			return Outcome{}, &Rejection{Evaluator: ev.Name(), Policy: result.Policy, Reason: result.Reason}
		}
		if result.Modified != nil {
			ctx.Response = result.Modified
		}
		if len(result.Modifications) > 0 {
			out.Modifications = append(out.Modifications, result.Modifications...)
		}
		if len(result.Skipped) > 0 {
			out.Skipped = append(out.Skipped, result.Skipped...)
		}
	}
	return out, nil
}
