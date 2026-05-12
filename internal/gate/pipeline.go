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

// EvaluatePre runs all evaluators in the pre-execution phase. Policies
// receive the tool name and input parameters but no response. The returned
// modification slice is nil when no policy mutated the data.
func (p *Pipeline) EvaluatePre(ctx GateContext) ([]audit.PolicyModification, error) {
	ctx.Phase = PhasePre
	return p.evaluate(ctx)
}

// EvaluatePost runs all evaluators in the post-execution phase. Policies
// receive the tool name, input parameters, and the backend response. The
// returned modification slice captures every (policy, target) pair where
// the JSON representation changed during the run.
func (p *Pipeline) EvaluatePost(ctx GateContext) ([]audit.PolicyModification, error) {
	ctx.Phase = PhasePost
	return p.evaluate(ctx)
}

// Evaluate runs all evaluators in sequence. If Phase is not set, it defaults
// to PhasePost for backward compatibility. Callers that only care about
// reject/allow may discard the returned modifications slice.
func (p *Pipeline) Evaluate(ctx GateContext) ([]audit.PolicyModification, error) {
	if ctx.Phase == "" {
		ctx.Phase = PhasePost
	}
	return p.evaluate(ctx)
}

func (p *Pipeline) evaluate(ctx GateContext) ([]audit.PolicyModification, error) {
	var mods []audit.PolicyModification
	for _, ev := range p.evaluators {
		result, err := ev.Evaluate(ctx)
		if err != nil {
			return nil, fmt.Errorf("evaluator %s: %w", ev.Name(), err)
		}
		if !result.Allowed {
			return nil, fmt.Errorf("evaluator %s rejected: %s", ev.Name(), result.Reason)
		}
		if result.Modified != nil {
			ctx.Response = result.Modified
		}
		if len(result.Modifications) > 0 {
			mods = append(mods, result.Modifications...)
		}
	}
	return mods, nil
}
