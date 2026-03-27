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

import "fmt"

// Pipeline runs a chain of Evaluators in order. If any evaluator rejects
// the request, the pipeline stops and returns the rejection.
type Pipeline struct {
	evaluators []Evaluator
}

// NewPipeline creates a Pipeline from the given evaluators.
func NewPipeline(evaluators []Evaluator) *Pipeline {
	return &Pipeline{evaluators: evaluators}
}

// EvaluatePre runs all evaluators in the pre-execution phase.
// Policies receive the tool name and input parameters but no response.
func (p *Pipeline) EvaluatePre(ctx GateContext) error {
	ctx.Phase = PhasePre
	return p.evaluate(ctx)
}

// EvaluatePost runs all evaluators in the post-execution phase.
// Policies receive the tool name, input parameters, and the backend response.
func (p *Pipeline) EvaluatePost(ctx GateContext) error {
	ctx.Phase = PhasePost
	return p.evaluate(ctx)
}

// Evaluate runs all evaluators in sequence. If Phase is not set, it defaults
// to PhasePost for backward compatibility.
func (p *Pipeline) Evaluate(ctx GateContext) error {
	if ctx.Phase == "" {
		ctx.Phase = PhasePost
	}
	return p.evaluate(ctx)
}

func (p *Pipeline) evaluate(ctx GateContext) error {
	for _, ev := range p.evaluators {
		result, err := ev.Evaluate(ctx)
		if err != nil {
			return fmt.Errorf("evaluator %s: %w", ev.Name(), err)
		}
		if !result.Allowed {
			return fmt.Errorf("evaluator %s rejected: %s", ev.Name(), result.Reason)
		}
		if result.Modified != nil {
			ctx.Response = result.Modified
		}
	}
	return nil
}
