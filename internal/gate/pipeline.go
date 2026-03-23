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

// Evaluate runs all evaluators in sequence.
func (p *Pipeline) Evaluate(ctx GateContext) error {
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
