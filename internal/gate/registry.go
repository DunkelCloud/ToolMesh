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
	"sync"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// Evaluator is a single evaluation step in the gate pipeline.
type Evaluator interface {
	// Name returns the evaluator name (e.g. "goja", "compliance-llm").
	Name() string
	// Evaluate runs policies against the given context. In the "pre" phase,
	// policies can inspect tool name and input parameters to block execution.
	// In the "post" phase, policies can inspect and modify the response.
	Evaluate(ctx GateContext) (*EvalResult, error)
}

// EvalResult describes the outcome of an evaluation.
type EvalResult struct {
	Allowed  bool                // Whether the result may be returned to the caller.
	Modified *backend.ToolResult // Optional: modified result (fields removed, etc.).
	Reason   string              // If rejected: reason.
}

// EvaluatorFactory creates an Evaluator instance from configuration.
type EvaluatorFactory func(config map[string]string) (Evaluator, error)

var (
	evalMu       sync.RWMutex
	evalRegistry = make(map[string]EvaluatorFactory)
)

// RegisterEvaluator registers an Evaluator factory under a name.
// Typically called from init().
func RegisterEvaluator(name string, factory EvaluatorFactory) {
	evalMu.Lock()
	defer evalMu.Unlock()
	if _, exists := evalRegistry[name]; exists {
		panic(fmt.Sprintf("gate: evaluator %q already registered", name))
	}
	evalRegistry[name] = factory
}

// NewEvaluator creates an Evaluator instance by its registered name.
func NewEvaluator(name string, config map[string]string) (Evaluator, error) {
	evalMu.RLock()
	factory, exists := evalRegistry[name]
	evalMu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("gate: unknown evaluator %q (registered: %v)", name, EvaluatorNames())
	}
	return factory(config)
}

// EvaluatorNames returns all registered evaluator names.
func EvaluatorNames() []string {
	evalMu.RLock()
	defer evalMu.RUnlock()
	names := make([]string, 0, len(evalRegistry))
	for name := range evalRegistry {
		names = append(names, name)
	}
	return names
}
