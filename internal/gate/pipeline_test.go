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
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

func TestPipeline_Evaluate(t *testing.T) {
	tests := []struct {
		name       string
		evaluators []Evaluator
		ctx        GateContext
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "empty pipeline allows all",
			evaluators: []Evaluator{},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: false,
		},
		{
			name: "single allowing evaluator passes",
			evaluators: []Evaluator{
				&mockEvaluator{name: "allow-all", allowAll: true},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: false,
		},
		{
			name: "single rejecting evaluator blocks",
			evaluators: []Evaluator{
				&mockEvaluator{name: "blocker", rejectMsg: "not allowed"},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: true,
			errMsg:  "rejected",
		},
		{
			name: "evaluator returning error propagates",
			evaluators: []Evaluator{
				&mockEvaluator{name: "error-eval", evalErr: fmt.Errorf("internal failure")},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: true,
			errMsg:  "internal failure",
		},
		{
			name: "first evaluator passes but second rejects",
			evaluators: []Evaluator{
				&mockEvaluator{name: "pass-eval", allowAll: true},
				&mockEvaluator{name: "block-eval", rejectMsg: "blocked by second"},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: true,
			errMsg:  "blocked by second",
		},
		{
			name: "multiple allowing evaluators all pass",
			evaluators: []Evaluator{
				&mockEvaluator{name: "eval-1", allowAll: true},
				&mockEvaluator{name: "eval-2", allowAll: true},
				&mockEvaluator{name: "eval-3", allowAll: true},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			},
			wantErr: false,
		},
		{
			name: "defaults to PhasePost when phase is empty",
			evaluators: []Evaluator{
				&mockEvaluator{name: "pass-eval", allowAll: true},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Phase:    "", // should default to PhasePost
				Response: &backend.ToolResult{},
			},
			wantErr: false,
		},
		{
			name: "preserves explicit phase",
			evaluators: []Evaluator{
				&mockEvaluator{name: "pass-eval", allowAll: true},
			},
			ctx: GateContext{
				User:     userctx.UserContext{UserID: "u1"},
				Tool:     "test_tool",
				Phase:    PhasePre,
				Response: &backend.ToolResult{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewPipeline(tt.evaluators)
			err := p.Evaluate(tt.ctx)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestPipeline_Evaluate_ModifiedResult(t *testing.T) {
	modifiedResult := &backend.ToolResult{
		Content: []any{map[string]any{"type": "text", "text": "modified"}},
	}

	evaluators := []Evaluator{
		&mockEvaluator{
			name: "modifier",
			modified: &EvalResult{
				Allowed:  true,
				Modified: modifiedResult,
			},
		},
		&mockEvaluator{name: "pass-eval", allowAll: true},
	}

	p := NewPipeline(evaluators)
	ctx := GateContext{
		User:     userctx.UserContext{UserID: "u1"},
		Tool:     "test_tool",
		Response: &backend.ToolResult{Content: []any{map[string]any{"type": "text", "text": "original"}}},
	}

	err := p.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPipeline_EvaluatePre_And_EvaluatePost(t *testing.T) {
	// Evaluator that blocks in pre phase only
	preBlocker := &phaseAwareEvaluator{
		name:       "phase-checker",
		blockPhase: PhasePre,
	}

	p := NewPipeline([]Evaluator{preBlocker})

	// EvaluatePre should set phase to PhasePre and trigger block
	err := p.EvaluatePre(GateContext{
		User:     userctx.UserContext{UserID: "u1"},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err == nil {
		t.Error("expected EvaluatePre to fail with phase-blocking evaluator")
	}

	// EvaluatePost should set phase to PhasePost and pass
	err = p.EvaluatePost(GateContext{
		User:     userctx.UserContext{UserID: "u1"},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Errorf("expected EvaluatePost to pass, got: %v", err)
	}
}

// phaseAwareEvaluator blocks requests in a specific phase.
type phaseAwareEvaluator struct {
	name       string
	blockPhase Phase
}

func (e *phaseAwareEvaluator) Name() string { return e.name }

func (e *phaseAwareEvaluator) Evaluate(ctx GateContext) (*EvalResult, error) {
	if ctx.Phase == e.blockPhase {
		return &EvalResult{Allowed: false, Reason: fmt.Sprintf("blocked in %s phase", e.blockPhase)}, nil
	}
	return &EvalResult{Allowed: true}, nil
}
