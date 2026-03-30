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
	"sort"
	"strings"
	"sync"
	"testing"
)

// withCleanRegistry runs fn with a temporary empty registry, restoring the
// original registry afterwards. This prevents tests from interfering with
// each other or with the init()-registered "goja" evaluator.
func withCleanRegistry(t *testing.T, fn func()) {
	t.Helper()
	evalMu.Lock()
	origRegistry := evalRegistry
	evalRegistry = make(map[string]EvaluatorFactory)
	evalMu.Unlock()

	defer func() {
		evalMu.Lock()
		evalRegistry = origRegistry
		evalMu.Unlock()
	}()

	fn()
}

func TestRegisterEvaluator(t *testing.T) {
	tests := []struct {
		name      string
		evalName  string
		setup     func() // pre-register evaluators
		wantPanic bool
	}{
		{
			name:      "registers new evaluator successfully",
			evalName:  "test-eval",
			setup:     func() {},
			wantPanic: false,
		},
		{
			name:     "panics on duplicate registration",
			evalName: "duplicate-eval",
			setup: func() {
				RegisterEvaluator("duplicate-eval", func(config map[string]string) (Evaluator, error) {
					return nil, nil
				})
			},
			wantPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCleanRegistry(t, func() {
				tt.setup()

				factory := func(config map[string]string) (Evaluator, error) {
					return nil, nil
				}

				if tt.wantPanic {
					defer func() {
						r := recover()
						if r == nil {
							t.Error("expected panic for duplicate registration, got none")
						}
						msg := fmt.Sprintf("%v", r)
						if !strings.Contains(msg, "already registered") {
							t.Errorf("unexpected panic message: %s", msg)
						}
					}()
				}

				RegisterEvaluator(tt.evalName, factory)

				if !tt.wantPanic {
					// Verify the evaluator is actually in the registry
					names := EvaluatorNames()
					found := false
					for _, n := range names {
						if n == tt.evalName {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("evaluator %q not found in registry after registration", tt.evalName)
					}
				}
			})
		})
	}
}

func TestNewEvaluator(t *testing.T) {
	tests := []struct {
		name     string
		evalName string
		config   map[string]string
		setup    func()
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "creates evaluator from registered factory",
			evalName: "mock-eval",
			config:   map[string]string{"key": "value"},
			setup: func() {
				RegisterEvaluator("mock-eval", func(config map[string]string) (Evaluator, error) {
					return &mockEvaluator{name: "mock-eval"}, nil
				})
			},
			wantErr: false,
		},
		{
			name:     "returns error for unknown evaluator",
			evalName: "nonexistent",
			config:   nil,
			setup:    func() {},
			wantErr:  true,
			errMsg:   "unknown evaluator",
		},
		{
			name:     "propagates factory error",
			evalName: "failing-eval",
			config:   nil,
			setup: func() {
				RegisterEvaluator("failing-eval", func(config map[string]string) (Evaluator, error) {
					return nil, fmt.Errorf("factory failed")
				})
			},
			wantErr: true,
			errMsg:  "factory failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCleanRegistry(t, func() {
				tt.setup()

				eval, err := NewEvaluator(tt.evalName, tt.config)
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
				if eval == nil {
					t.Fatal("expected non-nil evaluator")
				}
				if eval.Name() != tt.evalName {
					t.Errorf("evaluator name = %q, want %q", eval.Name(), tt.evalName)
				}
			})
		})
	}
}

func TestEvaluatorNames(t *testing.T) {
	tests := []struct {
		name      string
		register  []string
		wantNames []string
	}{
		{
			name:      "empty registry returns empty slice",
			register:  nil,
			wantNames: []string{},
		},
		{
			name:      "returns single registered name",
			register:  []string{"alpha"},
			wantNames: []string{"alpha"},
		},
		{
			name:      "returns all registered names",
			register:  []string{"alpha", "beta", "gamma"},
			wantNames: []string{"alpha", "beta", "gamma"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withCleanRegistry(t, func() {
				for _, name := range tt.register {
					RegisterEvaluator(name, func(config map[string]string) (Evaluator, error) {
						return nil, nil
					})
				}

				got := EvaluatorNames()
				sort.Strings(got)
				sort.Strings(tt.wantNames)

				if len(got) != len(tt.wantNames) {
					t.Fatalf("EvaluatorNames() returned %d names, want %d", len(got), len(tt.wantNames))
				}
				for i := range got {
					if got[i] != tt.wantNames[i] {
						t.Errorf("EvaluatorNames()[%d] = %q, want %q", i, got[i], tt.wantNames[i])
					}
				}
			})
		})
	}
}

func TestNewEvaluator_Concurrent(t *testing.T) {
	withCleanRegistry(t, func() {
		RegisterEvaluator("concurrent-eval", func(config map[string]string) (Evaluator, error) {
			return &mockEvaluator{name: "concurrent-eval"}, nil
		})

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				eval, err := NewEvaluator("concurrent-eval", nil)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if eval.Name() != "concurrent-eval" {
					t.Errorf("unexpected name: %s", eval.Name())
				}
			}()
		}
		wg.Wait()
	})
}

// mockEvaluator is a simple Evaluator implementation for testing.
type mockEvaluator struct {
	name      string
	allowAll  bool
	rejectMsg string
	evalErr   error
	modified  *EvalResult
}

func (m *mockEvaluator) Name() string { return m.name }

func (m *mockEvaluator) Evaluate(_ GateContext) (*EvalResult, error) {
	if m.evalErr != nil {
		return nil, m.evalErr
	}
	if m.modified != nil {
		return m.modified, nil
	}
	if m.rejectMsg != "" {
		return &EvalResult{Allowed: false, Reason: m.rejectMsg}, nil
	}
	return &EvalResult{Allowed: true}, nil
}
