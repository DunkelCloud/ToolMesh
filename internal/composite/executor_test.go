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

package composite

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// mockExecutor returns a ToolExecutor that responds with predefined results.
func mockExecutor(results map[string]any) ToolExecutor {
	return func(ctx context.Context, toolName string, params map[string]any) (any, error) {
		r, ok := results[toolName]
		if !ok {
			return nil, fmt.Errorf("tool %q not found", toolName)
		}
		return r, nil
	}
}

func TestExecute(t *testing.T) {
	tests := []struct {
		name      string
		comp      dadl.CompositeDef
		tools     []string
		executor  ToolExecutor
		params    map[string]any
		wantErr   string
		checkFunc func(t *testing.T, r *Result)
	}{
		{
			name: "happy path — calls two tools and joins results",
			comp: dadl.CompositeDef{
				Description: "join test",
				Code: `
					const items = await api.list_items();
					const status = await api.get_status();
					return { items: items, status: status };
				`,
				Timeout: "10s",
			},
			tools: []string{"list_items", "get_status"},
			executor: mockExecutor(map[string]any{
				"list_items": []any{map[string]any{"id": "a", "name": "Item A"}},
				"get_status": map[string]any{"ok": true},
			}),
			checkFunc: func(t *testing.T, r *Result) {
				if r.Value == nil {
					t.Fatal("result value is nil")
				}
				m, ok := r.Value.(map[string]any)
				if !ok {
					t.Fatalf("expected map, got %T", r.Value)
				}
				if m["status"] == nil {
					t.Error("status is nil")
				}
				if len(r.AuditEvents) != 2 {
					t.Errorf("expected 2 audit events, got %d", len(r.AuditEvents))
				}
			},
		},
		{
			name: "params passed through",
			comp: dadl.CompositeDef{
				Description: "params test",
				Code:        `return params.filter_on;`,
				Timeout:     "5s",
			},
			tools:    []string{},
			executor: mockExecutor(nil),
			params:   map[string]any{"filter_on": true},
			checkFunc: func(t *testing.T, r *Result) {
				if r.Value != true {
					t.Errorf("expected true, got %v", r.Value)
				}
			},
		},
		{
			name: "timeout kills infinite loop",
			comp: dadl.CompositeDef{
				Description: "timeout test",
				Code:        `while(true) {}`,
				Timeout:     "100ms",
			},
			tools:    []string{},
			executor: mockExecutor(nil),
			wantErr:  "interrupted",
		},
		{
			name: "call depth exceeded",
			comp: dadl.CompositeDef{
				Description: "depth test",
				Code: `
					for (let i = 0; i < 51; i++) {
						await api.ping();
					}
				`,
				Timeout: "10s",
			},
			tools: []string{"ping"},
			executor: mockExecutor(map[string]any{
				"ping": "pong",
			}),
			wantErr: "exceeded maximum",
		},
		{
			name: "empty result returns null",
			comp: dadl.CompositeDef{
				Description: "empty test",
				Code:        `// no return`,
				Timeout:     "5s",
			},
			tools:    []string{},
			executor: mockExecutor(nil),
			checkFunc: func(t *testing.T, r *Result) {
				if r.Value != nil {
					t.Errorf("expected nil, got %v", r.Value)
				}
			},
		},
		{
			name: "console.log captured",
			comp: dadl.CompositeDef{
				Description: "console test",
				Code:        `console.log("hello", "world"); return 42;`,
				Timeout:     "5s",
			},
			tools:    []string{},
			executor: mockExecutor(nil),
			checkFunc: func(t *testing.T, r *Result) {
				if len(r.ConsoleOutput) != 1 {
					t.Fatalf("expected 1 console line, got %d", len(r.ConsoleOutput))
				}
				if !strings.Contains(r.ConsoleOutput[0], "hello") {
					t.Errorf("console output = %q, want to contain 'hello'", r.ConsoleOutput[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := Execute(ctx, &tt.comp, "test_composite", tt.tools, tt.executor, tt.params)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestExecute_SandboxViolations(t *testing.T) {
	tests := []struct {
		name    string
		code    string
		wantErr string
	}{
		{
			name:    "fetch blocked",
			code:    `fetch("http://evil.com")`,
			wantErr: "not defined",
		},
		{
			name:    "require blocked",
			code:    `require("fs")`,
			wantErr: "not defined",
		},
		{
			name:    "eval blocked",
			code:    `eval("1+1")`,
			wantErr: "not allowed",
		},
		{
			name:    "Function constructor blocked",
			code:    `Function("return 1")()`,
			wantErr: "not allowed",
		},
		{
			name:    "process.env blocked",
			code:    `process.env.SECRET`,
			wantErr: "not defined",
		},
		{
			name:    "setTimeout blocked",
			code:    `setTimeout(() => {}, 100)`,
			wantErr: "not defined",
		},
		{
			name:    "globalThis blocked",
			code:    `globalThis.fetch`,
			wantErr: "not defined",
		},
		{
			name:    "XMLHttpRequest blocked",
			code:    `new XMLHttpRequest()`,
			wantErr: "not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comp := dadl.CompositeDef{
				Description: "sandbox test",
				Code:        tt.code,
				Timeout:     "5s",
			}
			ctx := context.Background()
			_, err := Execute(ctx, &comp, "test_sandbox", nil, mockExecutor(nil), nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
