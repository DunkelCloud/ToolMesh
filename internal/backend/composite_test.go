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

package backend

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// stubBackend is a minimal ToolBackend used to test CompositeBackend routing.
type stubBackend struct {
	name    string
	tools   []ToolDescriptor
	healthy error
}

func (s *stubBackend) Execute(_ context.Context, toolName string, _ map[string]any) (*ToolResult, error) {
	return &ToolResult{Content: []any{map[string]any{"type": "text", "text": s.name + ":" + toolName}}}, nil
}

func (s *stubBackend) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	return s.tools, nil
}

func (s *stubBackend) Healthy(_ context.Context) error { return s.healthy }

// notFoundPassthrough returns the "no backend found" error for every call.
type notFoundPassthrough struct{}

func (notFoundPassthrough) Execute(_ context.Context, toolName string, _ map[string]any) (*ToolResult, error) {
	return nil, fmt.Errorf("no backend found for tool %q", toolName)
}
func (notFoundPassthrough) ListTools(_ context.Context) ([]ToolDescriptor, error) { return nil, nil }
func (notFoundPassthrough) Healthy(_ context.Context) error                       { return errors.New("down") }

func TestCompositeBackend_ExecuteByNamedPrefix(t *testing.T) {
	a := &stubBackend{name: "a", tools: []ToolDescriptor{{Name: "hello"}}}
	b := &stubBackend{name: "b", tools: []ToolDescriptor{{Name: "world"}}}
	c := NewCompositeBackend(map[string]ToolBackend{"a": a, "b": b})

	r, err := c.Execute(context.Background(), "a_hello", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := r.Content[0].(map[string]any)
	if item["text"] != "a:hello" {
		t.Errorf("routed to wrong backend: %v", item)
	}

	if _, err := c.Execute(context.Background(), "nope_tool", nil); err == nil {
		t.Error("expected error for unknown backend")
	}
}

func TestCompositeBackend_AddPassthrough(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{})
	c.AddPassthrough(&stubBackend{name: "p", tools: []ToolDescriptor{{Name: "x_tool"}}})

	r, err := c.Execute(context.Background(), "x_tool", nil)
	if err != nil {
		t.Fatalf("passthrough execute: %v", err)
	}
	if r == nil {
		t.Fatal("nil result")
	}
}

func TestCompositeBackend_PassthroughSurfacesRealErrors(t *testing.T) {
	// A passthrough that returns a real, non-"no backend found" error must
	// propagate that error instead of falling through.
	fail := stubExecErr{err: errors.New("boom: real failure")}
	c := NewCompositeBackend(map[string]ToolBackend{})
	c.AddPassthrough(fail)

	if _, err := c.Execute(context.Background(), "x", nil); err == nil {
		t.Error("expected error")
	} else if err.Error() != "boom: real failure" {
		t.Errorf("got error %q", err)
	}

	// A passthrough returning "no backend found" must be skipped, not
	// surfaced directly — final error is the composite's own message.
	c2 := NewCompositeBackend(map[string]ToolBackend{})
	c2.AddPassthrough(notFoundPassthrough{})
	if _, err := c2.Execute(context.Background(), "x", nil); err == nil {
		t.Error("expected error")
	}
}

type stubExecErr struct{ err error }

func (s stubExecErr) Execute(_ context.Context, _ string, _ map[string]any) (*ToolResult, error) {
	return nil, s.err
}
func (s stubExecErr) ListTools(_ context.Context) ([]ToolDescriptor, error) { return nil, nil }
func (s stubExecErr) Healthy(_ context.Context) error                       { return nil }

func TestCompositeBackend_ListTools(t *testing.T) {
	a := &stubBackend{name: "a", tools: []ToolDescriptor{{Name: "one"}, {Name: "two"}}}
	p := &stubBackend{name: "p", tools: []ToolDescriptor{{Name: "p_three"}}}

	c := NewCompositeBackend(map[string]ToolBackend{"a": a})
	c.AddPassthrough(p)

	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 3 {
		t.Errorf("got %d tools, want 3", len(tools))
	}
	// Named backend tools are prefixed with "a_".
	found := map[string]bool{}
	for _, t := range tools {
		found[t.Name] = true
	}
	if !found["a_one"] || !found["a_two"] || !found["p_three"] {
		t.Errorf("missing expected tool names: %v", found)
	}
}

func TestCompositeBackend_AddNamed(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{})
	c.AddNamed("new", &stubBackend{name: "new", tools: []ToolDescriptor{{Name: "t"}}})

	r, err := c.Execute(context.Background(), "new_t", nil)
	if err != nil || r == nil {
		t.Fatalf("AddNamed: err=%v r=%v", err, r)
	}
}

func TestCompositeBackend_Healthy(t *testing.T) {
	healthy := &stubBackend{name: "h", healthy: nil}
	bad := &stubBackend{name: "b", healthy: errors.New("down")}

	c := NewCompositeBackend(map[string]ToolBackend{"bad": bad})
	if err := c.Healthy(context.Background()); err == nil {
		t.Error("expected unhealthy")
	}

	c.AddNamed("healthy", healthy)
	if err := c.Healthy(context.Background()); err != nil {
		t.Errorf("expected healthy, got %v", err)
	}

	// All-passthrough case.
	cp := NewCompositeBackend(map[string]ToolBackend{})
	cp.AddPassthrough(healthy)
	if err := cp.Healthy(context.Background()); err != nil {
		t.Errorf("passthrough healthy, got %v", err)
	}
}

func TestCompositeBackend_BackendSummaries(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{"a": &stubBackend{}})
	// Stub doesn't implement BackendSummarizer, so summaries should be empty.
	if summaries := c.BackendSummaries(); len(summaries) != 0 {
		t.Errorf("expected no summaries, got %d", len(summaries))
	}
}

// TestCompositeBackend_ConcurrentAccess exercises AddNamed / Execute /
// ListTools in parallel. The point is to detect data races under -race,
// not to assert on outputs.
func TestCompositeBackend_ConcurrentAccess(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{})
	var wg sync.WaitGroup
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		wg.Add(3)
		idx := i
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("b%d", idx)
			c.AddNamed(name, &stubBackend{name: name, tools: []ToolDescriptor{{Name: "t"}}})
		}()
		go func() {
			defer wg.Done()
			_, _ = c.ListTools(ctx)
		}()
		go func() {
			defer wg.Done()
			_, _ = c.Execute(ctx, fmt.Sprintf("b%d_t", idx), nil)
		}()
	}
	wg.Wait()
}

func TestCompositeBackend_Swap(t *testing.T) {
	a := &stubBackend{name: "a", tools: []ToolDescriptor{{Name: "one"}}}
	c := NewCompositeBackend(map[string]ToolBackend{"a": a})

	// Before swap: a_one should work.
	ctx := context.Background()
	if _, err := c.Execute(ctx, "a_one", nil); err != nil {
		t.Fatalf("before swap: %v", err)
	}

	// Swap to a completely new set of backends.
	b := &stubBackend{name: "b", tools: []ToolDescriptor{{Name: "two"}}}
	c.Swap(map[string]ToolBackend{"b": b}, nil)

	// After swap: a_one should fail, b_two should work.
	if _, err := c.Execute(ctx, "a_one", nil); err == nil {
		t.Error("expected error for old backend after swap")
	}
	r, err := c.Execute(ctx, "b_two", nil)
	if err != nil {
		t.Fatalf("after swap: %v", err)
	}
	item := r.Content[0].(map[string]any)
	if item["text"] != "b:two" {
		t.Errorf("got %v, want b:two", item["text"])
	}

	// ListTools should reflect new state.
	tools, _ := c.ListTools(ctx)
	if len(tools) != 1 || tools[0].Name != "b_two" {
		t.Errorf("tools after swap = %v, want [b_two]", tools)
	}
}

// TestCompositeBackend_ConcurrentSwap exercises Swap while concurrent readers
// call Execute and ListTools. The purpose is to verify no data races occur
// (run with -race) and that readers always see a consistent state snapshot.
func TestCompositeBackend_ConcurrentSwap(t *testing.T) {
	backends := make([]map[string]ToolBackend, 10)
	for i := range backends {
		name := fmt.Sprintf("b%d", i)
		backends[i] = map[string]ToolBackend{
			name: &stubBackend{name: name, tools: []ToolDescriptor{{Name: "t"}}},
		}
	}

	c := NewCompositeBackend(backends[0])
	ctx := context.Background()

	var wg sync.WaitGroup
	var swapCount atomic.Int64

	// Writer: continuously swaps to new backend sets.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i < len(backends); i++ {
			c.Swap(backends[i], nil)
			swapCount.Add(1)
		}
	}()

	// Readers: call Execute and ListTools concurrently with swaps.
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				tools, _ := c.ListTools(ctx)
				// Each snapshot must have exactly 1 backend with 1 tool.
				if len(tools) != 1 {
					t.Errorf("ListTools returned %d tools, want 1 (inconsistent snapshot)", len(tools))
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				// Try all possible tool names — one should succeed per snapshot.
				for k := range backends {
					name := fmt.Sprintf("b%d_t", k)
					_, _ = c.Execute(ctx, name, nil)
				}
			}
		}()
	}

	wg.Wait()

	if swapCount.Load() != int64(len(backends)-1) {
		t.Errorf("expected %d swaps, got %d", len(backends)-1, swapCount.Load())
	}
}
