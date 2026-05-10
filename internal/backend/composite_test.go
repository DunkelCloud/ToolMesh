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
	return &ToolResult{Content: []any{map[string]any{schemaKeyType: contentTypeText, contentTypeText: s.name + ":" + toolName}}}, nil
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
	a := &stubBackend{name: "a", tools: []ToolDescriptor{{Name: testHelloLiteral}}}
	b := &stubBackend{name: "b", tools: []ToolDescriptor{{Name: "world"}}}
	c := NewCompositeBackend(map[string]ToolBackend{"a": a, "b": b})

	r, err := c.Execute(context.Background(), "a_hello", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := r.Content[0].(map[string]any)
	if item[contentTypeText] != "a:hello" {
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

// promoterStub is a stubBackend that also implements ToolPromoter.
type promoterStub struct {
	stubBackend
	promoted []ToolDescriptor
}

func (p *promoterStub) PromotedTools() []ToolDescriptor { return p.promoted }

func TestCompositeBackend_PromotedTools_AggregatesNamedAndPassthrough(t *testing.T) {
	named := &promoterStub{
		stubBackend: stubBackend{name: "rest"},
		promoted:    []ToolDescriptor{{Name: "rest_" + testToolSearch, Description: testToolSearch}},
	}
	pass := &promoterStub{
		stubBackend: stubBackend{name: "mcp"},
		promoted:    []ToolDescriptor{{Name: "mcp_" + testToolFetchURL, Description: testToolFetchURL}},
	}

	c := NewCompositeBackend(map[string]ToolBackend{"rest": named})
	c.AddPassthrough(pass)

	got := c.PromotedTools()
	if len(got) != 2 {
		t.Fatalf("got %d promoted tools, want 2", len(got))
	}
	names := map[string]bool{}
	for _, d := range got {
		names[d.Name] = true
	}
	if !names["rest_"+testToolSearch] || !names["mcp_"+testToolFetchURL] {
		t.Errorf("missing expected names: %v", names)
	}
}

func TestCompositeBackend_PromotedTools_DeduplicatesByName(t *testing.T) {
	a := &promoterStub{
		stubBackend: stubBackend{name: "a"},
		promoted:    []ToolDescriptor{{Name: "shared_x", Description: "first"}},
	}
	b := &promoterStub{
		stubBackend: stubBackend{name: "b"},
		promoted:    []ToolDescriptor{{Name: "shared_x", Description: "second"}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{"a": a})
	c.AddPassthrough(b)

	got := c.PromotedTools()
	if len(got) != 1 {
		t.Fatalf("got %d promoted tools, want 1 (deduped)", len(got))
	}
}

func TestCompositeBackend_PromotedTools_SkipsNonPromoter(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{"a": &stubBackend{name: "a"}})
	if got := c.PromotedTools(); len(got) != 0 {
		t.Errorf("expected no promoted tools, got %d", len(got))
	}
}

// TestCompositeBackend_Execute_CollapseFallback verifies the routing
// convention used when a backend is named after its own primary tool: a bare
// call equal to the backend name dispatches to that backend's same-named
// tool. This is what makes the expose_tools collapse testToolWebSearch (instead
// of "web_search_web_search") actually invokable end-to-end.
func TestCompositeBackend_Execute_CollapseFallback(t *testing.T) {
	b := &stubBackend{name: testToolWebSearch, tools: []ToolDescriptor{{Name: testToolWebSearch}}}
	c := NewCompositeBackend(map[string]ToolBackend{testToolWebSearch: b})

	r, err := c.Execute(context.Background(), testToolWebSearch, nil)
	if err != nil {
		t.Fatalf("collapse execute: %v", err)
	}
	item := r.Content[0].(map[string]any)
	if item[contentTypeText] != "web_search:web_search" {
		t.Errorf("collapse routed elsewhere: %v", item)
	}
}

// TestCompositeBackend_Execute_PrefixWinsOverCollapse verifies that an
// unambiguous "<backend>_<tool>" prefix dispatch still beats a coexisting
// bare-name collapse target on a different backend. Avoids overlapping
// prefixes (e.g. backends "web" and testToolWebSearch) because the composite's
// existing first-match semantics over a map iteration are not deterministic
// for overlapping prefixes — that orthogonal limitation is documented as
// "longest prefix wins" but is not implemented and out of scope here.
func TestCompositeBackend_Execute_PrefixWinsOverCollapse(t *testing.T) {
	collapse := &stubBackend{name: testToolFetchURL, tools: []ToolDescriptor{{Name: testToolFetchURL}}}
	prefixed := &stubBackend{name: "github", tools: []ToolDescriptor{{Name: "create_issue"}}}
	c := NewCompositeBackend(map[string]ToolBackend{
		testToolFetchURL: collapse,
		"github":         prefixed,
	})

	// Prefix match: "github_create_issue" → backend "github", tool "create_issue".
	r, err := c.Execute(context.Background(), "github_create_issue", nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	item := r.Content[0].(map[string]any)
	if item[contentTypeText] != "github:create_issue" {
		t.Errorf("expected prefix dispatch, got %v", item)
	}

	// Collapse match: testToolFetchURL → backend testToolFetchURL, tool testToolFetchURL.
	r, err = c.Execute(context.Background(), testToolFetchURL, nil)
	if err != nil {
		t.Fatalf("execute (collapse): %v", err)
	}
	item = r.Content[0].(map[string]any)
	if item[contentTypeText] != testToolFetchURL+":"+testToolFetchURL {
		t.Errorf("expected collapse dispatch, got %v", item)
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
	if item[contentTypeText] != "b:two" {
		t.Errorf("got %v, want b:two", item[contentTypeText])
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
