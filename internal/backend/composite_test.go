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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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
	promoted []Promotion
}

func (p *promoterStub) PromotedTools() []Promotion { return p.promoted }

func TestCompositeBackend_PromotedTools_AggregatesNamedAndPassthrough(t *testing.T) {
	named := &promoterStub{
		stubBackend: stubBackend{name: "rest"},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolSearch, Description: testToolSearch},
			Canonical:  "rest_" + testToolSearch,
		}},
	}
	pass := &promoterStub{
		stubBackend: stubBackend{name: "mcp"},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolFetchURL, Description: testToolFetchURL},
			Canonical:  "mcp_" + testToolFetchURL,
		}},
	}

	c := NewCompositeBackend(map[string]ToolBackend{"rest": named})
	c.AddPassthrough(pass)

	got := c.PromotedTools()
	if len(got) != 2 {
		t.Fatalf("got %d promoted tools, want 2", len(got))
	}
	names := map[string]bool{}
	for _, p := range got {
		names[p.Descriptor.Name] = true
	}
	if !names[testToolSearch] || !names[testToolFetchURL] {
		t.Errorf("missing expected bare names: %v", names)
	}
}

// TestCompositeBackend_PromotedTools_ConflictDemotedToCanonical: when two
// backends would advertise the same bare name, both fall back to their
// canonical "<backend>_<tool>" form for advertisement so the public surface
// stays unambiguous.
func TestCompositeBackend_PromotedTools_ConflictDemotedToCanonical(t *testing.T) {
	a := &promoterStub{
		stubBackend: stubBackend{name: testVendorBrave},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolWebSearch, Description: testVendorBrave},
			Canonical:  "brave_" + testToolWebSearch,
		}},
	}
	b := &promoterStub{
		stubBackend: stubBackend{name: testVendorTavily},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolWebSearch, Description: testVendorTavily},
			Canonical:  "tavily_" + testToolWebSearch,
		}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{testVendorBrave: a})
	c.AddPassthrough(b)

	got := c.PromotedTools()
	if len(got) != 2 {
		t.Fatalf("got %d promoted tools, want 2 (both backends keep their entries)", len(got))
	}
	names := map[string]bool{}
	for _, p := range got {
		names[p.Descriptor.Name] = true
	}
	if names[testToolWebSearch] {
		t.Errorf("bare name %q must NOT be advertised when conflicting; got %v", testToolWebSearch, names)
	}
	if !names["brave_"+testToolWebSearch] || !names["tavily_"+testToolWebSearch] {
		t.Errorf("expected canonical fallback names, got %v", names)
	}
}

func TestCompositeBackend_PromotedTools_SkipsNonPromoter(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{"a": &stubBackend{name: "a"}})
	if got := c.PromotedTools(); len(got) != 0 {
		t.Errorf("expected no promoted tools, got %d", len(got))
	}
}

// TestCompositeBackend_ResolveAlias verifies the bare-name → canonical
// dispatch translation that the MCP handler relies on. Unaliased names pass
// through unchanged; conflicting bare names are also unaliased (they were
// demoted to canonical at advertisement time) so a caller using their
// canonical name routes directly without translation.
func TestCompositeBackend_ResolveAlias(t *testing.T) {
	tavily := &promoterStub{
		stubBackend: stubBackend{name: testVendorTavily},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolSearch},
			Canonical:  "tavily_" + testToolSearch,
		}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{testVendorTavily: tavily})

	if got := c.ResolveAlias(testToolSearch); got != "tavily_"+testToolSearch {
		t.Errorf("ResolveAlias(%q) = %q, want canonical", testToolSearch, got)
	}
	// Canonical name should pass through unchanged.
	if got := c.ResolveAlias("tavily_" + testToolSearch); got != "tavily_"+testToolSearch {
		t.Errorf("ResolveAlias(canonical) changed the name: %q", got)
	}
	// Unrelated name should pass through unchanged.
	if got := c.ResolveAlias("other_thing"); got != "other_thing" {
		t.Errorf("ResolveAlias(unknown) = %q, want pass-through", got)
	}
}

// TestCompositeBackend_PromotedTools_ReservedNameDemoted covers the
// OpenAI-compatibility fallback: when a single backend's expose_tools
// entry uses a bare name reserved by an upstream LLM client (web_search,
// code_interpreter, file_search, computer_use), the composite must
// advertise it under the canonical "<backend>_<tool>" form even though
// no cross-backend conflict exists. Without this, ChatGPT's MCP
// connector rejects the entire tools/list with "Invalid MCP tool schema".
//
// ResolveAlias must continue to round-trip the canonical name through
// unchanged so the executor / authz / audit pipeline keep using the
// single canonical key for the tool.
func TestCompositeBackend_PromotedTools_ReservedNameDemoted(t *testing.T) {
	cases := []struct {
		name      string
		bare      string
		canonical string
	}{
		{name: "web_search", bare: "web_search", canonical: "search_web_search"},
		{name: "code_interpreter", bare: "code_interpreter", canonical: "sandbox_code_interpreter"},
		{name: "file_search", bare: "file_search", canonical: "docs_file_search"},
		{name: "computer_use", bare: "computer_use", canonical: "remote_computer_use"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := &promoterStub{
				stubBackend: stubBackend{name: tc.canonical[:strings.Index(tc.canonical, "_")]},
				promoted: []Promotion{{
					Descriptor: ToolDescriptor{Name: tc.bare, Description: tc.bare},
					Canonical:  tc.canonical,
				}},
			}
			c := NewCompositeBackend(map[string]ToolBackend{b.name: b})

			got := c.PromotedTools()
			if len(got) != 1 {
				t.Fatalf("got %d promoted tools, want 1", len(got))
			}
			if got[0].Descriptor.Name != tc.canonical {
				t.Errorf("Descriptor.Name = %q, want demotion to canonical %q",
					got[0].Descriptor.Name, tc.canonical)
			}
			// ResolveAlias of the canonical must be a pass-through; the
			// bare reserved name must not resolve back to anything
			// (we removed it from the public surface).
			if got := c.ResolveAlias(tc.canonical); got != tc.canonical {
				t.Errorf("ResolveAlias(canonical) = %q, want pass-through %q", got, tc.canonical)
			}
			if got := c.ResolveAlias(tc.bare); got != tc.bare {
				t.Errorf("ResolveAlias(reserved bare) = %q, want pass-through %q (no longer advertised)",
					got, tc.bare)
			}
		})
	}
}

// TestCompositeBackend_PromotedTools_NonReservedNameKeptBare guards the
// converse: a non-reserved bare name (e.g. fetch_url) must NOT be demoted
// when only one backend advertises it. Otherwise the OpenAI-compat fix
// over-fires and degrades every expose_tools entry.
func TestCompositeBackend_PromotedTools_NonReservedNameKeptBare(t *testing.T) {
	const bare = "fetch_url"
	const canonical = "web_fetch_url"
	b := &promoterStub{
		stubBackend: stubBackend{name: "web"},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: bare, Description: bare},
			Canonical:  canonical,
		}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{"web": b})

	got := c.PromotedTools()
	if len(got) != 1 || got[0].Descriptor.Name != bare {
		t.Fatalf("non-reserved bare name %q was demoted; got %+v", bare, got)
	}
	if r := c.ResolveAlias(bare); r != canonical {
		t.Errorf("ResolveAlias(%q) = %q, want canonical %q", bare, r, canonical)
	}
}

// TestCompositeBackend_PromotedTools_ReservedNameWarnsOnce verifies the
// WARN log is emitted on the first request that demotes a reserved alias
// and silenced on subsequent requests. The dedup is critical because
// PromotedTools is called on every tools/list — without it a chatty
// client would flood the log.
func TestCompositeBackend_PromotedTools_ReservedNameWarnsOnce(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	b := &promoterStub{
		stubBackend: stubBackend{name: testToolSearch},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolWebSearch, Description: testToolSearch},
			Canonical:  testToolSearch + "_" + testToolWebSearch,
		}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{testToolSearch: b})
	c.SetLogger(logger)

	for i := 0; i < 5; i++ {
		_ = c.PromotedTools()
	}
	output := buf.String()
	count := strings.Count(output, "expose_tools alias collides with a reserved upstream tool name")
	if count != 1 {
		t.Errorf("WARN logged %d times, want exactly 1; output:\n%s", count, output)
	}
	if !strings.Contains(output, "bare_name=web_search") {
		t.Errorf("WARN missing bare_name=web_search; output:\n%s", output)
	}
	if !strings.Contains(output, "canonical_name=search_web_search") {
		t.Errorf("WARN missing canonical_name=search_web_search; output:\n%s", output)
	}
}

// TestCompositeBackend_PromotedTools_ConflictBeatsReserved guards the
// precedence: when two backends both expose the reserved name "web_search",
// the cross-backend conflict path already demotes both to canonical, so
// the reserved-name path never fires and no WARN is emitted (the
// existing conflict log path covers it under a separate concern).
func TestCompositeBackend_PromotedTools_ConflictBeatsReserved(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	a := &promoterStub{
		stubBackend: stubBackend{name: testVendorBrave},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolWebSearch, Description: testVendorBrave},
			Canonical:  "brave_" + testToolWebSearch,
		}},
	}
	b := &promoterStub{
		stubBackend: stubBackend{name: testVendorTavily},
		promoted: []Promotion{{
			Descriptor: ToolDescriptor{Name: testToolWebSearch, Description: testVendorTavily},
			Canonical:  "tavily_" + testToolWebSearch,
		}},
	}
	c := NewCompositeBackend(map[string]ToolBackend{testVendorBrave: a, testVendorTavily: b})
	c.SetLogger(logger)

	got := c.PromotedTools()
	if len(got) != 2 {
		t.Fatalf("got %d promoted tools, want 2", len(got))
	}
	// Both must have been demoted via the conflict path, NOT the
	// reserved-name path; therefore no reserved-name WARN.
	if strings.Contains(buf.String(), "reserved upstream tool name") {
		t.Errorf("reserved-name WARN fired but should be silenced by conflict path; output:\n%s", buf.String())
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
