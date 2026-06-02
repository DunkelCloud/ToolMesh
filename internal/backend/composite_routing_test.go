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
	"fmt"
	"testing"
)

const (
	rtNetdata             = "netdata"
	rtNetdataRaw          = "netdata-raw"
	rtRollTool            = "roll"
	rtNetdataRawQueryTool = "netdata-raw_query_metrics"
)

// routedPassthrough records the toolName each call arrived with so tests
// can assert the composite forwarded with the full prefix intact. It
// implements both ToolBackend and BackendSummarizer, mimicking how the
// real MCPAdapter exposes its sub-backend names.
type routedPassthrough struct {
	subs       []BackendInfo
	lastCall   string
	respondFor map[string]string // toolName -> text response, "" to return "no backend found"
}

func (r *routedPassthrough) Execute(_ context.Context, toolName string, _ map[string]any) (*ToolResult, error) {
	r.lastCall = toolName
	resp, known := r.respondFor[toolName]
	if !known {
		return nil, fmt.Errorf("no backend found for tool %q", toolName)
	}
	return &ToolResult{Content: []any{map[string]any{schemaKeyType: contentTypeText, contentTypeText: resp}}}, nil
}
func (r *routedPassthrough) ListTools(_ context.Context) ([]ToolDescriptor, error) { return nil, nil }
func (r *routedPassthrough) Healthy(_ context.Context) error                       { return nil }
func (r *routedPassthrough) BackendSummaries() []BackendInfo                       { return r.subs }

// TestExecute_LongestPrefixWinsAcrossLayers reproduces the netdata /
// netdata-raw routing bug: a unit named "netdata" and an MCP passthrough
// sub-backend named "netdata-raw" share the "netdata" prefix root.
// Without longest-match across layers, rtNetdataRawQueryTool can
// route to the unit (Go map iteration is randomized). With the fix it
// must always reach the passthrough that owns "netdata-raw".
func TestExecute_LongestPrefixWinsAcrossLayers(t *testing.T) {
	unitNetdata := &stubBackend{name: rtNetdata, tools: []ToolDescriptor{{Name: rtRollTool}}}

	pass := &routedPassthrough{
		subs: []BackendInfo{{Name: rtNetdataRaw}},
		respondFor: map[string]string{
			rtNetdataRawQueryTool: "metrics-payload",
		},
	}

	c := NewCompositeBackend(map[string]ToolBackend{rtNetdata: unitNetdata})
	c.AddPassthrough(pass)

	// Iterate often enough to exercise multiple map orderings. With the
	// pre-fix code, this loop would intermittently route to the unit and
	// fail with "unknown tool raw_query_metrics".
	for i := 0; i < 50; i++ {
		res, err := c.Execute(context.Background(), rtNetdataRawQueryTool, nil)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		block := res.Content[0].(map[string]any)
		if block[contentTypeText] != "metrics-payload" {
			t.Fatalf("iter %d: routed to wrong backend, got %v", i, block)
		}
	}

	// And the unit's own tool must still route to the unit.
	res, err := c.Execute(context.Background(), "netdata_roll", nil)
	if err != nil {
		t.Fatalf("unit call: %v", err)
	}
	block := res.Content[0].(map[string]any)
	if block[contentTypeText] != rtNetdata+":roll" {
		t.Fatalf("unit tool routed wrong: %v", block)
	}
}

// TestExecute_LongestPrefixWinsAmongNamed covers the same rule when both
// candidates are directly-named (no passthrough involved). Without the
// fix, "foo_bar_baz" could land on either "foo" or "foo_bar" depending
// on map order.
func TestExecute_LongestPrefixWinsAmongNamed(t *testing.T) {
	short := &stubBackend{name: "foo", tools: []ToolDescriptor{{Name: "bar_baz"}}}
	long := &stubBackend{name: "foo_bar", tools: []ToolDescriptor{{Name: "baz"}}}
	c := NewCompositeBackend(map[string]ToolBackend{"foo": short, "foo_bar": long})

	for i := 0; i < 50; i++ {
		res, err := c.Execute(context.Background(), "foo_bar_baz", nil)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		block := res.Content[0].(map[string]any)
		// stubBackend echoes "<name>:<toolName>", so longest-match means
		// realTool="baz" against backend "foo_bar".
		if block[contentTypeText] != "foo_bar:baz" {
			t.Fatalf("iter %d: longest prefix lost, got %v", i, block)
		}
	}
}

// TestLookupTool_LongestPrefixWinsAcrossLayers ensures AuthZ/Gate paths
// see the same routing decision as Execute. The unit "netdata" implements
// ToolMetadataLookup but does NOT know "raw_query_metrics"; if LookupTool
// uses the short prefix the lookup falsely returns (zero, false) and the
// gate sees an empty Access classification for a tool that is actually
// owned by the passthrough.
func TestLookupTool_LongestPrefixWinsAcrossLayers(t *testing.T) {
	unitNetdata := &lookupStub{name: rtNetdata, tools: map[string]ToolDescriptor{
		rtRollTool: {Name: rtRollTool, Access: accessRead},
	}}

	pass := &lookupRoutedPassthrough{
		subs: []BackendInfo{{Name: rtNetdataRaw}},
		tools: map[string]ToolDescriptor{
			rtNetdataRawQueryTool: {Name: rtNetdataRawQueryTool, Access: accessRead},
		},
	}

	c := NewCompositeBackend(map[string]ToolBackend{rtNetdata: unitNetdata})
	c.AddPassthrough(pass)

	for i := 0; i < 50; i++ {
		desc, ok := c.LookupTool(rtNetdataRawQueryTool)
		if !ok {
			t.Fatalf("iter %d: tool not found", i)
		}
		if desc.Access != accessRead {
			t.Fatalf("iter %d: wrong access %q", i, desc.Access)
		}
	}
}

// lookupStub is a stubBackend that also implements ToolMetadataLookup,
// returning only tools it explicitly knows.
type lookupStub struct {
	name  string
	tools map[string]ToolDescriptor
}

func (l *lookupStub) Execute(_ context.Context, _ string, _ map[string]any) (*ToolResult, error) {
	return &ToolResult{Content: []any{}}, nil
}
func (l *lookupStub) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	out := make([]ToolDescriptor, 0, len(l.tools))
	for _, d := range l.tools {
		out = append(out, d)
	}
	return out, nil
}
func (l *lookupStub) Healthy(_ context.Context) error { return nil }
func (l *lookupStub) LookupTool(toolName string) (ToolDescriptor, bool) {
	d, ok := l.tools[toolName]
	return d, ok
}

// lookupRoutedPassthrough is a passthrough that implements both
// BackendSummarizer (so the composite sees its sub-backend names) and
// ToolMetadataLookup (so LookupTool can complete the chain).
type lookupRoutedPassthrough struct {
	subs  []BackendInfo
	tools map[string]ToolDescriptor
}

func (p *lookupRoutedPassthrough) Execute(_ context.Context, _ string, _ map[string]any) (*ToolResult, error) {
	return &ToolResult{Content: []any{}}, nil
}
func (p *lookupRoutedPassthrough) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	return nil, nil
}
func (p *lookupRoutedPassthrough) Healthy(_ context.Context) error { return nil }
func (p *lookupRoutedPassthrough) BackendSummaries() []BackendInfo { return p.subs }
func (p *lookupRoutedPassthrough) LookupTool(toolName string) (ToolDescriptor, bool) {
	d, ok := p.tools[toolName]
	return d, ok
}
