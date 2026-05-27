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
	"testing"
)

// Test-local names. Pulled into constants so the repeated-string linter
// (goconst) stays quiet across the package's test files.
const (
	bnAlpha  = "alpha"
	bnBeta   = "beta"
	bnGamma  = "gamma"
	bnMCPA   = "mcp-alpha"
	bnMCPB   = "mcp-beta"
	bnShared = "shared"
	bnUnique = "unique"
)

// summarizerPassthrough advertises sub-backends via BackendSummarizer.
// Used to verify that CompositeBackend.BackendNames() surfaces passthrough
// sub-backends (so the unit loader's collision detection can see MCP-adapter
// sub-backends, not just direct named entries).
type summarizerPassthrough struct {
	subs []BackendInfo
}

func (summarizerPassthrough) Execute(_ context.Context, _ string, _ map[string]any) (*ToolResult, error) {
	return &ToolResult{Content: []any{}}, nil
}
func (summarizerPassthrough) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	return nil, nil
}
func (summarizerPassthrough) Healthy(_ context.Context) error   { return nil }
func (s summarizerPassthrough) BackendSummaries() []BackendInfo { return s.subs }

func TestBackendNames_EmptyComposite(t *testing.T) {
	c := NewCompositeBackend(nil)
	if names := c.BackendNames(); len(names) != 0 {
		t.Fatalf("expected empty names, got %v", names)
	}
}

func TestBackendNames_IncludesNamedEntries(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{
		bnAlpha: &stubBackend{name: bnAlpha},
		bnBeta:  &stubBackend{name: bnBeta},
	})
	c.AddNamed(bnGamma, &stubBackend{name: bnGamma})

	got := asSet(c.BackendNames())
	for _, want := range []string{bnAlpha, bnBeta, bnGamma} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 names, got %d: %v", len(got), got)
	}
}

func TestBackendNames_IncludesPassthroughSubBackends(t *testing.T) {
	c := NewCompositeBackend(map[string]ToolBackend{
		echoToolName: &stubBackend{name: echoToolName},
	})
	c.AddPassthrough(summarizerPassthrough{subs: []BackendInfo{
		{Name: bnMCPA},
		{Name: bnMCPB},
	}})

	got := asSet(c.BackendNames())
	for _, want := range []string{echoToolName, bnMCPA, bnMCPB} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in %v", want, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 names, got %d: %v", len(got), got)
	}
}

func TestBackendNames_DedupesNameAcrossLayers(t *testing.T) {
	// A passthrough sub-backend with the same name as a directly-named
	// entry should appear once. Real configurations should never have
	// this overlap, but the public surface must remain well-defined.
	c := NewCompositeBackend(map[string]ToolBackend{
		bnShared: &stubBackend{name: bnShared},
	})
	c.AddPassthrough(summarizerPassthrough{subs: []BackendInfo{
		{Name: bnShared},
		{Name: bnUnique},
	}})

	got := asSet(c.BackendNames())
	if len(got) != 2 {
		t.Fatalf("expected 2 unique names, got %d: %v", len(got), got)
	}
	if _, ok := got[bnShared]; !ok {
		t.Fatalf("expected 'shared' in %v", got)
	}
	if _, ok := got[bnUnique]; !ok {
		t.Fatalf("expected 'unique' in %v", got)
	}
}

func asSet(names []string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, n := range names {
		out[n] = struct{}{}
	}
	return out
}
