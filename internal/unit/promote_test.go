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

package unit_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/unit"
)

// Tool name reused across cases, and its expected promoted (prefixed) form.
// Hoisted to constants to satisfy goconst.
const (
	toolSearch     = "search"
	promotedSearch = "federated_internal_search"
)

// promoteJS declares two tools so tests can assert that only the names listed
// in expose.tools are promoted, not every tool the unit exposes.
const promoteJS = `
function describe() {
	return { tools: [
		{ name: "search", description: "Federated internal search.", access: "read",
		  params: { q: { type: "string", required: true, description: "query" } } },
		{ name: "detail", description: "Fetch one item.", access: "read" }
	] };
}
`

func newPromoteUnit(t *testing.T, exposeTools []string) *unit.Backend {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	b := unit.New("federated_internal", promoteJS, "promote_test.js", nil,
		unit.ExposeConfig{Tools: exposeTools}, logger)
	if err := b.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return b
}

func TestBackend_PromotedTools(t *testing.T) {
	tests := []struct {
		name        string
		exposeTools []string
		// wantNames is both the expected Descriptor.Name and Canonical for each
		// promotion, in order: unit tools promote under the prefixed name, so
		// the two are always identical.
		wantNames []string
	}{
		{name: "none configured", exposeTools: nil, wantNames: nil},
		{name: "single tool", exposeTools: []string{toolSearch},
			wantNames: []string{promotedSearch}},
		{name: "subset of declared tools", exposeTools: []string{"detail"},
			wantNames: []string{"federated_internal_detail"}},
		{name: "order follows expose list", exposeTools: []string{"detail", toolSearch},
			wantNames: []string{"federated_internal_detail", promotedSearch}},
		{name: "unknown name skipped", exposeTools: []string{toolSearch, "bogus"},
			wantNames: []string{promotedSearch}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newPromoteUnit(t, tt.exposeTools)

			// Reach it exactly as the composite backend does — through the
			// interface — so the test also guards that *Backend satisfies it.
			var promoter backend.ToolPromoter = b
			proms := promoter.PromotedTools()

			if len(proms) != len(tt.wantNames) {
				t.Fatalf("got %d promotions, want %d: %+v", len(proms), len(tt.wantNames), proms)
			}
			for i, p := range proms {
				want := tt.wantNames[i]
				if p.Descriptor.Name != want {
					t.Errorf("promotion[%d].Descriptor.Name = %q, want %q", i, p.Descriptor.Name, want)
				}
				if p.Canonical != want {
					t.Errorf("promotion[%d].Canonical = %q, want %q (unit tools promote under the prefixed name)",
						i, p.Canonical, want)
				}
			}
		})
	}
}

// TestBackend_PromotedTools_PreservesDescriptor ensures the promoted tool
// carries the description and input schema through, so the root-level
// advertisement is usable without a discover_tools round-trip — the whole
// point of promotion.
func TestBackend_PromotedTools_PreservesDescriptor(t *testing.T) {
	b := newPromoteUnit(t, []string{toolSearch})

	proms := b.PromotedTools()
	if len(proms) != 1 {
		t.Fatalf("want 1 promotion, got %d", len(proms))
	}
	p := proms[0]
	if p.Descriptor.Description != "Federated internal search." {
		t.Errorf("description not preserved: %q", p.Descriptor.Description)
	}
	if p.Descriptor.InputSchema == nil {
		t.Error("InputSchema is nil; the promoted root tool would advertise no parameters")
	}
}
