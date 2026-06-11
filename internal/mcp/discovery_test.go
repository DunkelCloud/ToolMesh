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

package mcp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Shared fixture literals, hoisted to satisfy goconst.
const (
	markerSummaries = "one-line summaries"
	testParamCity   = "city"
)

// makeDiscoveryTools generates n descriptors spread over five fake backends.
func makeDiscoveryTools(n int) []backend.ToolDescriptor {
	tools := make([]backend.ToolDescriptor, n)
	for i := range tools {
		tools[i] = backend.ToolDescriptor{
			Name:        fmt.Sprintf("fake%d_tool_%03d", i%5, i),
			Description: fmt.Sprintf("Does generated thing number %d. With a second sentence.", i),
			Backend:     fmt.Sprintf("rest:fake%d", i%5),
		}
	}
	return tools
}

func discoveryCtx() context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})
}

func discoverText(t *testing.T, h *Handler, params map[string]any) string {
	t.Helper()
	result, err := h.HandleToolCall(discoveryCtx(), toolDiscoverTools, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	return extractText(t, result)
}

func TestDiscoverTools_AutoTiering(t *testing.T) {
	tests := []struct {
		name        string
		toolCount   int
		wantMarker  string // substring identifying the chosen tier
		rejectedTag string // substring that must NOT appear
		wantDetail  string // detail mode reported in the footer
	}{
		{
			name:        "few tools get full declarations",
			toolCount:   10,
			wantMarker:  "declare namespace toolmesh",
			rejectedTag: markerSummaries,
			wantDetail:  "detail: full (auto)",
		},
		{
			name:        "medium count degrades to summaries",
			toolCount:   discoverFullMax + 5,
			wantMarker:  markerSummaries,
			rejectedTag: "declare namespace toolmesh",
			wantDetail:  "detail: summary (auto)",
		},
		{
			name:        "large count degrades to names",
			toolCount:   discoverSummaryMax + 5,
			wantMarker:  "names only",
			rejectedTag: markerSummaries,
			wantDetail:  "detail: names (auto)",
		},
		{
			name:        "huge count degrades to backend overview",
			toolCount:   discoverNamesMax + 5,
			wantMarker:  "per-backend overview",
			rejectedTag: "names only",
			wantDetail:  "detail: overview (auto)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newHandlerWithTools(t, makeDiscoveryTools(tt.toolCount))
			text := discoverText(t, h, map[string]any{})

			if !strings.Contains(text, tt.wantMarker) {
				t.Errorf("expected marker %q in output", tt.wantMarker)
			}
			if strings.Contains(text, tt.rejectedTag) {
				t.Errorf("did not expect %q in output", tt.rejectedTag)
			}
			if !strings.Contains(text, tt.wantDetail) {
				t.Errorf("expected footer to report %q", tt.wantDetail)
			}
			wantCount := fmt.Sprintf("%d of %d tools matched", tt.toolCount, tt.toolCount)
			if !strings.Contains(text, wantCount) {
				t.Errorf("expected footer to contain %q", wantCount)
			}
		})
	}
}

func TestDiscoverTools_DetailOverride(t *testing.T) {
	h := newHandlerWithTools(t, makeDiscoveryTools(discoverFullMax+5))

	t.Run("explicit full overrides auto summary", func(t *testing.T) {
		text := discoverText(t, h, map[string]any{argNameDetail: detailFull})
		if !strings.Contains(text, "declare namespace toolmesh") {
			t.Error("expected full declarations")
		}
		if !strings.Contains(text, "detail: full.") {
			t.Error("expected footer to report explicit full detail without (auto) tag")
		}
	})

	t.Run("explicit overview on small set", func(t *testing.T) {
		text := discoverText(t, h, map[string]any{argNameDetail: detailOverview})
		if !strings.Contains(text, "per-backend overview") {
			t.Error("expected overview output")
		}
		if !strings.Contains(text, "rest:fake0 — 6 tools") {
			t.Errorf("expected per-backend count line, got: %s", text)
		}
	})

	t.Run("invalid detail is a tool error", func(t *testing.T) {
		result, err := h.HandleToolCall(discoveryCtx(), toolDiscoverTools, map[string]any{argNameDetail: "everything"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.IsError {
			t.Fatal("expected IsError for invalid detail value")
		}
	})
}

func TestDiscoverTools_Limit(t *testing.T) {
	h := newHandlerWithTools(t, makeDiscoveryTools(40))

	text := discoverText(t, h, map[string]any{argNameLimit: float64(5)})
	if !strings.Contains(text, "40 of 40 tools matched, showing first 5") {
		t.Errorf("expected limit footer, got: %s", text)
	}
	// 5 shown tools fall under the full threshold.
	if !strings.Contains(text, "declare namespace toolmesh") {
		t.Error("expected full declarations for limited result set")
	}
	if got := strings.Count(text, "function fake"); got != 5 {
		t.Errorf("expected 5 function declarations, got %d", got)
	}
}

func TestDiscoverTools_Query(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{Name: "cloudflare_create_dns_record", Description: "Create a DNS record in a zone", Backend: "rest:cloudflare"},
		{Name: "hetzner_list_dns_zones", Description: "List DNS zones", Backend: "rest:hetzner"},
		{Name: "netbox_list_devices", Description: "List all devices", Backend: "rest:netbox"},
		{Name: "github_create_issue", Description: "Create an issue", Backend: "rest:github"},
	}
	h := newHandlerWithTools(t, tools)

	t.Run("query ranks and filters", func(t *testing.T) {
		text := discoverText(t, h, map[string]any{argNameQuery: "dns"})
		if !strings.Contains(text, "cloudflare_create_dns_record") || !strings.Contains(text, "hetzner_list_dns_zones") {
			t.Errorf("expected both DNS tools in output, got: %s", text)
		}
		if strings.Contains(text, "netbox_list_devices") {
			t.Error("netbox_list_devices must not match query \"dns\"")
		}
		if !strings.Contains(text, "2 of 4 tools matched") {
			t.Errorf("expected query match count in footer, got: %s", text)
		}
	})

	t.Run("pattern prefilters query", func(t *testing.T) {
		text := discoverText(t, h, map[string]any{argNamePattern: "^cloudflare", argNameQuery: "dns"})
		if !strings.Contains(text, "cloudflare_create_dns_record") {
			t.Error("expected cloudflare DNS tool")
		}
		if strings.Contains(text, "hetzner_list_dns_zones") {
			t.Error("pattern should have excluded hetzner before ranking")
		}
	})

	t.Run("query without matches reports zero", func(t *testing.T) {
		text := discoverText(t, h, map[string]any{argNameQuery: "kubernetes"})
		if !strings.Contains(text, "0 of 4 tools matched") {
			t.Errorf("expected zero-match footer, got: %s", text)
		}
	})

	t.Run("query result is cut to top limit", func(t *testing.T) {
		manyTools := makeDiscoveryTools(60)
		for i := range manyTools {
			manyTools[i].Description = "Manages widgets. " + manyTools[i].Description
		}
		hMany := newHandlerWithTools(t, manyTools)
		text := discoverText(t, hMany, map[string]any{argNameQuery: "widgets"})
		if !strings.Contains(text, fmt.Sprintf("showing top %d", discoverQueryLimit)) {
			t.Errorf("expected default query limit footer, got: %s", text)
		}
	})
}

func TestDiscoverTools_OutputCap(t *testing.T) {
	bigDesc := strings.Repeat("Verbose documentation sentence. ", 40) // ~1.3 KB each
	tools := make([]backend.ToolDescriptor, 100)
	for i := range tools {
		tools[i] = backend.ToolDescriptor{
			Name:        fmt.Sprintf("fake_big_tool_%03d", i),
			Description: bigDesc,
			Backend:     "rest:fake",
		}
	}
	h := newHandlerWithTools(t, tools)

	// Force the expensive tier explicitly: 100 full declarations ≈ 130 KB.
	text := discoverText(t, h, map[string]any{argNameDetail: detailFull})

	if len(text) > discoverMaxBytes+1000 {
		t.Errorf("output exceeds cap: %d bytes", len(text))
	}
	if !strings.Contains(text, "[TRUNCATED") {
		t.Error("expected truncation marker")
	}
	if !strings.Contains(text, "100 of 100 tools matched") {
		t.Error("expected footer to survive truncation")
	}
}

func TestCodeRunner_SandboxDiscover(t *testing.T) {
	mb := &codeRunnerTestBackend{}
	runner := newTestCodeRunner(t, mb)

	t.Run("discover returns ranked matches", func(t *testing.T) {
		result, err := runner.Execute(testCtx(), `return toolmesh.discover("test tool");`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(t, result)
		if !strings.Contains(text, "test_foo") || !strings.Contains(text, "test_bar") {
			t.Errorf("expected both test tools in discover output, got: %s", text)
		}
		if len(mb.calls) != 0 {
			t.Errorf("discover must not hit the backend, got %d calls", len(mb.calls))
		}
	})

	t.Run("discover respects limit argument", func(t *testing.T) {
		result, err := runner.Execute(testCtx(), `return toolmesh.discover("test tool", 1).length;`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if text := extractText(t, result); !strings.Contains(text, "1") {
			t.Errorf("expected single result, got: %s", text)
		}
	})

	t.Run("empty query throws", func(t *testing.T) {
		_, err := runner.Execute(testCtx(), `return toolmesh.discover("");`)
		if err == nil || !strings.Contains(err.Error(), "non-empty free-text query") {
			t.Errorf("expected non-empty query error, got: %v", err)
		}
	})

	t.Run("discover does not count toward call budget", func(t *testing.T) {
		mb2 := &codeRunnerTestBackend{}
		runner2 := newTestCodeRunner(t, mb2)
		code := fmt.Sprintf(`
			for (let i = 0; i < %d; i++) { toolmesh.discover("test"); }
			return await toolmesh.test_foo({});
		`, maxCodeCalls+10)
		result, err := runner2.Execute(testCtx(), code)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.IsError {
			t.Fatalf("unexpected IsError: %v", result.Content)
		}
		if len(mb2.calls) != 1 {
			t.Errorf("expected exactly 1 backend call, got %d", len(mb2.calls))
		}
	})
}

func TestCodeRunner_SandboxDescribe(t *testing.T) {
	logger := handlerTestLogger()
	mb := &codeRunnerTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	tools := []backend.ToolDescriptor{{
		Name:        "test:weather",
		Description: "Get the weather for a city. Supports forecasts.",
		Backend:     "rest:test",
		Access:      "read",
		InputSchema: map[string]any{
			contentKeyType: jsonTypeObject,
			schemaKeyProperties: map[string]any{
				testParamCity: map[string]any{contentKeyType: jsonTypeString},
			},
			schemaKeyRequired: []any{testParamCity},
		},
	}}
	runner := NewCodeRunner(map[string]string{"test_weather": "test:weather"}, tools, exec, nil, logger)

	t.Run("describe returns schema and metadata", func(t *testing.T) {
		result, err := runner.Execute(testCtx(), `return toolmesh.describe("test_weather");`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		text := extractText(t, result)
		for _, want := range []string{testParamCity, "rest:test", "read", "Get the weather"} {
			if !strings.Contains(text, want) {
				t.Errorf("expected %q in describe output, got: %s", want, text)
			}
		}
	})

	t.Run("describe accepts canonical name", func(t *testing.T) {
		result, err := runner.Execute(testCtx(), `return toolmesh.describe("test:weather").name;`)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if text := extractText(t, result); !strings.Contains(text, "test_weather") {
			t.Errorf("expected sanitized name, got: %s", text)
		}
	})

	t.Run("unknown tool throws with discover hint", func(t *testing.T) {
		_, err := runner.Execute(testCtx(), `return toolmesh.describe("nope_missing");`)
		if err == nil || !strings.Contains(err.Error(), "unknown tool") {
			t.Errorf("expected unknown tool error, got: %v", err)
		}
	})
}
