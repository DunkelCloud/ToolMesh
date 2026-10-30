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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
)

// Fixture names of the execute_code metrics test. The second backend's name
// contains an underscore, so a label taken from the tool name up to its
// first underscore would read "web" instead.
const (
	cmShop      = "shop"
	cmWebSearch = "web_search"
	cmShopGet   = "shop_get"
	cmQuery     = "web_search_query"

	cmScriptsMetric   = "toolmesh_codemode_scripts_total"
	cmSwallowedMetric = "toolmesh_codemode_swallowed_errors_total"
)

// metricsTestBackend routes tools to the backends "shop" and "web_search".
// shop_get fails in the pipeline and web_search_query reports an error result
// when the test asks for it.
type metricsTestBackend struct {
	failDispatch  bool
	failToolError bool
}

func (b *metricsTestBackend) Execute(_ context.Context, toolName string, _ map[string]any) (*backend.ToolResult, error) {
	if toolName == cmShopGet && b.failDispatch {
		return nil, errors.New("upstream unreachable")
	}
	if toolName == cmQuery && b.failToolError {
		return &backend.ToolResult{
			IsError: true,
			Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: `{"error":"quota exceeded"}`}},
		}, nil
	}
	return &backend.ToolResult{
		Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: `{"ok":true}`}},
	}, nil
}

func (b *metricsTestBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return []backend.ToolDescriptor{
		{Name: cmShopGet, Description: "Get an item", Backend: "rest:" + cmShop},
		{Name: cmQuery, Description: "Search the web", Backend: "rest:" + cmWebSearch},
	}, nil
}

func (b *metricsTestBackend) Healthy(_ context.Context) error { return nil }

func (b *metricsTestBackend) ResolveBackendName(toolName string) (string, bool) {
	for _, name := range []string{cmWebSearch, cmShop} {
		if strings.HasPrefix(toolName, name+"_") {
			return name, true
		}
	}
	return "", false
}

// newMetricsTestHandler builds a handler with a fresh metrics registry over
// the test backend; shop_get requires a string id, so calling it without one
// fails the coercion.
func newMetricsTestHandler(mb *metricsTestBackend) (*Handler, *metrics.Registry) {
	logger := newQuietMCPLogger()
	coercer := tsdef.NewCoercer([]tsdef.ToolDef{{
		Name:   cmShopGet,
		Params: []tsdef.ParamDef{{Name: "id", Required: true, Type: tsdef.ParamType{Kind: jsonTypeString}}},
	}}, logger)
	exec := executor.New(nil, nil, mb, nil, nil, 5*time.Second, logger, nil, nil)
	m := metrics.New(metrics.Options{LabelTool: true})
	return NewHandler(exec, mb, coercer, "", m, logger, false), m
}

// counterValue reads one series of a counter vector, or -1 when the series
// does not exist.
func counterValue(t *testing.T, m *metrics.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := m.PrometheusRegistry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
	series:
		for _, s := range f.GetMetric() {
			if len(s.GetLabel()) != len(labels) {
				continue
			}
			for _, l := range s.GetLabel() {
				if labels[l.GetName()] != l.GetValue() {
					continue series
				}
			}
			return s.GetCounter().GetValue()
		}
	}
	return -1
}

func TestExecuteCode_Metrics(t *testing.T) {
	type swallowed struct{ backend, reason string }

	cases := []struct {
		name          string
		backend       metricsTestBackend
		timeout       time.Duration
		code          string
		wantOutcome   string
		wantSwallowed []swallowed
	}{
		{
			name:        "dispatch error",
			backend:     metricsTestBackend{failDispatch: true},
			code:        `const r = await toolmesh.shop_get({id: "1"}); return {item: r.item};`,
			wantOutcome: metrics.ScriptOutcomeOK,
			wantSwallowed: []swallowed{
				{cmShop, metrics.SwallowedDispatch},
			},
		},
		{
			name:        "coercion error",
			code:        `const r = await toolmesh.shop_get({}); return {item: r === undefined};`,
			wantOutcome: metrics.ScriptOutcomeOK,
			wantSwallowed: []swallowed{
				{cmShop, metrics.SwallowedCoercion},
			},
		},
		{
			name:        "tool error result",
			backend:     metricsTestBackend{failToolError: true},
			code:        `const r = await toolmesh.web_search_query({q: "x"}); return {hits: r.hits};`,
			wantOutcome: metrics.ScriptOutcomeOK,
			wantSwallowed: []swallowed{
				{cmWebSearch, metrics.SwallowedToolError},
			},
		},
		{
			name:        "built-in tool error",
			code:        `const r = await toolmesh.request_grant({kit: "ops"}); return {r: r};`,
			wantOutcome: metrics.ScriptOutcomeOK,
			wantSwallowed: []swallowed{
				{metricsBackendBuiltin, metrics.SwallowedToolError},
			},
		},
		{
			name:    "counted once per script, backend and reason",
			backend: metricsTestBackend{failDispatch: true, failToolError: true},
			code: `
				for (let i = 0; i < 3; i++) { await toolmesh.shop_get({id: String(i)}); }
				await toolmesh.shop_get({});
				await toolmesh.web_search_query({q: "x"});
				return "done";`,
			wantOutcome: metrics.ScriptOutcomeOK,
			wantSwallowed: []swallowed{
				{cmShop, metrics.SwallowedDispatch},
				{cmShop, metrics.SwallowedCoercion},
				{cmWebSearch, metrics.SwallowedToolError},
			},
		},
		{
			name:        "no failure",
			code:        `const r = await toolmesh.shop_get({id: "1"}); return r;`,
			wantOutcome: metrics.ScriptOutcomeOK,
		},
		{
			name:        "script throws after a failed call",
			backend:     metricsTestBackend{failDispatch: true},
			code:        `const r = await toolmesh.shop_get({id: "1"}); if (r.error) { throw new Error("stop"); }`,
			wantOutcome: metrics.ScriptOutcomeError,
		},
		{
			name:        "script rejected by the static analysis",
			code:        `eval("1"); await toolmesh.shop_get({id: "1"});`,
			wantOutcome: metrics.ScriptOutcomeError,
		},
		{
			name:        "script runs out of time after a failed call",
			backend:     metricsTestBackend{failDispatch: true},
			timeout:     50 * time.Millisecond,
			code:        `await toolmesh.shop_get({id: "1"}); while (true) {}`,
			wantOutcome: metrics.ScriptOutcomeTimeout,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mb := tc.backend
			h, m := newMetricsTestHandler(&mb)
			h.SetCodeTimeout(tc.timeout)

			if _, err := h.HandleToolCall(testCtx(), toolExecuteCode, map[string]any{argNameCode: tc.code}); err != nil {
				t.Fatalf("HandleToolCall: %v", err)
			}

			for _, outcome := range []string{metrics.ScriptOutcomeOK, metrics.ScriptOutcomeError, metrics.ScriptOutcomeTimeout} {
				want := 0.0
				if outcome == tc.wantOutcome {
					want = 1
				}
				if got := counterValue(t, m, cmScriptsMetric, map[string]string{"outcome": outcome}); got != want {
					t.Errorf("%s{outcome=%q} = %v, want %v", cmScriptsMetric, outcome, got, want)
				}
			}

			// Every series of the backends the handler knows exists from the
			// start; the expected ones are at one, all others at zero.
			for _, b := range []string{cmShop, cmWebSearch, metricsBackendBuiltin} {
				for _, reason := range []string{metrics.SwallowedDispatch, metrics.SwallowedCoercion, metrics.SwallowedToolError} {
					want := 0.0
					for _, s := range tc.wantSwallowed {
						if s.backend == b && s.reason == reason {
							want = 1
						}
					}
					labels := map[string]string{"backend": b, "reason": reason}
					if got := counterValue(t, m, cmSwallowedMetric, labels); got != want {
						t.Errorf("%s %v = %v, want %v", cmSwallowedMetric, labels, got, want)
					}
				}
			}
		})
	}
}
