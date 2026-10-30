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

package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/telemetry"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// passthroughSubBackend stands in for a passthrough backend such as the MCP
// adapter: it routes the full tool name itself and names its sub-backends
// through BackendSummaries.
type passthroughSubBackend struct {
	mockBackend
	name string
}

func (p *passthroughSubBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	if !strings.HasPrefix(toolName, p.name+"_") {
		return nil, fmt.Errorf("no backend found for tool %q", toolName)
	}
	return p.mockBackend.Execute(ctx, toolName, params)
}

func (p *passthroughSubBackend) BackendSummaries() []backend.BackendInfo {
	return []backend.BackendInfo{{Name: p.name}}
}

// TestExecuteTool_RoutedBackendName checks that the audit entry, telemetry
// and the tool-call metrics name the backend a call is routed to. The names
// "web" and "web_search" share a prefix, so splitting the tool name at the
// first underscore would attribute "web_search_query" to "web".
func TestExecuteTool_RoutedBackendName(t *testing.T) {
	// Telemetry stays off the network; counters are still kept and written
	// to the state file on shutdown.
	t.Setenv("DO_NOT_SEND_ANONYMOUS_STATISTICS", "yes")

	tests := []struct {
		name        string
		tool        string
		wantErr     bool
		wantBackend string // audit entry
		wantSeries  string // the only toolmesh_tool_calls_total series
		wantCounted string // telemetry hash the call is counted under, "" for none
	}{
		{
			name:        "backend name without underscore",
			tool:        testToolWebFetch,
			wantBackend: testBackendWeb,
			wantSeries:  `toolmesh_tool_calls_total{backend="web",result="success",tool="fetch"} 1`,
			wantCounted: "hash-" + testBackendWeb,
		},
		{
			name:        "backend name with underscore",
			tool:        testToolWebSearchQuery,
			wantBackend: testBackendWebSearch,
			wantSeries:  `toolmesh_tool_calls_total{backend="web_search",result="success",tool="query"} 1`,
			wantCounted: "hash-" + testBackendWebSearch,
		},
		{
			name:        "passthrough sub-backend with underscore",
			tool:        "opnsense_backup_download",
			wantBackend: "opnsense_backup",
			wantSeries:  `toolmesh_tool_calls_total{backend="opnsense_backup",result="success",tool="download"} 1`,
		},
		{
			name:       "tool no backend claims",
			tool:       "ghost_lookup",
			wantErr:    true,
			wantSeries: `toolmesh_tool_calls_total{backend="unknown",result="error",tool="ghost_lookup"} 1`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{
				testBackendWeb:       &mockBackend{},
				testBackendWebSearch: &mockBackend{},
			})
			composite.AddPassthrough(&passthroughSubBackend{name: "opnsense_backup"})

			dataDir := t.TempDir()
			collector := telemetry.New(dataDir, "test", newTestLogger())
			collector.RegisterBackend(testBackendWeb, "hash-"+testBackendWeb)
			collector.RegisterBackend(testBackendWebSearch, "hash-"+testBackendWebSearch)
			reg := metrics.New(metrics.Options{LabelTool: true})
			rec := &recordingAudit{}
			exec := New(nil, nil, composite, nil, rec, time.Second, newTestLogger(), collector, reg)

			ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testUserID})
			_, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: tc.tool})
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExecuteTool error = %v, wantErr %v", err, tc.wantErr)
			}

			if rec.last.Tool != tc.tool || rec.last.Backend != tc.wantBackend {
				t.Errorf("audit entry tool/backend = %q/%q, want %q/%q", rec.last.Tool, rec.last.Backend, tc.tool, tc.wantBackend)
			}

			if got := toolCallSeries(t, reg); len(got) != 1 || got[0] != tc.wantSeries {
				t.Errorf("tool-call series = %q, want [%q]", got, tc.wantSeries)
			}

			counted := telemetryCallCounts(t, collector, dataDir)
			want := map[string]int{}
			if tc.wantCounted != "" {
				want[tc.wantCounted] = 1
			}
			if fmt.Sprint(counted) != fmt.Sprint(want) {
				t.Errorf("telemetry call counts = %v, want %v", counted, want)
			}
		})
	}
}

// toolCallSeries scrapes reg and returns its toolmesh_tool_calls_total lines.
func toolCallSeries(t *testing.T, reg *metrics.Registry) []string {
	t.Helper()
	rr := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rr, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	var series []string
	for _, line := range strings.Split(rr.Body.String(), "\n") {
		if strings.HasPrefix(line, "toolmesh_tool_calls_total{") {
			series = append(series, line)
		}
	}
	return series
}

// telemetryCallCounts stops the collector, which writes its counters to the
// state file in dataDir, and returns the call count per DADL hash.
func telemetryCallCounts(t *testing.T, c *telemetry.Collector, dataDir string) map[string]int {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx)
		close(done)
	}()
	cancel()
	<-done

	data, err := os.ReadFile(filepath.Join(dataDir, "toolmesh.json")) //nolint:gosec // G304: path is under t.TempDir()
	if err != nil {
		t.Fatalf("read telemetry state: %v", err)
	}
	var state struct {
		Telemetry struct {
			Counters map[string]struct {
				CallCount int `json:"call_count"`
			} `json:"counters"`
		} `json:"telemetry"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("parse telemetry state: %v", err)
	}
	counts := make(map[string]int, len(state.Telemetry.Counters))
	for hash, c := range state.Telemetry.Counters {
		counts[hash] = c.CallCount
	}
	return counts
}
