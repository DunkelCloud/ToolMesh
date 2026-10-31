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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/health"
)

// Tool names of the health discovery tests.
const (
	testHealthTool   = "gitlab_health"
	testGitLabStatus = "gitlab_get_pipeline_status"
)

// staticHealthReport is a HealthReporter returning a fixed report.
type staticHealthReport health.Report

func (r staticHealthReport) Report() health.Report { return health.Report(r) }

func TestServer_HealthReportsBackends(t *testing.T) {
	srv, mux := newTestServer(t, &config.Config{})
	srv.SetHealthReporter(staticHealthReport{
		Status: health.StatusDegraded,
		Backends: map[string]health.BackendStatus{
			"tailscale": {Status: health.StatusDegraded, Reason: "health check failing since 2026-10-30T10:00:00Z (2 consecutive): unauthorized (HTTP 401)"},
		},
	})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// A degraded upstream must not fail container liveness probes.
	if w.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200 while degraded", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{`"status":"degraded"`, `"tailscale":{"status":"degraded"`, "unauthorized (HTTP 401)"} {
		if !strings.Contains(body, want) {
			t.Errorf("body %s lacks %s", body, want)
		}
	}
}

// healthDiscoveryTools are a regular tool and a synthetic health tool whose
// descriptions both match "health status".
func healthDiscoveryTools() []backend.ToolDescriptor {
	return []backend.ToolDescriptor{
		{Name: testGitLabStatus, Description: "Get the pipeline status and health of a project", Backend: "rest:gitlab"},
		{Name: testHealthTool, Description: "Standardized backend health check: verifies that the API is reachable.", Backend: "rest:gitlab", Access: testAccessRead, Unranked: true},
	}
}

// The synthetic health tool is not ranked by a query, but a pattern lists it.
func TestDiscoverTools_UnrankedHealthTool(t *testing.T) {
	h := newHandlerWithTools(t, healthDiscoveryTools())

	ranked := discoverText(t, h, map[string]any{argNameQuery: "health status check"})
	if strings.Contains(ranked, testHealthTool) {
		t.Errorf("query mode ranked the synthetic health tool:\n%s", ranked)
	}
	if !strings.Contains(ranked, testGitLabStatus) {
		t.Errorf("query mode lost the regular tool:\n%s", ranked)
	}

	listed := discoverText(t, h, map[string]any{argNamePattern: "^gitlab"})
	if !strings.Contains(listed, testHealthTool) {
		t.Errorf("pattern mode hid the synthetic health tool:\n%s", listed)
	}
}

func TestCodeRunner_DiscoverSkipsUnrankedButDescribes(t *testing.T) {
	tools := healthDiscoveryTools()
	mb := &mockToolBackend{tools: tools}
	logger := handlerTestLogger()
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	nameMap := map[string]string{testGitLabStatus: testGitLabStatus, testHealthTool: testHealthTool}
	runner := NewCodeRunner(nameMap, tools, exec, nil, logger)

	result, err := runner.Execute(testCtx(), `return toolmesh.discover("health status check").map(t => t.name).join(",");`)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if text := extractText(t, result); strings.Contains(text, testHealthTool) || !strings.Contains(text, testGitLabStatus) {
		t.Errorf("discover = %s, want the regular tool only", text)
	}

	result, err = runner.Execute(testCtx(), `return toolmesh.describe("gitlab_health").access;`)
	if err != nil {
		t.Fatalf("describe: %v", err)
	}
	if text := extractText(t, result); !strings.Contains(text, "read") {
		t.Errorf("describe(gitlab_health).access = %s, want read", text)
	}
}
