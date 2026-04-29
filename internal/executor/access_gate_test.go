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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// accessAwareBackend extends mockBackend with a ToolMetadataLookup
// implementation so the executor can resolve access classifications.
type accessAwareBackend struct {
	mockBackend
	access map[string]string
}

func (a *accessAwareBackend) LookupTool(toolName string) (backend.ToolDescriptor, bool) {
	access, ok := a.access[toolName]
	if !ok {
		return backend.ToolDescriptor{}, false
	}
	return backend.ToolDescriptor{Name: toolName, Access: access}, true
}

// recordingAudit captures the last AuditEntry persisted, so tests can verify
// the access classification is propagated end to end.
type recordingAudit struct {
	last audit.AuditEntry
}

func (r *recordingAudit) Record(_ context.Context, entry audit.AuditEntry) error {
	r.last = entry
	return nil
}

func (r *recordingAudit) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, audit.ErrQueryNotSupported
}

func (r *recordingAudit) Healthy(_ context.Context) error { return nil }

// TestExecuteTool_PropagatesToolAccess wires the executor with a backend that
// declares "github_list_repos" as access: read and a write tool, then asserts
// that the audit entry carries the classification on every code path.
func TestExecuteTool_PropagatesToolAccess(t *testing.T) {
	cases := []struct {
		name       string
		toolName   string
		wantAccess string
	}{
		{name: "read tool", toolName: "github_list_repos", wantAccess: "read"},
		{name: "write tool", toolName: "github_create_repo", wantAccess: "write"},
		{name: "unknown tool stays empty", toolName: "github_unknown", wantAccess: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := &accessAwareBackend{
				access: map[string]string{
					"github_list_repos":  "read",
					"github_create_repo": "write",
				},
			}
			rec := &recordingAudit{}
			exec := New(nil, nil, be, nil, rec, 30*time.Second, newTestLogger(), nil, nil)

			ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
				UserID:        testUserID,
				Authenticated: true,
			})

			if _, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
				ToolName: tc.toolName,
			}); err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}
			if got := rec.last.ToolAccess; got != tc.wantAccess {
				t.Errorf("audit ToolAccess = %q, want %q", got, tc.wantAccess)
			}
		})
	}
}

// TestExecuteTool_GateSeesToolAccess ensures the access tag reaches JS gate
// policies as ctx.toolAccess so they can implement the read-only enforcement
// pattern (the FAQ-shipped reference policy).
func TestExecuteTool_GateSeesToolAccess(t *testing.T) {
	be := &accessAwareBackend{
		access: map[string]string{
			"github_list_repos":  "read",
			"github_create_repo": "write",
		},
	}

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "readonly.js")
	if err := os.WriteFile(policyPath, []byte(`
		if (ctx.phase === "pre" && ctx.toolAccess !== "" && ctx.toolAccess !== "read") {
			throw "blocked: " + ctx.tool + " requires " + ctx.toolAccess;
		}
	`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	exec := New(nil, nil, be, gate.NewPipeline([]gate.Evaluator{g}), nil, 30*time.Second, newTestLogger(), nil, nil)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	// Read tool passes the gate.
	read, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "github_list_repos"})
	if err != nil {
		t.Fatalf("read tool: ExecuteTool: %v", err)
	}
	if read.IsError {
		t.Errorf("read tool: expected pass, got IsError=true")
	}

	// Write tool is blocked at the pre-execution gate before backend runs.
	write, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "github_create_repo"})
	if err != nil {
		t.Fatalf("write tool: ExecuteTool: %v", err)
	}
	if !write.IsError {
		t.Errorf("write tool: expected gate rejection, got IsError=false")
	}
}
