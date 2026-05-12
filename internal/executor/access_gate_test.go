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
	"strings"
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
// declares testGitHubListRepos as access: read and a write tool, then asserts
// that the audit entry carries the classification on every code path.
func TestExecuteTool_PropagatesToolAccess(t *testing.T) {
	cases := []struct {
		name       string
		toolName   string
		wantAccess string
	}{
		{name: "read tool", toolName: testGitHubListRepos, wantAccess: testAccessRead},
		{name: "write tool", toolName: testGitHubCreateRepo, wantAccess: testAccessWrite},
		{name: "unknown tool stays empty", toolName: "github_unknown", wantAccess: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			be := &accessAwareBackend{
				access: map[string]string{
					testGitHubListRepos:  testAccessRead,
					testGitHubCreateRepo: testAccessWrite,
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
			testGitHubListRepos:  testAccessRead,
			testGitHubCreateRepo: testAccessWrite,
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
	read, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: testGitHubListRepos})
	if err != nil {
		t.Fatalf("read tool: ExecuteTool: %v", err)
	}
	if read.IsError {
		t.Errorf("read tool: expected pass, got IsError=true")
	}

	// Write tool is blocked at the pre-execution gate before backend runs.
	write, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: testGitHubCreateRepo})
	if err != nil {
		t.Fatalf("write tool: ExecuteTool: %v", err)
	}
	if !write.IsError {
		t.Errorf("write tool: expected gate rejection, got IsError=false")
	}
}

// TestExecuteTool_AuditCapturesPolicyModification wires a post-execution
// gate that redacts the backend response and verifies that the resulting
// audit entry carries a before/after PolicyModification — the contract the
// gate guarantees to operators auditing the system.
func TestExecuteTool_AuditCapturesPolicyModification(t *testing.T) {
	// Documented AWS example key used as fixture for the redaction policy
	// under test — constructed at runtime to avoid tripping gosec G101 on
	// the literal pattern.
	secretFixture := "raw secret: " + "AKIA" + "IOSFODNN7EXAMPLE"
	be := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{
					contentKeyType: contentKeyText,
					contentKeyText: secretFixture,
				}},
			}, nil
		},
	}

	dir := t.TempDir()
	policy := `
		if (ctx.phase === "post" && ctx.response && ctx.response.content) {
			for (var i = 0; i < ctx.response.content.length; i++) {
				if (ctx.response.content[i].type === "text") {
					ctx.response.content[i].text =
						ctx.response.content[i].text.replace(/AKIA[A-Z0-9]{16}/g, "[AWS_KEY]");
				}
			}
		}
	`
	if err := os.WriteFile(filepath.Join(dir, "redact_aws.js"), []byte(policy), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	rec := &recordingAudit{}
	exec := New(nil, nil, be, gate.NewPipeline([]gate.Evaluator{g}), rec,
		30*time.Second, newTestLogger(), nil, nil)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: testGitHubListRepos})
	if err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("expected success, got IsError=true: %+v", result)
	}

	// The fragment we expect to see only in the before-snapshot. Built the
	// same way as the fixture so gosec ignores the literal.
	secretFragment := "AKIA" + "IOSFODNN7EXAMPLE"

	// The response that left the executor must already be redacted.
	if got := result.Content[0].(map[string]any)[contentKeyText].(string); strings.Contains(got, secretFragment) {
		t.Errorf("response leaked unredacted AWS key: %q", got)
	}

	// And the audit entry must prove what was changed.
	if len(rec.last.Modifications) != 1 {
		t.Fatalf("expected 1 audit modification, got %d: %+v",
			len(rec.last.Modifications), rec.last.Modifications)
	}
	mod := rec.last.Modifications[0]
	if mod.Policy != "redact_aws.js" {
		t.Errorf("policy = %q, want redact_aws.js", mod.Policy)
	}
	if mod.Phase != "post" {
		t.Errorf("phase = %q, want post", mod.Phase)
	}
	if mod.Target != audit.ModificationTargetResponseContent {
		t.Errorf("target = %q, want %q", mod.Target, audit.ModificationTargetResponseContent)
	}
	if !strings.Contains(string(mod.Before), secretFragment) {
		t.Errorf("audit before snapshot must contain the original secret: %s", string(mod.Before))
	}
	if strings.Contains(string(mod.After), secretFragment) {
		t.Errorf("audit after snapshot must NOT contain the secret: %s", string(mod.After))
	}
	if !strings.Contains(string(mod.After), "[AWS_KEY]") {
		t.Errorf("audit after snapshot should contain the redaction marker: %s", string(mod.After))
	}
}

// TestExecuteTool_NoModificationsForUnchangedCall verifies the negative
// contract: when the post-gate inspects but does not mutate the response,
// the audit entry must NOT carry a Modifications list. "No audit modification
// event" is the proof that nothing was changed.
func TestExecuteTool_NoModificationsForUnchangedCall(t *testing.T) {
	be := &mockBackend{}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inspect_only.js"),
		[]byte(`// read-only: counts content blocks but never writes
		var n = (ctx.response && ctx.response.content) ? ctx.response.content.length : 0;
		`), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}

	rec := &recordingAudit{}
	exec := New(nil, nil, be, gate.NewPipeline([]gate.Evaluator{g}), rec,
		30*time.Second, newTestLogger(), nil, nil)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	if _, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: testGitHubListRepos}); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if len(rec.last.Modifications) != 0 {
		t.Errorf("inspection-only policy should not produce audit modifications, got %d: %+v",
			len(rec.last.Modifications), rec.last.Modifications)
	}
}
