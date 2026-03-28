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
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const testUserID = "user-1"

// mockBackend implements backend.ToolBackend for testing.
type mockBackend struct {
	executeFunc func(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error)
	tools       []backend.ToolDescriptor
}

func (m *mockBackend) Execute(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, toolName, params)
	}
	return &backend.ToolResult{
		Content: []any{map[string]any{"type": "text", "text": "ok"}},
	}, nil
}

func (m *mockBackend) ListTools(ctx context.Context) ([]backend.ToolDescriptor, error) {
	return m.tools, nil
}

func (m *mockBackend) Healthy(ctx context.Context) error {
	return nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestExecuteTool_Success(t *testing.T) {
	mb := &mockBackend{}
	logger := newTestLogger()

	exec := New(nil, nil, mb, nil, nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		CompanyID:     "acme",
		Authenticated: true,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "test:tool",
		Params:   map[string]any{"key": "value"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.IsError {
		t.Error("expected IsError = false")
	}
	if result.Metadata["user"] != testUserID {
		t.Errorf("metadata user = %v, want \"user-1\"", result.Metadata["user"])
	}
	if _, ok := result.Metadata["latencyMs"]; !ok {
		t.Error("expected latencyMs in metadata")
	}
}

func TestExecuteTool_NoUserContext(t *testing.T) {
	mb := &mockBackend{}
	logger := newTestLogger()

	exec := New(nil, nil, mb, nil, nil, "", logger)

	_, err := exec.ExecuteTool(context.Background(), ExecuteToolRequest{
		ToolName: "test:tool",
	})
	if err == nil {
		t.Fatal("expected error for missing user context, got nil")
	}
}

func TestExecuteTool_BackendError(t *testing.T) {
	mb := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			return nil, fmt.Errorf("backend unavailable")
		},
	}
	logger := newTestLogger()

	exec := New(nil, nil, mb, nil, nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	_, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "test:tool",
	})
	if err == nil {
		t.Fatal("expected error from backend, got nil")
	}
}

func TestExecuteTool_GateRejects(t *testing.T) {
	mb := &mockBackend{}
	logger := newTestLogger()

	// Create a gate with a policy that rejects unauthenticated users
	dir := t.TempDir()
	os.WriteFile(dir+"/reject.js", []byte(`
		if (!ctx.user.authenticated) {
			throw new Error("not authenticated");
		}
	`), 0600)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: false,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "test:tool",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError = true when gate rejects")
	}
}

func TestExecuteTool_GatePasses(t *testing.T) {
	mb := &mockBackend{}
	logger := newTestLogger()

	dir := t.TempDir()
	os.WriteFile(dir+"/pass.js", []byte(`
		if (!ctx.user.authenticated) {
			throw new Error("not authenticated");
		}
	`), 0600)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "test:tool",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Error("expected IsError = false when gate passes")
	}
}

func TestExecuteTool_PreGateBlocksBeforeBackend(t *testing.T) {
	backendCalled := false
	mb := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			backendCalled = true
			return &backend.ToolResult{
				Content: []any{map[string]any{"type": "text", "text": "ok"}},
			}, nil
		},
	}
	logger := newTestLogger()

	// Policy that blocks set_switch with on=false in pre phase
	dir := t.TempDir()
	os.WriteFile(dir+"/block.js", []byte(`
		if (ctx.phase === "pre" && /set_switch/.test(ctx.tool)) {
			if (ctx.params && ctx.params.on === false) {
				throw "turning off devices is not allowed";
			}
		}
	`), 0600)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	// Turn off should be blocked — backend must NOT be called
	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "shelly_cloud_set_switch",
		Params:   map[string]any{"on": false, "id": "device123"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError = true when pre-gate rejects")
	}
	if backendCalled {
		t.Error("backend should NOT be called when pre-gate rejects")
	}

	// Turn on should pass — backend should be called
	backendCalled = false
	result, err = exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "shelly_cloud_set_switch",
		Params:   map[string]any{"on": true, "id": "device123"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Error("expected IsError = false when pre-gate passes")
	}
	if !backendCalled {
		t.Error("backend should be called when pre-gate passes")
	}
}

func TestExecuteTool_PostGateFiltersResponse(t *testing.T) {
	mb := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{"type": "text", "text": "sensitive data here"}},
			}, nil
		},
	}
	logger := newTestLogger()

	dir := t.TempDir()
	os.WriteFile(dir+"/post_block.js", []byte(`
		if (ctx.phase === "post" && ctx.tool === "secret_tool") {
			throw "response blocked by policy";
		}
	`), 0600)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "secret_tool",
		Params:   map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Error("expected IsError = true when post-gate rejects")
	}
}

func TestExecuteTool_BackendResultWithExistingMetadata(t *testing.T) {
	mb := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content:  []any{map[string]any{"type": "text", "text": "ok"}},
				Metadata: map[string]any{"backend": "test"},
			}, nil
		},
	}
	logger := newTestLogger()

	exec := New(nil, nil, mb, nil, nil, "", logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
	})

	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "test:tool"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should preserve existing metadata and add latencyMs + user
	if result.Metadata["backend"] != "test" {
		t.Error("expected existing metadata to be preserved")
	}
	if result.Metadata["user"] != testUserID {
		t.Error("expected user to be added to metadata")
	}
}

// TestCallerCredentialDurchstich is the Sprint 2 integration test that verifies
// the complete flow: CallerID → UserContext → Executor → Credential injection →
// Pre-Gate (JS policy with callerId/callerClass) → Backend → Post-Gate.
func TestCallerCredentialDurchstich(t *testing.T) {
	// Set env-var credentials for the EmbeddedStore
	t.Setenv("CREDENTIAL_GITHUB_API_KEY", "ghp_test_token_123")    //nolint:gosec // G101: intentional test data
	t.Setenv("CREDENTIAL_GITHUB_WEBHOOK_SECRET", "whsec_test_456") //nolint:gosec // G101: intentional test data

	credStore := credentials.NewEmbeddedStore()

	// Backend that verifies credentials arrived via context
	var receivedCreds map[string]string
	mb := &mockBackend{
		executeFunc: func(ctx context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
			receivedCreds = credentials.CredentialsFromContext(ctx)
			return &backend.ToolResult{
				Content: []any{map[string]any{"type": "text", "text": "executed " + toolName}},
			}, nil
		},
	}

	// Gate policies: pre-gate blocks untrusted callers on destructive tools,
	// post-gate blocks responses containing "BLOCKED_MARKER".
	policyDir := t.TempDir()
	os.WriteFile(policyDir+"/caller_class.js", []byte(`
		if (ctx.phase === "pre") {
			if (ctx.user.callerClass === "untrusted" && ctx.tool.match(/_(delete|drop|remove)/i)) {
				throw new Error("destructive op blocked for " + ctx.user.callerId);
			}
		}
		if (ctx.phase === "post" && ctx.response && ctx.response.content) {
			for (var i = 0; i < ctx.response.content.length; i++) {
				var item = ctx.response.content[i];
				if (item.text && item.text.indexOf("BLOCKED_MARKER") !== -1) {
					throw new Error("response contains blocked content");
				}
			}
		}
	`), 0600)

	g, err := gate.New(policyDir, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}
	pipeline := gate.NewPipeline([]gate.Evaluator{g})

	exec := New(nil, credStore, mb, pipeline, nil, "", newTestLogger())

	tests := []struct {
		name             string
		callerID         string
		callerClass      string
		tool             string
		wantError        bool
		wantCount        int
		wantKey          string
		wantVal          string
		wantRequestField bool // verify request fields populated for Temporal
	}{
		{
			name:             "trusted caller executes read tool with multi-credential injection",
			callerID:         "claude-code",
			callerClass:      "trusted",
			tool:             "github_get_repo",
			wantError:        false,
			wantCount:        2,
			wantKey:          "GITHUB_API_KEY",
			wantVal:          "ghp_test_token_123",
			wantRequestField: true,
		},
		{
			name:        "untrusted caller blocked on destructive tool by pre-gate",
			callerID:    "anonymous",
			callerClass: "untrusted",
			tool:        "github_delete_repo",
			wantError:   true,
		},
		{
			name:        "untrusted caller allowed on read tool",
			callerID:    "anonymous",
			callerClass: "untrusted",
			tool:        "github_get_repo",
			wantError:   false,
			wantCount:   2,
			wantKey:     "GITHUB_WEBHOOK_SECRET",
			wantVal:     "whsec_test_456",
		},
		{
			name:        "standard caller executes tool normally",
			callerID:    "partner-acme",
			callerClass: "standard",
			tool:        "github_list_issues",
			wantError:   false,
			wantCount:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			receivedCreds = nil

			ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
				UserID:        testUserID,
				CompanyID:     "acme",
				Authenticated: true,
				CallerID:      tt.callerID,
				CallerClass:   tt.callerClass,
			})

			req := ExecuteToolRequest{
				ToolName: tt.tool,
				Params:   map[string]any{"repo": "test"},
			}

			result, err := exec.ExecuteTool(ctx, req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantError {
				if !result.IsError {
					t.Error("expected IsError = true")
				}
				return
			}

			if result.IsError {
				t.Errorf("expected IsError = false, got error result")
			}

			// Verify credentials were injected via context
			if tt.wantCount > 0 {
				if len(receivedCreds) != tt.wantCount {
					t.Errorf("expected %d credentials, got %d: %v", tt.wantCount, len(receivedCreds), receivedCreds)
				}
			}
			if tt.wantKey != "" {
				if receivedCreds[tt.wantKey] != tt.wantVal {
					t.Errorf("credential %s = %q, want %q", tt.wantKey, receivedCreds[tt.wantKey], tt.wantVal)
				}
			}

			// Verify request fields are populated for Temporal search attributes
			if tt.wantRequestField {
				// The executor populates req fields internally, so we verify
				// the metadata reflects the correct user
				if result.Metadata["user"] != testUserID {
					t.Errorf("metadata user = %v, want user-1", result.Metadata["user"])
				}
			}
		})
	}
}

// TestCallerCredentialDurchstich_PostGateWithCallerClass verifies the post-gate
// has access to callerClass for response filtering.
func TestCallerCredentialDurchstich_PostGateWithCallerClass(t *testing.T) {
	mb := &mockBackend{
		executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			return &backend.ToolResult{
				Content: []any{map[string]any{"type": "text", "text": "secret internal data"}},
			}, nil
		},
	}

	policyDir := t.TempDir()
	os.WriteFile(policyDir+"/post_filter.js", []byte(`
		if (ctx.phase === "post" && ctx.user.callerClass === "untrusted") {
			throw new Error("untrusted callers cannot view this tool's output");
		}
	`), 0600)

	g, err := gate.New(policyDir, newTestLogger())
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, "", newTestLogger())

	// Trusted caller should see the response
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
		CallerID:      "claude-code",
		CallerClass:   "trusted",
	})
	result, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "internal_data"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Error("trusted caller should not be blocked by post-gate")
	}

	// Untrusted caller should be blocked
	ctx = userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-2",
		Authenticated: true,
		CallerID:      "anonymous",
		CallerClass:   "untrusted",
	})
	result, err = exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: "internal_data"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Error("untrusted caller should be blocked by post-gate")
	}
}
