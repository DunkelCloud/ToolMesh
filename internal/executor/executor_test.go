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
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

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

	exec := New(nil, nil, mb, nil, logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-1",
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
	if result.Metadata["user"] != "user-1" {
		t.Errorf("metadata user = %v, want \"user-1\"", result.Metadata["user"])
	}
	if _, ok := result.Metadata["latencyMs"]; !ok {
		t.Error("expected latencyMs in metadata")
	}
}

func TestExecuteTool_NoUserContext(t *testing.T) {
	mb := &mockBackend{}
	logger := newTestLogger()

	exec := New(nil, nil, mb, nil, logger)

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

	exec := New(nil, nil, mb, nil, logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-1",
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
	`), 0644)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-1",
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
	`), 0644)

	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	exec := New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-1",
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

	exec := New(nil, nil, mb, nil, logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "user-1",
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
	if result.Metadata["user"] != "user-1" {
		t.Error("expected user to be added to metadata")
	}
}
