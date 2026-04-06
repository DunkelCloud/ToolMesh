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
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

func handlerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func newHandlerWithTools(t *testing.T, tools []backend.ToolDescriptor) *Handler {
	t.Helper()
	mb := &mockToolBackend{tools: tools}
	logger := handlerTestLogger()
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil)
	return NewHandler(exec, mb, nil, "", logger)
}

type mockToolBackend struct {
	tools []backend.ToolDescriptor
}

func (m *mockToolBackend) Execute(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{Content: []any{map[string]any{"type": "text", "text": "ok"}}}, nil
}

func (m *mockToolBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return m.tools, nil
}

func (m *mockToolBackend) Healthy(_ context.Context) error { return nil }

func TestListTools_PatternRequired(t *testing.T) {
	h := newHandlerWithTools(t, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	result, err := h.HandleToolCall(ctx, "list_tools", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when pattern is missing")
	}
}

func TestListTools_InvalidRegex(t *testing.T) {
	h := newHandlerWithTools(t, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	result, err := h.HandleToolCall(ctx, "list_tools", map[string]any{"pattern": "[invalid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex")
	}
}

func TestListTools_FilterByName(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{Name: "github_list_issues", Description: "List issues"},
		{Name: "github_create_pull", Description: "Create a pull request"},
		{Name: "vikunja_list_tasks", Description: "List tasks"},
		{Name: "vikunja_create_task", Description: "Create a task"},
	}
	h := newHandlerWithTools(t, tools)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	tests := []struct {
		name      string
		pattern   string
		wantNames []string
	}{
		{
			name:      "filter by backend prefix",
			pattern:   "github",
			wantNames: []string{"github_list_issues", "github_create_pull"},
		},
		{
			name:      "filter by tool name substring",
			pattern:   "pull",
			wantNames: []string{"github_create_pull"},
		},
		{
			name:      "match all",
			pattern:   ".*",
			wantNames: []string{"github_list_issues", "github_create_pull", "vikunja_list_tasks", "vikunja_create_task"},
		},
		{
			name:      "no matches",
			pattern:   "nonexistent",
			wantNames: nil,
		},
		{
			name:      "case insensitive",
			pattern:   "GITHUB",
			wantNames: []string{"github_list_issues", "github_create_pull"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.HandleToolCall(ctx, "list_tools", map[string]any{"pattern": tt.pattern})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %v", result.Content)
			}

			text := extractText(t, result)
			for _, name := range tt.wantNames {
				if !strings.Contains(text, name) {
					t.Errorf("expected output to contain %q", name)
				}
			}

			// Verify excluded tools are not present
			allNames := []string{"github_list_issues", "github_create_pull", "vikunja_list_tasks", "vikunja_create_task"}
			for _, name := range allNames {
				if contains(tt.wantNames, name) {
					continue
				}
				if strings.Contains(text, "function "+name+"(") {
					t.Errorf("expected output NOT to contain function %q", name)
				}
			}
		})
	}
}

func TestListTools_MatchesDescription(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{Name: "github_list_issues", Description: "List issues for a repository"},
		{Name: "vikunja_create_task", Description: "Create a new task in a project"},
	}
	h := newHandlerWithTools(t, tools)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	// "repository" only appears in the description of github_list_issues
	result, err := h.HandleToolCall(ctx, "list_tools", map[string]any{"pattern": "repository"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, "github_list_issues") {
		t.Error("expected github_list_issues to match via description")
	}
	if strings.Contains(text, "function vikunja_create_task(") {
		t.Error("vikunja_create_task should not match 'repository'")
	}
}

func TestBuildToolList_PatternInSchema(t *testing.T) {
	h := newHandlerWithTools(t, nil)
	tools, err := h.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var listTool *ToolDefinition
	for i := range tools {
		if tools[i].Name == "list_tools" {
			listTool = &tools[i]
			break
		}
	}
	if listTool == nil {
		t.Fatal("list_tools not found in tool list")
	}

	props, ok := listTool.InputSchema["properties"].(map[string]any)
	if !ok {
		t.Fatal("expected properties in input schema")
	}
	if _, ok := props["pattern"]; !ok {
		t.Error("expected 'pattern' property in list_tools schema")
	}

	required, ok := listTool.InputSchema["required"].([]string)
	if !ok {
		t.Fatal("expected required array in input schema")
	}
	if len(required) != 1 || required[0] != "pattern" {
		t.Errorf("expected required=[\"pattern\"], got %v", required)
	}
}

func extractText(t *testing.T, result *backend.ToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty result content")
	}
	item, ok := result.Content[0].(map[string]any)
	if !ok {
		t.Fatal("unexpected content type")
	}
	text, ok := item["text"].(string)
	if !ok {
		t.Fatal("missing text in content")
	}
	return text
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
