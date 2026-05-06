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
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	return NewHandler(exec, mb, nil, "", nil, logger, false)
}

type mockToolBackend struct {
	tools []backend.ToolDescriptor
}

func (m *mockToolBackend) Execute(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}}}, nil
}

func (m *mockToolBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return m.tools, nil
}

func (m *mockToolBackend) Healthy(_ context.Context) error { return nil }

// TestListTools_PatternOptional verifies that an omitted or empty pattern is
// treated as ".*" and lists every authorized tool. Requiring callers to pass
// the magic string ".*" for the common "list everything" case was friction.
func TestListTools_PatternOptional(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{Name: "github_list_issues", Description: "List issues"},
		{Name: "vikunja_list_tasks", Description: "List tasks"},
	}
	h := newHandlerWithTools(t, tools)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	cases := []struct {
		name   string
		params map[string]any
	}{
		{name: "missing pattern", params: map[string]any{}},
		{name: "empty pattern", params: map[string]any{"pattern": ""}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := h.HandleToolCall(ctx, "discover_tools", tc.params)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsError {
				t.Fatalf("expected non-error result for %s, got: %v", tc.name, result.Content)
			}
			text := extractText(t, result)
			for _, name := range []string{"github_list_issues", "vikunja_list_tasks"} {
				if !strings.Contains(text, name) {
					t.Errorf("expected %s in output for %s, got: %s", name, tc.name, text)
				}
			}
		})
	}
}

func TestListTools_InvalidRegex(t *testing.T) {
	h := newHandlerWithTools(t, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	result, err := h.HandleToolCall(ctx, "discover_tools", map[string]any{argNamePattern: "[invalid"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for invalid regex")
	}
}

func TestListTools_FilterByName(t *testing.T) {
	tools := []backend.ToolDescriptor{
		{Name: testToolGithubListIss, Description: "List issues"},
		{Name: testToolGithubCreatePR, Description: "Create a pull request"},
		{Name: testToolVikunjaList, Description: "List tasks"},
		{Name: testToolVikunjaCreate, Description: "Create a task"},
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
			pattern:   testBackendNameGitHub,
			wantNames: []string{testToolGithubListIss, testToolGithubCreatePR},
		},
		{
			name:      "filter by tool name substring",
			pattern:   "pull",
			wantNames: []string{testToolGithubCreatePR},
		},
		{
			name:      "match all",
			pattern:   ".*",
			wantNames: []string{testToolGithubListIss, testToolGithubCreatePR, testToolVikunjaList, testToolVikunjaCreate},
		},
		{
			name:      "no matches",
			pattern:   "nonexistent",
			wantNames: nil,
		},
		{
			name:      "case insensitive",
			pattern:   "GITHUB",
			wantNames: []string{testToolGithubListIss, testToolGithubCreatePR},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.HandleToolCall(ctx, "discover_tools", map[string]any{argNamePattern: tt.pattern})
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
			allNames := []string{testToolGithubListIss, testToolGithubCreatePR, testToolVikunjaList, testToolVikunjaCreate}
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
		{Name: testToolGithubListIss, Description: "List issues for a repository"},
		{Name: testToolVikunjaCreate, Description: "Create a new task in a project"},
	}
	h := newHandlerWithTools(t, tools)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: "u1", Authenticated: true})

	// "repository" only appears in the description of github_list_issues
	result, err := h.HandleToolCall(ctx, "discover_tools", map[string]any{argNamePattern: "repository"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	text := extractText(t, result)
	if !strings.Contains(text, testToolGithubListIss) {
		t.Error("expected github_list_issues to match via description")
	}
	if strings.Contains(text, "function vikunja_create_task(") {
		t.Error("vikunja_create_task should not match 'repository'")
	}
}

// TestBuildToolList_PatternInSchema verifies that the schema for discover_tools
// declares the pattern property but does NOT mark it required. The default-to-".*"
// behavior is implemented in handleDiscoverTools, so listing pattern as required
// would force callers to pass the magic string for the common "list all" case.
func TestBuildToolList_PatternInSchema(t *testing.T) {
	h := newHandlerWithTools(t, nil)
	tools, err := h.BuildToolList(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var discoverTool *ToolDefinition
	for i := range tools {
		if tools[i].Name == "discover_tools" {
			discoverTool = &tools[i]
			break
		}
	}
	if discoverTool == nil {
		t.Fatal("discover_tools not found in tool list")
	}

	props, ok := discoverTool.InputSchema[schemaKeyProperties].(map[string]any)
	if !ok {
		t.Fatal("expected properties in input schema")
	}
	if _, ok := props[argNamePattern]; !ok {
		t.Error("expected 'pattern' property in discover_tools schema")
	}

	// pattern must NOT appear in required — it has a sensible default (".*").
	if required, present := discoverTool.InputSchema[schemaKeyRequired]; present {
		if list, ok := required.([]string); ok && len(list) > 0 {
			t.Errorf("discover_tools must not list any required fields (pattern has a default), got %v", list)
		}
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
	text, ok := item[contentKeyText].(string)
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
