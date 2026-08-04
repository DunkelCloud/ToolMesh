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

package backend

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// newIncludeTestAdapter builds an MCPAdapter wired to an in-memory MCP server
// offering the named tools, with discovery already run. It bypasses
// connectBackend because createTransport only speaks http/stdio, while the
// filtering under test lives in discoverTools and Execute.
func newIncludeTestAdapter(t *testing.T, entry BackendEntry, toolNames ...string) *MCPAdapter {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: "srv", Version: testVersion01}, nil)
	for _, toolName := range toolNames {
		server.AddTool(
			&mcp.Tool{
				Name:        toolName,
				Description: toolName + " description",
				InputSchema: map[string]any{"type": "object"},
			},
			func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return &mcp.CallToolResult{
					Content: []mcp.Content{&mcp.TextContent{Text: "ok"}},
				}, nil
			},
		)
	}

	ct, st := mcp.NewInMemoryTransports()
	go server.Connect(ctx, st, nil) //nolint:errcheck // test server, failure surfaces as a client connect error

	client := mcp.NewClient(&mcp.Implementation{Name: "tm", Version: testVersion01}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect in-memory: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	conn := &backendConn{
		entry:   entry,
		session: session,
		include: buildMCPIncludeSet(entry.IncludeTools),
	}
	adapter := &MCPAdapter{
		backends: map[string]*backendConn{entry.Name: conn},
		creds:    credentials.NewEmbeddedStore(),
		logger:   slog.Default(),
		client:   client,
	}
	if err := adapter.discoverTools(ctx, entry.Name, conn); err != nil {
		t.Fatalf("discover tools: %v", err)
	}
	return adapter
}

func includeTestEntry(includeTools, exposeTools []string) BackendEntry {
	return BackendEntry{
		Name:         testBackendNameTest,
		Transport:    transportTypeHTTP,
		URL:          testMCPURLExample,
		IncludeTools: includeTools,
		ExposeTools:  exposeTools,
	}
}

func toolNameSet(t *testing.T, adapter *MCPAdapter) map[string]bool {
	t.Helper()
	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		names[tool.Name] = true
	}
	return names
}

// include_tools restricts what discovery keeps, so discover_tools and
// execute_code never see the excluded tool.
func TestMCPAdapter_IncludeTools_FiltersDiscovery(t *testing.T) {
	adapter := newIncludeTestAdapter(t,
		includeTestEntry([]string{testToolFetchURL, testToolFetchURLs}, nil),
		testToolFetchURL, testToolFetchURLs, testToolBrowserInstall,
	)

	names := toolNameSet(t, adapter)
	if len(names) != 2 {
		t.Fatalf("expected 2 tools, got %d: %v", len(names), names)
	}
	if !names[testBackendNameTest+"_"+testToolFetchURL] || !names[testBackendNameTest+"_"+testToolFetchURLs] {
		t.Errorf("expected both included tools, got %v", names)
	}
	if names[testBackendNameTest+"_"+testToolBrowserInstall] {
		t.Errorf("excluded tool leaked into ListTools: %v", names)
	}
}

// Without include_tools the backend keeps its full surface — the filter must
// not change the default.
func TestMCPAdapter_NoIncludeTools_ExposesEverything(t *testing.T) {
	adapter := newIncludeTestAdapter(t,
		includeTestEntry(nil, nil),
		testToolFetchURL, testToolFetchURLs, testToolBrowserInstall,
	)

	if names := toolNameSet(t, adapter); len(names) != 3 {
		t.Fatalf("expected 3 tools, got %d: %v", len(names), names)
	}
}

// A hidden tool must not be reachable by guessing its name either: the
// allow-list is enforced at the execution boundary, not only in discovery.
func TestMCPAdapter_IncludeTools_BlocksExecute(t *testing.T) {
	adapter := newIncludeTestAdapter(t,
		includeTestEntry([]string{testToolFetchURL}, nil),
		testToolFetchURL, testToolBrowserInstall,
	)
	ctx := context.Background()

	_, err := adapter.Execute(ctx, testBackendNameTest+"_"+testToolBrowserInstall, nil)
	if err == nil {
		t.Fatal("expected error for excluded tool, got nil")
	}
	if !strings.Contains(err.Error(), testToolBrowserInstall) {
		t.Errorf("error should name the tool, got: %v", err)
	}

	if _, err := adapter.Execute(ctx, testBackendNameTest+"_"+testToolFetchURL, nil); err != nil {
		t.Fatalf("included tool should stay callable: %v", err)
	}
}

// expose_tools may not promote past include_tools: a promoted tool that
// discover_tools cannot see would be a contradictory surface.
func TestMCPAdapter_IncludeTools_ExcludesPromotion(t *testing.T) {
	adapter := newIncludeTestAdapter(t,
		includeTestEntry(
			[]string{testToolFetchURL},
			[]string{testToolFetchURL, testToolBrowserInstall},
		),
		testToolFetchURL, testToolBrowserInstall,
	)

	promoted := adapter.PromotedTools()
	if len(promoted) != 1 {
		t.Fatalf("expected 1 promotion, got %d: %+v", len(promoted), promoted)
	}
	if promoted[0].Descriptor.Name != testToolFetchURL {
		t.Errorf("expected %q promoted, got %q", testToolFetchURL, promoted[0].Descriptor.Name)
	}
}

// An include_tools entry that matches nothing upstream hides everything it was
// meant to allow. Discovery must survive it rather than fail the backend.
func TestMCPAdapter_IncludeTools_UnknownEntryIsNotFatal(t *testing.T) {
	adapter := newIncludeTestAdapter(t,
		includeTestEntry([]string{"typo_tool"}, nil),
		testToolFetchURL, testToolBrowserInstall,
	)

	if names := toolNameSet(t, adapter); len(names) != 0 {
		t.Fatalf("expected no tools for a non-matching allow-list, got %v", names)
	}
}
