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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fixtures of the tool list paging tests.
const (
	pgBackend    = "paged"
	pgToolAlpha  = "alpha"
	pgToolBravo  = "bravo"
	pgToolDelta  = "delta"
	pgCursorNext = "page-2"
	// pgWarnCutOff is the log line for a tool list that does not end.
	pgWarnCutOff = "tool list cut off"
)

// pgTool is a tool as a scripted tools/list answer returns it.
func pgTool(name string) *mcp.Tool {
	return &mcp.Tool{Name: name, Description: name, InputSchema: map[string]any{schemaKeyType: schemaTypeObject}}
}

// pgNoopHandler answers a tool call of the paging fixtures; the tests only
// list tools.
func pgNoopHandler(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
}

// newPagingTestAdapter wires an MCPAdapter to server over an in-memory
// transport without running discovery, and returns the adapter, the
// backend's connection and the buffer its log goes to.
func newPagingTestAdapter(t *testing.T, server *mcp.Server, entry BackendEntry) (*MCPAdapter, *backendConn, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	conn := &backendConn{
		entry:   entry,
		session: connectInMemoryMCP(t, server),
		include: buildMCPIncludeSet(entry.IncludeTools),
	}
	adapter := &MCPAdapter{
		backends: map[string]*backendConn{entry.Name: conn},
		creds:    credentials.NewEmbeddedStore(),
		logger:   slog.New(slog.NewTextHandler(&logs, nil)),
	}
	return adapter, conn, &logs
}

// countToolLists counts the tools/list requests server receives.
func countToolLists(server *mcp.Server) *atomic.Int32 {
	var requests atomic.Int32
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				requests.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	return &requests
}

// TestMCPAdapter_DiscoverTools_FollowsCursor runs discovery against an MCP
// server that hands out its tool list two tools at a time. Before discovery
// followed the cursor, the backend lost every tool after the first page.
func TestMCPAdapter_DiscoverTools_FollowsCursor(t *testing.T) {
	tests := []struct {
		name         string
		includeTools []string
		want         []string
	}{
		{name: "all pages are discovered", want: []string{pgToolAlpha, pgToolBravo, pgToolDelta}},
		{name: "include_tools reaches a tool of the second page", includeTools: []string{pgToolDelta}, want: []string{pgToolDelta}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: pgBackend, Version: testVersion01}, &mcp.ServerOptions{PageSize: 2})
			for _, name := range []string{pgToolAlpha, pgToolBravo, pgToolDelta} {
				server.AddTool(pgTool(name), pgNoopHandler)
			}
			requests := countToolLists(server)
			adapter, conn, logs := newPagingTestAdapter(t, server, BackendEntry{Name: pgBackend, IncludeTools: tt.includeTools})

			if err := adapter.discoverTools(context.Background(), pgBackend, conn); err != nil {
				t.Fatalf("discover tools: %v", err)
			}
			if got := requests.Load(); got != 2 {
				t.Errorf("backend received %d tools/list requests, want 2", got)
			}
			names := toolNameSet(t, adapter)
			if len(names) != len(tt.want) {
				t.Errorf("discovered %d tools, want %d: %v", len(names), len(tt.want), names)
			}
			for _, want := range tt.want {
				if !names[pgBackend+"_"+want] {
					t.Errorf("tool %q is missing: %v", want, names)
				}
			}
			for _, unwanted := range []string{pgWarnCutOff, "does not match any tool"} {
				if strings.Contains(logs.String(), unwanted) {
					t.Errorf("unexpected log line %q:\n%s", unwanted, logs.String())
				}
			}
		})
	}
}

// scriptedToolLists replaces the tools/list answers of server with those of
// page, which gets the number of the request, from 1, and its cursor. It
// returns the number of requests answered.
func scriptedToolLists(server *mcp.Server, page func(n int, cursor string) (*mcp.ListToolsResult, error)) *atomic.Int32 {
	var requests atomic.Int32
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method != "tools/list" {
				return next(ctx, method, req)
			}
			cursor := ""
			if params, ok := req.GetParams().(*mcp.ListToolsParams); ok && params != nil {
				cursor = params.Cursor
			}
			return page(int(requests.Add(1)), cursor)
		}
	})
	return &requests
}

// TestMCPAdapter_DiscoverTools_Paging covers the cursor handling against
// backends that script their pages: the cursor of one answer is the cursor
// of the next request, a cursor that never ends is followed for
// maxToolListPages pages and then given up with a warning, and an error on
// a later page is the error of discovery as a whole.
func TestMCPAdapter_DiscoverTools_Paging(t *testing.T) {
	tests := []struct {
		name         string
		page         func(n int, cursor string) (*mcp.ListToolsResult, error)
		wantErr      string
		wantRequests int32
		wantTools    int
		wantLog      string
	}{
		{
			name: "two pages",
			page: func(n int, cursor string) (*mcp.ListToolsResult, error) {
				switch {
				case n == 1 && cursor == "":
					return &mcp.ListToolsResult{Tools: []*mcp.Tool{pgTool(pgToolAlpha)}, NextCursor: pgCursorNext}, nil
				case n == 2 && cursor == pgCursorNext:
					return &mcp.ListToolsResult{Tools: []*mcp.Tool{pgTool(pgToolBravo)}}, nil
				}
				return nil, fmt.Errorf("request %d came with cursor %q", n, cursor)
			},
			wantRequests: 2,
			wantTools:    2,
		},
		{
			// Every page repeats one tool and adds a new one: the repeated
			// name is kept once, the others are all there. Each answer
			// carries a cursor of its own, so no page can come from a cache.
			name: "the cursor never ends",
			page: func(n int, _ string) (*mcp.ListToolsResult, error) {
				return &mcp.ListToolsResult{
					Tools:      []*mcp.Tool{pgTool(pgToolAlpha), pgTool(fmt.Sprintf("tool_%d", n))},
					NextCursor: fmt.Sprintf("page-%d", n+1),
				}, nil
			},
			wantRequests: maxToolListPages,
			wantTools:    maxToolListPages + 1,
			wantLog:      pgWarnCutOff,
		},
		{
			name: "the second page fails",
			page: func(n int, _ string) (*mcp.ListToolsResult, error) {
				if n == 1 {
					return &mcp.ListToolsResult{Tools: []*mcp.Tool{pgTool(pgToolAlpha)}, NextCursor: pgCursorNext}, nil
				}
				return nil, errors.New("cursor expired")
			},
			wantErr:      "list tools, page 2",
			wantRequests: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := mcp.NewServer(&mcp.Implementation{Name: pgBackend, Version: testVersion01}, nil)
			// One registered tool makes the server announce the tools
			// capability; the script answers the list requests.
			server.AddTool(pgTool(pgToolDelta), pgNoopHandler)
			requests := scriptedToolLists(server, tt.page)
			adapter, conn, logs := newPagingTestAdapter(t, server, BackendEntry{Name: pgBackend})

			err := adapter.discoverTools(context.Background(), pgBackend, conn)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("discover tools: error = %v, want one containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("discover tools: %v", err)
			}
			if got := requests.Load(); got != tt.wantRequests {
				t.Errorf("backend received %d tools/list requests, want %d", got, tt.wantRequests)
			}
			names := toolNameSet(t, adapter)
			if len(conn.tools) != tt.wantTools || len(names) != tt.wantTools {
				t.Errorf("discovered %d tools (%d distinct names), want %d", len(conn.tools), len(names), tt.wantTools)
			}
			if cut := strings.Contains(logs.String(), pgWarnCutOff); cut != (tt.wantLog != "") {
				t.Errorf("warning %q logged = %v, want %v:\n%s", pgWarnCutOff, cut, tt.wantLog != "", logs.String())
			}
		})
	}
}
