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
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	mbBackend = "live"
	mbKept    = "status"
	mbOld     = "legacy"
	mbFresh   = "fresh"

	// Names of the tools as scripts and discovery see them.
	mbLiveKept  = mbBackend + "_" + mbKept
	mbLiveOld   = mbBackend + "_" + mbOld
	mbLiveFresh = mbBackend + "_" + mbFresh

	mbCallKept  = `return await toolmesh.` + mbLiveKept + `({})`
	mbCallOld   = `return await toolmesh.` + mbLiveOld + `({})`
	mbCallFresh = `return await toolmesh.` + mbLiveFresh + `({})`
)

// mbServer builds an MCP server whose tools answer "<tool> ran".
func mbServer(tools ...string) *mcpsdk.Server {
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: mbBackend, Version: "1"}, nil)
	for _, name := range tools {
		mbAddTool(server, name)
	}
	return server
}

func mbAddTool(server *mcpsdk.Server, name string) {
	server.AddTool(
		&mcpsdk.Tool{Name: name, Description: "Runs " + name, InputSchema: map[string]any{contentKeyType: jsonTypeObject}},
		func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: name + " ran"}}}, nil
		},
	)
}

// mbHost serves an MCP server over Streamable HTTP at one URL; restart puts
// another server behind it, as a restart of the backend does.
type mbHost struct {
	ts      *httptest.Server
	handler atomic.Pointer[http.Handler]
}

func newMBHost(t *testing.T, server *mcpsdk.Server) *mbHost {
	t.Helper()
	h := &mbHost{}
	h.serve(server)
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		(*h.handler.Load()).ServeHTTP(w, r)
	}))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *mbHost) serve(server *mcpsdk.Server) {
	var handler http.Handler = mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return server }, nil)
	h.handler.Store(&handler)
}

func (h *mbHost) restart(server *mcpsdk.Server) {
	h.serve(server)
	h.ts.CloseClientConnections()
}

// newMCPBackendHandler builds a handler over a composite backend whose only
// child is the adapter for the MCP server behind host, the way main wires
// the MCP backends of backends.yaml.
func newMCPBackendHandler(t *testing.T, host *mbHost) *Handler {
	t.Helper()
	logger := newQuietMCPLogger()
	adapter := backend.NewMCPAdapterFromEntries(
		[]backend.BackendEntry{{Name: mbBackend, Transport: "http", URL: host.ts.URL}},
		credentials.NewEmbeddedStore(), logger)
	t.Cleanup(adapter.Close)
	if err := adapter.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}

	cb := backend.NewCompositeBackend(map[string]backend.ToolBackend{})
	cb.AddPassthrough(adapter)
	exec := executor.New(nil, nil, cb, nil, nil, 5*time.Second, logger, nil, nil)
	h := NewHandler(exec, cb, nil, "", nil, logger, false)

	// The runner has served a script from the tool set of the start by the
	// time the backend changes its tools.
	if text, isErr := runScript(t, h, mbCallKept); isErr || !strings.Contains(text, mbKept+" ran") {
		t.Fatalf("baseline run = %q (error %v)", text, isErr)
	}
	return h
}

// checkMCPBackendCatalog waits until a script can call the tool the backend
// brought, and then checks the rest of the catalog: the tool the backend no
// longer has is gone from execute_code and from discover_tools, the new one
// is found by both. While it waits, scripts go on calling the tool the
// backend had all along, as the callers of a backend do.
func checkMCPBackendCatalog(t *testing.T, h *Handler) {
	t.Helper()
	waitFor(t, "execute_code to call the tool the backend added", func() bool {
		_, _, _ = execScript(h, mbCallKept)
		text, isErr, err := execScript(h, mbCallFresh)
		return err == nil && !isErr && strings.Contains(text, mbFresh+" ran")
	})

	if text, isErr := runScript(t, h, mbCallOld); !isErr || !strings.Contains(text, "no member '"+mbLiveOld+"'") {
		t.Errorf("call of the removed tool = %q (error %v), want it unknown to the sandbox", text, isErr)
	}
	if text, isErr := runScript(t, h, mbCallKept); isErr || !strings.Contains(text, mbKept+" ran") {
		t.Errorf("call of the kept tool = %q (error %v)", text, isErr)
	}
	if text, isErr := runScript(t, h, `return toolmesh.discover("`+mbFresh+`").map(t => t.name)`); isErr || !strings.Contains(text, mbLiveFresh) {
		t.Errorf("toolmesh.discover = %q (error %v), want it to find %s", text, isErr, mbLiveFresh)
	}

	listing := discoverText(t, h, map[string]any{argNamePattern: "^" + mbBackend + "_", argNameDetail: detailNames})
	if !strings.Contains(listing, mbLiveFresh) || !strings.Contains(listing, mbLiveKept) {
		t.Errorf("discover_tools lacks a tool of the backend:\n%s", listing)
	}
	if strings.Contains(listing, mbLiveOld) {
		t.Errorf("discover_tools still lists the removed tool:\n%s", listing)
	}
}

// An MCP backend adds a tool and removes one while ToolMesh runs. Without a
// restart of ToolMesh, the added tool is callable from execute_code and
// found by discover_tools, and the removed one is gone from both.
func TestExecuteCode_FollowsToolsAnMCPBackendAddsAndRemoves(t *testing.T) {
	server := mbServer(mbKept, mbOld)
	h := newMCPBackendHandler(t, newMBHost(t, server))

	mbAddTool(server, mbFresh)
	server.RemoveTools(mbOld)

	checkMCPBackendCatalog(t, h)
}

// An MCP backend restarts with another tool list. ToolMesh connects again,
// here as soon as a call needs the backend, and execute_code and
// discover_tools show the tools the backend has now.
func TestExecuteCode_FollowsMCPBackendRestart(t *testing.T) {
	host := newMBHost(t, mbServer(mbKept, mbOld))
	h := newMCPBackendHandler(t, host)

	host.restart(mbServer(mbKept, mbFresh))

	checkMCPBackendCatalog(t, h)
}
