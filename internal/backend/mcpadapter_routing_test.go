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
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Fixtures of the prefix routing tests: MCP backends of which one name is a
// prefix of the next, so that a tool name such as "a_b_x" starts with the
// prefix of more than one of them.
const (
	prShort  = "a"
	prLong   = "a_b"
	prLonger = "a_b_c"

	// Tools of the short backend. Prefixed with its name, the first three
	// fall into the namespace of the long backend: "a" + "_" + "b_x" is the
	// name of tool "x" of "a_b".
	prShortShadowedX      = "b_x"
	prShortShadowedOnly   = "b_only"
	prShortShadowedHidden = "b_hidden"
	prShortOwn            = "y"

	// Tools of the long backend. prLongHidden is offered by its server and
	// kept back by include_tools; prLongMissing is not offered at all.
	prLongX       = "x"
	prLongZ       = "z"
	prLongHidden  = "hidden"
	prLongMissing = "only"

	// prUnclaimed starts with the name of no backend.
	prUnclaimed = "other_x"

	// prRounds is how often a routing decision is repeated. Go starts every
	// walk over a map at a random entry, so a decision that depends on the
	// order shows up within a few rounds.
	prRounds = 200
)

// connectInMemoryMCP serves server on an in-memory transport and returns a
// client session to it, closed when the test ends.
func connectInMemoryMCP(t *testing.T, server *mcp.Server) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ct, st := mcp.NewInMemoryTransports()
	go server.Connect(ctx, st, nil) //nolint:errcheck // test server, failure surfaces as a client connect error

	client := mcp.NewClient(&mcp.Implementation{Name: "tm", Version: testVersion01}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect in-memory: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// prefixConn is a backend without a session whose tool list is set by hand.
// Every descriptor carries "<backend>/<tool>" as its description, so a
// lookup shows which backend answered.
func prefixConn(name string, tools ...string) *backendConn {
	conn := &backendConn{entry: BackendEntry{Name: name}}
	for _, tool := range tools {
		conn.tools = append(conn.tools, ToolDescriptor{Name: tool, Description: name + "/" + tool})
	}
	return conn
}

// TestMCPAdapter_LongestPrefixWins checks the routing decision itself. The
// tool lists are set by hand, so the shorter backends still hold the tools
// that a longer backend name shadows ("a" has "b_only", "a_b" has no
// "only"): a lookup that fell back to them would find a descriptor.
func TestMCPAdapter_LongestPrefixWins(t *testing.T) {
	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			prShort:  prefixConn(prShort, prShortShadowedX, prShortShadowedOnly, prShortOwn),
			prLong:   prefixConn(prLong, prLongX, prLongZ, "c_x", "c_only"),
			prLonger: prefixConn(prLonger, prLongX),
		},
		logger: slog.Default(),
	}

	tests := []struct {
		name        string
		tool        string
		wantBackend string // empty: no backend claims the name
		wantTool    string
		wantFound   bool
	}{
		{"two prefixes match, the longer has the tool", prLong + "_" + prLongX, prLong, prLongX, true},
		{"only tool of the longer backend", prLong + "_" + prLongZ, prLong, prLongZ, true},
		{"tool of the shorter backend", prShort + "_" + prShortOwn, prShort, prShortOwn, true},
		{"three prefixes match", prLonger + "_" + prLongX, prLonger, prLongX, true},
		{"the longer backend lacks the tool, the shorter has it", prLong + "_" + prLongMissing, prLong, prLongMissing, false},
		{"the longest backend lacks the tool, the middle one has it", prLonger + "_" + prLongMissing, prLonger, prLongMissing, false},
		{"a backend name without a tool part", prLong, prShort, "b", false},
		{"no backend", prUnclaimed, "", prUnclaimed, false},
		{"prefix without the separator", "ab_x", "", "ab_x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i := range prRounds {
				name, realTool, conn := adapter.matchBackend(tt.tool)
				if name != tt.wantBackend || realTool != tt.wantTool {
					t.Fatalf("round %d: matchBackend(%q) = %q, %q; want %q, %q",
						i, tt.tool, name, realTool, tt.wantBackend, tt.wantTool)
				}
				if (conn != nil) != (tt.wantBackend != "") {
					t.Fatalf("round %d: matchBackend(%q) connection = %v", i, tt.tool, conn)
				}
				if conn != nil && conn.entry.Name != tt.wantBackend {
					t.Fatalf("round %d: matchBackend(%q) returned the connection of %q", i, tt.tool, conn.entry.Name)
				}

				desc, found := adapter.LookupTool(tt.tool)
				if found != tt.wantFound {
					t.Fatalf("round %d: LookupTool(%q) found = %v, want %v (descriptor %+v)",
						i, tt.tool, found, tt.wantFound, desc)
				}
				if !found {
					continue
				}
				if desc.Name != tt.tool || desc.Backend != "mcp:"+tt.wantBackend ||
					desc.Description != tt.wantBackend+"/"+tt.wantTool {
					t.Fatalf("round %d: LookupTool(%q) = %+v, want tool %q of backend %q",
						i, tt.tool, desc, tt.wantTool, tt.wantBackend)
				}
			}
		})
	}
}

// callLog counts how often the tool handlers of the routing fixtures ran,
// keyed "<backend>/<tool>".
type callLog struct {
	mu   sync.Mutex
	runs map[string]int
}

func (l *callLog) add(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.runs[key]++
}

// prefixFixture is one backend of newPrefixRoutingAdapter: its entry and the
// tools its MCP server offers.
type prefixFixture struct {
	entry BackendEntry
	tools []string
}

// prefixFixtures are the two backends the Execute and discovery tests share:
// "a" promotes one shadowed and one reachable tool, "a_b" offers three tools
// and exposes those include_tools names, all of them when it is nil.
func prefixFixtures(includeTools []string) []prefixFixture {
	return []prefixFixture{
		{
			entry: BackendEntry{Name: prShort, ExposeTools: []string{prShortShadowedX, prShortOwn}},
			tools: []string{prShortShadowedX, prShortShadowedOnly, prShortShadowedHidden, prShortOwn},
		},
		{
			entry: BackendEntry{Name: prLong, IncludeTools: includeTools},
			tools: []string{prLongX, prLongZ, prLongHidden},
		},
	}
}

// newPrefixRoutingAdapter wires an MCPAdapter to one in-memory MCP server per
// fixture, with discovery run. Every tool answers "<backend>/<tool>" and is
// counted in the returned log, so a test sees which backend ran a call.
func newPrefixRoutingAdapter(t *testing.T, logger *slog.Logger, fixtures []prefixFixture) (*MCPAdapter, *callLog) {
	t.Helper()
	calls := &callLog{runs: make(map[string]int)}
	adapter := &MCPAdapter{
		backends: make(map[string]*backendConn, len(fixtures)),
		creds:    credentials.NewEmbeddedStore(),
		logger:   logger,
	}
	for _, f := range fixtures {
		server := mcp.NewServer(&mcp.Implementation{Name: f.entry.Name, Version: testVersion01}, nil)
		for _, tool := range f.tools {
			ran := f.entry.Name + "/" + tool
			server.AddTool(
				&mcp.Tool{Name: tool, Description: ran, InputSchema: map[string]any{schemaKeyType: schemaTypeObject}},
				func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					calls.add(ran)
					return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: ran}}}, nil
				},
			)
		}
		adapter.backends[f.entry.Name] = &backendConn{
			entry:   f.entry,
			session: connectInMemoryMCP(t, server),
			include: buildMCPIncludeSet(f.entry.IncludeTools),
		}
	}
	// As in Connect, discovery runs with every backend registered: which
	// tools a backend keeps depends on the names of the others.
	for name, conn := range adapter.backends {
		if err := adapter.discoverTools(context.Background(), name, conn); err != nil {
			t.Fatalf("discover tools of %q: %v", name, err)
		}
	}
	return adapter, calls
}

// TestMCPAdapter_Execute_LongestPrefixWins runs calls against two live
// backends "a" and "a_b". A call named "a_b_<tool>" belongs to "a_b" on
// every round, also where "a_b" refuses it and "a" offers a tool of that
// name: the call fails and "a" never sees it. With include_tools on "a_b",
// that list decides, and a tool it keeps back is not reachable through "a"
// either.
func TestMCPAdapter_Execute_LongestPrefixWins(t *testing.T) {
	tests := []struct {
		name         string
		includeTools []string // include_tools of "a_b"
		tool         string
		wantRan      string // "<backend>/<tool>" of the handler that must answer
		wantErr      string // part of the error when the call must fail
	}{
		{name: "two prefixes match", tool: prLong + "_" + prLongX, wantRan: prLong + "/" + prLongX},
		{name: "only tool of the longer backend", tool: prLong + "_" + prLongZ, wantRan: prLong + "/" + prLongZ},
		{name: "tool of the shorter backend", tool: prShort + "_" + prShortOwn, wantRan: prShort + "/" + prShortOwn},
		{
			name:    "the longer backend lacks the tool, the shorter has it",
			tool:    prLong + "_" + prLongMissing,
			wantErr: "call tool " + prLongMissing + " on backend " + prLong,
		},
		{name: "no backend", tool: prUnclaimed, wantErr: "no backend found"},
		{
			name:         "include_tools of the longer backend admits the tool",
			includeTools: []string{prLongX},
			tool:         prLong + "_" + prLongX,
			wantRan:      prLong + "/" + prLongX,
		},
		{
			name:         "include_tools of the longer backend keeps the tool back, the shorter has it",
			includeTools: []string{prLongX},
			tool:         prLong + "_" + prLongHidden,
			wantErr:      `tool "hidden" not found in MCP backend "a_b"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, calls := newPrefixRoutingAdapter(t, slog.Default(), prefixFixtures(tt.includeTools))
			ctx := context.Background()

			for i := range prRounds {
				result, err := adapter.Execute(ctx, tt.tool, nil)
				if tt.wantErr != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
						t.Fatalf("round %d: Execute(%q) = %+v, %v; want an error containing %q",
							i, tt.tool, result, err, tt.wantErr)
					}
					continue
				}
				if err != nil {
					t.Fatalf("round %d: Execute(%q): %v", i, tt.tool, err)
				}
				text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
				if text != tt.wantRan {
					t.Fatalf("round %d: Execute(%q) was answered by %q, want %q", i, tt.tool, text, tt.wantRan)
				}
				wantBackend, _, _ := strings.Cut(tt.wantRan, "/")
				if got := result.Metadata[metadataKeyBackend]; got != wantBackend {
					t.Fatalf("round %d: Execute(%q) reports backend %v, want %q", i, tt.tool, got, wantBackend)
				}
			}

			// Only the handler the case names may have run, on every round;
			// a failing call reaches no handler at all.
			calls.mu.Lock()
			defer calls.mu.Unlock()
			for key, n := range calls.runs {
				if key != tt.wantRan {
					t.Errorf("handler %s ran %d times, want 0", key, n)
				}
			}
			if tt.wantRan != "" && calls.runs[tt.wantRan] != prRounds {
				t.Errorf("handler %s ran %d times, want %d", tt.wantRan, calls.runs[tt.wantRan], prRounds)
			}
		})
	}
}

// TestMCPAdapter_Discovery_DropsShadowedTools: a tool that can never be
// called, because a longer backend name claims its prefixed name, is neither
// listed nor promoted, and the log says why. Otherwise "a_b_x" would be
// listed twice, and the bare name "b_x" promoted from "a" would run tool "x"
// of "a_b".
func TestMCPAdapter_Discovery_DropsShadowedTools(t *testing.T) {
	var logs bytes.Buffer
	adapter, _ := newPrefixRoutingAdapter(t, slog.New(slog.NewTextHandler(&logs, nil)),
		prefixFixtures([]string{prLongX, prLongZ}))

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	listed := make(map[string]int, len(tools))
	for _, tool := range tools {
		listed[tool.Name]++
	}
	want := []string{prLong + "_" + prLongX, prLong + "_" + prLongZ, prShort + "_" + prShortOwn}
	if len(tools) != len(want) {
		t.Errorf("listed %d tools, want %d: %v", len(tools), len(want), listed)
	}
	for _, name := range want {
		if listed[name] != 1 {
			t.Errorf("tool %q listed %d times, want once: %v", name, listed[name], listed)
		}
	}
	// What is listed is what a lookup finds, with the descriptor of the
	// backend that runs the call.
	for _, tool := range tools {
		desc, found := adapter.LookupTool(tool.Name)
		if !found || desc.Backend != tool.Backend || desc.Description != tool.Description {
			t.Errorf("LookupTool(%q) = %+v, %v; listed as %+v", tool.Name, desc, found, tool)
		}
	}

	promoted := adapter.PromotedTools()
	if len(promoted) != 1 || promoted[0].Descriptor.Name != prShortOwn || promoted[0].Canonical != prShort+"_"+prShortOwn {
		t.Errorf("promoted = %+v, want only %q of backend %q", promoted, prShortOwn, prShort)
	}

	for _, tool := range []string{prShortShadowedX, prShortShadowedOnly, prShortShadowedHidden} {
		if !strings.Contains(logs.String(), "tool="+tool+" ") {
			t.Errorf("no warning for the shadowed tool %q:\n%s", tool, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "tool is not reachable") {
		t.Errorf("the log does not say why the tools are dropped:\n%s", logs.String())
	}
}
