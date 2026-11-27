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

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	// reloadHelperVar switches TestHelperReloadMCPServer from a skipped test
	// into the child process of a stdio backend. Its value is the directory
	// the child reports its start and its end to, as <pid>.start and
	// <pid>.stop.
	reloadHelperVar  = "TOOLMESH_TEST_RELOAD_MCP_DIR"
	reloadEventStart = "start"
	reloadEventStop  = "stop"

	reloadRelayWait = "relay_wait"
	reloadChildPing = "child_ping"
	reloadReleased  = "released"
	reloadPong      = "pong"
	reloadKeyType   = "type"
	reloadTypeObj   = "object"

	// Placeholders in the configurations below, replaced with the address
	// of the relay's server and the path of the test binary.
	reloadURL = "RELAY_URL"
	reloadExe = "EXE"

	// reloadMCPEntries are two MCP backends: "relay" over HTTP, whose tool
	// answers when the test lets it, and "child" over stdio, whose process is
	// TestHelperReloadMCPServer.
	reloadMCPEntries = `
  - name: relay
    transport: http
    url: 'RELAY_URL'
  - name: child
    transport: stdio
    command: 'EXE'
    args: ['-test.run=^TestHelperReloadMCPServer$']
`
	// reloadWithMCP is backends.yaml at startup of the tests below.
	reloadWithMCP = reloadStartup + reloadMCPEntries
	// reloadBeta adds a REST entry.
	reloadBeta = `
  - name: beta
    transport: rest
    dadl: api.dadl
`
	// reloadChildAsUnit loads a stdio backend under the name of the unit.
	reloadChildAsUnit = `
  - name: lone
    transport: stdio
    command: 'EXE'
    args: ['-test.run=^TestHelperReloadMCPServer$']
`

	// reloadQuiet is how long a test watches for an adapter being closed
	// too early: a close that does not wait for the running call happens
	// right after the reload.
	reloadQuiet = 200 * time.Millisecond
)

// TestHelperReloadMCPServer is the child process of the stdio backend in the
// reload tests: an MCP server with the tool "ping".
func TestHelperReloadMCPServer(t *testing.T) {
	dir := os.Getenv(reloadHelperVar)
	if dir == "" {
		t.Skip("child process of the reload tests")
	}
	report := func(event string) {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.%s", os.Getpid(), event)), nil, 0o600) //nolint:gosec // dir is the temp dir the parent test passed in
	}
	report(reloadEventStart)
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "reload-child", Version: "1.0.0"}, nil)
	server.AddTool(&mcpsdk.Tool{Name: "ping", Description: "Answers pong", InputSchema: map[string]any{reloadKeyType: reloadTypeObj}},
		func(context.Context, *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: reloadPong}}}, nil
		})
	_ = server.Run(context.Background(), &mcpsdk.StdioTransport{})
	report(reloadEventStop)
	os.Exit(0)
}

// runningChildren returns the number of stdio children reporting to dir
// that have started and not ended.
func runningChildren(t *testing.T, dir string) int {
	t.Helper()
	count := func(event string) int {
		files, err := filepath.Glob(filepath.Join(dir, "*."+event))
		if err != nil {
			t.Fatal(err)
		}
		return len(files)
	}
	return count(reloadEventStart) - count(reloadEventStop)
}

// waitUntil fails the test when cond does not hold within 20 seconds.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// relayServer is the MCP server of the backend "relay", over Streamable
// HTTP. Its tool "wait" answers once release is called, and counts the
// calls it receives.
type relayServer struct {
	url     string
	calls   atomic.Int32
	entered chan struct{}
	release func()
}

func newRelayServer(t *testing.T) *relayServer {
	t.Helper()
	released := make(chan struct{})
	var once sync.Once
	r := &relayServer{
		entered: make(chan struct{}, 8),
		release: func() { once.Do(func() { close(released) }) },
	}
	server := mcpsdk.NewServer(&mcpsdk.Implementation{Name: "reload-relay", Version: "1.0.0"}, nil)
	server.AddTool(&mcpsdk.Tool{Name: "wait", Description: "Answers once the test releases it", InputSchema: map[string]any{reloadKeyType: reloadTypeObj}},
		func(ctx context.Context, _ *mcpsdk.CallToolRequest) (*mcpsdk.CallToolResult, error) {
			r.calls.Add(1)
			select {
			case r.entered <- struct{}{}:
			default:
			}
			select {
			case <-released:
				return &mcpsdk.CallToolResult{Content: []mcpsdk.Content{&mcpsdk.TextContent{Text: reloadReleased}}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	srv := httptest.NewServer(mcpsdk.NewStreamableHTTPHandler(func(*http.Request) *mcpsdk.Server { return server }, nil))
	t.Cleanup(func() {
		r.release()
		srv.CloseClientConnections()
		srv.Close()
	})
	r.url = srv.URL
	return r
}

// callTool calls a tool through the composite, as the executor does, and
// returns the text of the result.
func callTool(s *reloadServer, tool string) (string, error) {
	res, err := s.composite.Execute(context.Background(), tool, map[string]any{})
	if err != nil {
		return "", err
	}
	var texts []string
	for _, c := range res.Content {
		if m, ok := c.(map[string]any); ok {
			if text, ok := m["text"].(string); ok {
				texts = append(texts, text)
			}
		}
	}
	text := strings.Join(texts, "\n")
	if res.IsError {
		return "", errors.New(text)
	}
	return text, nil
}

// startMCPReloadServer starts a server over startup, with the placeholders
// filled in, and returns it with the directory of its files.
func startMCPReloadServer(t *testing.T, relay *relayServer, startup string) (*reloadServer, func(config string), string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	reports := t.TempDir()
	t.Setenv(reloadHelperVar, reports)
	// Closing an HTTP session waits for the calls running on it. A test
	// that closes too early then hangs until the client gives up: let it
	// give up after seconds, not the default two minutes.
	t.Setenv("TOOLMESH_MCP_TIMEOUT", "10")
	dir := t.TempDir()
	writeConfig := func(config string) {
		config = strings.ReplaceAll(config, reloadURL, relay.url)
		writeReloadFiles(t, dir, map[string]string{reloadConfig: strings.ReplaceAll(config, reloadExe, exe)})
	}
	writeReloadFiles(t, dir, map[string]string{reloadDADL: testDADLContent})
	writeConfig(startup)
	writeReloadUnit(t, dir)
	return startReloadServer(t, dir), writeConfig, reports
}

// A reload opens new sessions to every MCP backend, for a stdio backend with
// a child process of its own. Once the reload has replaced them, the
// previous adapter is closed and its children end, but not before the calls
// running on it have returned: a call is neither cut off nor sent to the
// backend a second time. A reload that fails leaves the running adapter
// alone, and closes the sessions it opened itself. At shutdown the adapter
// in use is closed.
func TestBackendsReload_ClosesReplacedMCPAdapter(t *testing.T) {
	tests := []struct {
		name string
		// config is backends.yaml for the reload.
		config string
		// callRunning starts a call on the relay before the reload and lets
		// it answer only after the reload has returned.
		callRunning bool
		wantErr     string
		// wantChildren is the number of stdio children running once the
		// reload is done and the call has returned.
		wantChildren int
		// wantOldClosed says whether the adapter from startup is closed
		// then.
		wantOldClosed bool
	}{
		{
			name:          "entry added",
			config:        reloadWithMCP + reloadBeta,
			wantChildren:  1,
			wantOldClosed: true,
		},
		{
			name:          "entry added while a call runs",
			config:        reloadWithMCP + reloadBeta,
			callRunning:   true,
			wantChildren:  1,
			wantOldClosed: true,
		},
		{
			name:          "MCP entries removed",
			config:        reloadStartup,
			wantOldClosed: true,
		},
		{
			name:          "MCP entries removed while a call runs",
			config:        reloadStartup,
			callRunning:   true,
			wantOldClosed: true,
		},
		{
			name:         "file does not load while a call runs",
			config:       reloadWithMCP + "unknown_key: true\n",
			callRunning:  true,
			wantErr:      "parse backends config",
			wantChildren: 1,
		},
		{
			name:         "MCP entry takes the name of a unit while a call runs",
			config:       reloadWithMCP + reloadChildAsUnit,
			callRunning:  true,
			wantErr:      "running unit (" + reloadUnitName + ")",
			wantChildren: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			relay := newRelayServer(t)
			s, writeConfig, reports := startMCPReloadServer(t, relay, reloadWithMCP)
			old := s.reloader.currentAdapter()
			if err := old.Healthy(ctx); err != nil {
				t.Fatalf("MCP backends not connected at startup: %v", err)
			}
			if n := runningChildren(t, reports); n != 1 {
				t.Fatalf("%d stdio children run at startup, want 1", n)
			}

			type answer struct {
				text string
				err  error
			}
			answers := make(chan answer, 1)
			if tt.callRunning {
				go func() {
					text, err := callTool(s, reloadRelayWait)
					answers <- answer{text, err}
				}()
				<-relay.entered
			}

			writeConfig(tt.config)
			err := s.reloader.reload(ctx)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("reload error = %v, want one containing %q", err, tt.wantErr)
				}
				if s.reloader.currentAdapter() != old {
					t.Error("a failed reload replaced the adapter")
				}
			} else if err != nil {
				t.Fatalf("reload: %v", err)
			}

			if tt.callRunning {
				for deadline := time.Now().Add(reloadQuiet); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					if err := old.Healthy(ctx); err != nil {
						t.Fatalf("the adapter was closed while a call was running on it: %v", err)
					}
				}
				relay.release()
				a := <-answers
				if a.err != nil || a.text != reloadReleased {
					t.Errorf("the call running across the reload answered %q, %v; want %q", a.text, a.err, reloadReleased)
				}
				if n := relay.calls.Load(); n != 1 {
					t.Errorf("the relay received the call %d times, want once", n)
				}
			}
			relay.release()
			s.reloader.closing.Wait()

			if closed := old.Healthy(ctx) != nil; closed != tt.wantOldClosed {
				t.Errorf("adapter from startup closed = %v, want %v", closed, tt.wantOldClosed)
			}
			waitUntil(t, fmt.Sprintf("%d stdio child(ren) run", tt.wantChildren), func() bool {
				return runningChildren(t, reports) == tt.wantChildren
			})

			// The MCP backends the composite routes to now still answer.
			if tt.wantChildren > 0 {
				if text, err := callTool(s, reloadRelayWait); err != nil || text != reloadReleased {
					t.Errorf("relay after the reload answered %q, %v; want %q", text, err, reloadReleased)
				}
				if text, err := callTool(s, reloadChildPing); err != nil || text != reloadPong {
					t.Errorf("child after the reload answered %q, %v; want %q", text, err, reloadPong)
				}
			}

			current := s.reloader.currentAdapter()
			s.reloader.close()
			if s.reloader.currentAdapter() != nil {
				t.Error("close left a current adapter")
			}
			if tt.wantChildren > 0 && current.Healthy(ctx) == nil {
				t.Error("close did not close the adapter in use")
			}
			waitUntil(t, "every stdio child has ended", func() bool { return runningChildren(t, reports) == 0 })
		})
	}
}

// At shutdown, close ends the adapter in use and every replaced adapter that
// still waits for its calls, and the waits end with it.
func TestBackendsReloader_Close(t *testing.T) {
	ctx := context.Background()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	reports := t.TempDir()
	t.Setenv(reloadHelperVar, reports)
	newChild := func() *backend.MCPAdapter {
		a := backend.NewMCPAdapterFromEntries([]backend.BackendEntry{{
			Name:      "child",
			Transport: "stdio",
			Command:   exe,
			Args:      []string{"-test.run=^TestHelperReloadMCPServer$"},
		}}, credentials.NewEmbeddedStore(), quietLogger())
		t.Cleanup(a.Close)
		if err := a.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		if err := a.Healthy(ctx); err != nil {
			t.Fatalf("child not connected: %v", err)
		}
		return a
	}
	current, waiting := newChild(), newChild()
	r := &backendsReloader{adapter: current}
	r.mu.Lock()
	r.retireLocked(waiting, make(chan struct{})) // its calls never return
	r.mu.Unlock()

	r.close()
	r.closing.Wait()
	if current.Healthy(ctx) == nil {
		t.Error("close left the adapter in use open")
	}
	if waiting.Healthy(ctx) == nil {
		t.Error("close left the replaced adapter open")
	}
	waitUntil(t, "every stdio child has ended", func() bool { return runningChildren(t, reports) == 0 })
	r.close() // a second close does nothing
}

// A reload that finishes after close publishes nothing and closes what it
// built: a change of backends.yaml that lands during shutdown does not open
// new sessions.
func TestBackendsReload_AfterClose(t *testing.T) {
	relay := newRelayServer(t)
	s, writeConfig, reports := startMCPReloadServer(t, relay, reloadWithMCP)
	version := s.composite.ToolSetVersion()

	s.reloader.close()
	writeConfig(reloadWithMCP + reloadBeta)
	err := s.reloader.reload(context.Background())
	if err == nil || !strings.Contains(err.Error(), "shutting down") {
		t.Fatalf("reload after close: error = %v, want one saying ToolMesh is shutting down", err)
	}
	if s.composite.ToolSetVersion() != version {
		t.Error("a reload after close published a new tool set")
	}
	waitUntil(t, "every stdio child has ended", func() bool { return runningChildren(t, reports) == 0 })
}

// A wait for a replaced adapter takes it out of the bookkeeping once the
// calls have returned, so close does not close it a second time.
func TestBackendsReloader_RetiringEmptiesAfterDrain(t *testing.T) {
	r := &backendsReloader{}
	drained := make(chan struct{})
	a := backend.NewMCPAdapterFromEntries(nil, nil, quietLogger())
	r.mu.Lock()
	r.retireLocked(a, drained)
	if len(r.retiring) != 1 {
		t.Errorf("retiring holds %d adapter(s) while the calls run, want 1", len(r.retiring))
	}
	r.mu.Unlock()
	close(drained)
	r.closing.Wait()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.retiring) != 0 {
		t.Errorf("retiring holds %d adapter(s) after the calls returned, want 0", len(r.retiring))
	}
}
