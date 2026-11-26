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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	rfLive  = "live"
	rfOther = "steady"

	rfFirst  = "first"
	rfSecond = "second"
	rfThird  = "third"

	rfLiveFirst  = rfLive + "_" + rfFirst
	rfLiveSecond = rfLive + "_" + rfSecond
	rfLiveThird  = rfLive + "_" + rfThird

	// rfChangedLine is the log line of a reading that found another list.
	rfChangedLine = "backend tool list changed"

	rfStateful  = "server with sessions"
	rfStateless = "stateless server"
)

// rfLogs collects the log of an adapter whose watchers write while the test
// reads.
type rfLogs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *rfLogs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *rfLogs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// rfServer builds an MCP server with the SDK that offers the named tools.
func rfServer(opts *mcp.ServerOptions, tools ...string) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "rf", Version: testVersion01}, opts)
	for _, name := range tools {
		rfAddTool(server, name, "runs "+name)
	}
	return server
}

// rfAddTool adds a tool that answers "<name> ran". Adding a name again
// replaces the tool, which is how a test changes a description.
func rfAddTool(server *mcp.Server, name, description string) {
	server.AddTool(
		&mcp.Tool{Name: name, Description: description, InputSchema: map[string]any{schemaKeyType: schemaTypeObject}},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: name + " ran"}}}, nil
		},
	)
}

// rfSilent are the options of a server that does not say when its tool list
// changes.
func rfSilent() *mcp.ServerOptions {
	return &mcp.ServerOptions{Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{ListChanged: false}}}
}

// rfHost serves an MCP server over Streamable HTTP at one URL. The server
// behind the URL can be replaced, which is what a restart of a backend looks
// like from outside, and the host can be down.
type rfHost struct {
	ts        *httptest.Server
	stateless bool
	handler   atomic.Pointer[http.Handler]
	down      atomic.Bool
	// lists counts the tools/list requests of all servers the host served.
	lists atomic.Int64
}

func newRFHost(t *testing.T, stateless bool, server *mcp.Server) *rfHost {
	t.Helper()
	h := &rfHost{stateless: stateless}
	h.serve(server)
	h.ts = httptest.NewServer(h)
	t.Cleanup(h.ts.Close)
	return h
}

func (h *rfHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.down.Load() {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	(*h.handler.Load()).ServeHTTP(w, r)
}

// serve puts server behind the URL.
func (h *rfHost) serve(server *mcp.Server) {
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == testMethodToolsList {
				h.lists.Add(1)
			}
			return next(ctx, method, req)
		}
	})
	var handler http.Handler = mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: h.stateless},
	)
	h.handler.Store(&handler)
}

// restart replaces the server and cuts every connection to the old one.
func (h *rfHost) restart(server *mcp.Server) {
	h.serve(server)
	h.ts.CloseClientConnections()
}

func (h *rfHost) entry(name string) BackendEntry {
	return BackendEntry{Name: name, Transport: transportTypeHTTP, URL: h.ts.URL}
}

// rfPace is the timing the tests run the background work at: no periodic
// reading unless a test asks for one.
func rfPace() mcpPace {
	return mcpPace{
		minGap:   20 * time.Millisecond,
		list:     5 * time.Second,
		retryMin: 20 * time.Millisecond,
		retryMax: 100 * time.Millisecond,
	}
}

// rfTracked is an adapter under test with what the tests read from it.
type rfTracked struct {
	*MCPAdapter
	logs *rfLogs
	// changes counts the calls of the function set with OnToolSetChange.
	changes atomic.Int64
}

// rfAdapter builds an adapter for the entries, not yet connected.
func rfAdapter(t *testing.T, pace mcpPace, entries ...BackendEntry) *rfTracked {
	t.Helper()
	tr := &rfTracked{logs: &rfLogs{}}
	tr.MCPAdapter = NewMCPAdapterFromEntries(entries, credentials.NewEmbeddedStore(),
		slog.New(slog.NewTextHandler(tr.logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	tr.pace = &pace
	tr.OnToolSetChange(func() { tr.changes.Add(1) })
	t.Cleanup(tr.Close)
	return tr
}

// rfConnected builds an adapter and connects it.
func rfConnected(t *testing.T, pace mcpPace, entries ...BackendEntry) *rfTracked {
	t.Helper()
	tr := rfAdapter(t, pace, entries...)
	if err := tr.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return tr
}

// toolNames returns the names the adapter lists, in ascending order.
func (tr *rfTracked) toolNames() []string {
	tools, _ := tr.ListTools(context.Background())
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// lists reports whether the adapter lists exactly the given names.
func (tr *rfTracked) lists(want ...string) bool {
	slices.Sort(want)
	return slices.Equal(tr.toolNames(), want)
}

// rfEventually fails the test when cond does not hold within ten seconds.
func rfEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// rfGenerations runs a test against a server of each generation of the
// protocol: one that keeps sessions and one of the stateless revision.
func rfGenerations(t *testing.T, run func(t *testing.T, stateless bool)) {
	t.Helper()
	for _, g := range []struct {
		name      string
		stateless bool
	}{{rfStateful, false}, {rfStateless, true}} {
		t.Run(g.name, func(t *testing.T) { run(t, g.stateless) })
	}
}

// A backend adds a tool and removes one while it runs and says so. The
// adapter lists the new tool and no longer the removed one, a call reaches
// the new tool, the change is logged by name and whoever follows the tool
// set is told, all without a reconnect.
func TestMCPAdapter_ToolListFollowsNotification(t *testing.T) {
	rfGenerations(t, func(t *testing.T, stateless bool) {
		server := rfServer(nil, rfFirst, rfSecond)
		host := newRFHost(t, stateless, server)
		tr := rfConnected(t, rfPace(), host.entry(rfLive))
		if !tr.lists(rfLiveFirst, rfLiveSecond) {
			t.Fatalf("tools after connect = %v", tr.toolNames())
		}
		session := tr.currentSession(tr.backends[rfLive])
		before := tr.changes.Load()

		rfAddTool(server, rfThird, "runs "+rfThird)
		server.RemoveTools(rfSecond)
		rfEventually(t, "the adapter lists the added tool and not the removed one", func() bool {
			return tr.lists(rfLiveFirst, rfLiveThird)
		})

		result, err := tr.Execute(context.Background(), rfLiveThird, map[string]any{})
		if err != nil || result.IsError {
			t.Fatalf("call of the added tool: %v %+v", err, result)
		}
		if _, found := tr.LookupTool(rfLiveSecond); found {
			t.Error("the removed tool is still found")
		}
		if tr.changes.Load() == before {
			t.Error("the change was not reported to the follower of the tool set")
		}
		if got := tr.currentSession(tr.backends[rfLive]); got != session {
			t.Error("the backend was connected again; the list should have been read over the session it had")
		}
		logs := tr.logs.String()
		for _, want := range []string{rfChangedLine, "added=[" + rfThird + "]", "removed=[" + rfSecond + "]"} {
			if !strings.Contains(logs, want) {
				t.Errorf("log lacks %q:\n%s", want, logs)
			}
		}
	})
}

// The notification of a stdio backend arrives on the pipe of its process and
// has the list read again as well.
func TestMCPAdapter_ToolListFollowsNotificationOverStdio(t *testing.T) {
	adapter := helperStdioAdapter(t, mcpHelperChanging, io.Discard)
	pace := rfPace()
	adapter.pace = &pace
	if err := adapter.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	listed := func() []string {
		tools, _ := adapter.ListTools(context.Background())
		names := make([]string, 0, len(tools))
		for _, tool := range tools {
			names = append(names, tool.Name)
		}
		return names
	}
	query := testBackendNameTest + "_" + testToolQuery
	if got := listed(); !slices.Equal(got, []string{query}) {
		t.Fatalf("tools after connect = %v", got)
	}

	// The helper gets its second tool with the first call.
	if result, err := adapter.Execute(context.Background(), query, map[string]any{}); err != nil || result.IsError {
		t.Fatalf("call: %v %+v", err, result)
	}
	rfEventually(t, "the adapter lists the tool the backend announced", func() bool {
		return slices.Contains(listed(), testBackendNameTest+"_"+testToolAsk)
	})
}

// A tool that keeps its name and gets another description is a change as
// well, and is logged as one: what a model reads about a tool is part of
// what the backend offers.
func TestMCPAdapter_ChangedDescriptionIsReported(t *testing.T) {
	server := rfServer(nil, rfFirst)
	host := newRFHost(t, false, server)
	tr := rfConnected(t, rfPace(), host.entry(rfLive))
	before := tr.changes.Load()

	const rewritten = "does something else now"
	rfAddTool(server, rfFirst, rewritten)
	rfEventually(t, "the adapter lists the new description", func() bool {
		d, found := tr.LookupTool(rfLiveFirst)
		return found && d.Description == rewritten
	})
	rfEventually(t, "the change is reported", func() bool { return tr.changes.Load() > before })
	if logs := tr.logs.String(); !strings.Contains(logs, "changed=["+rfFirst+"]") {
		t.Errorf("log does not name the changed tool:\n%s", logs)
	}
}

// Not every change is announced. A server that sends no notification, and a
// server of the stateless revision that was restarted, are caught by the
// periodic reading.
func TestMCPAdapter_ToolListFollowsPeriodicReading(t *testing.T) {
	pace := rfPace()
	pace.refresh = 30 * time.Millisecond

	t.Run("server that sends no notification", func(t *testing.T) {
		server := rfServer(rfSilent(), rfFirst)
		host := newRFHost(t, false, server)
		tr := rfConnected(t, pace, host.entry(rfLive))

		rfAddTool(server, rfSecond, "runs "+rfSecond)
		rfEventually(t, "the adapter lists the added tool", func() bool {
			return tr.lists(rfLiveFirst, rfLiveSecond)
		})
	})

	t.Run("stateless server restarted with another list", func(t *testing.T) {
		host := newRFHost(t, true, rfServer(rfSilent(), rfFirst, rfSecond))
		tr := rfConnected(t, pace, host.entry(rfLive))

		host.restart(rfServer(rfSilent(), rfFirst, rfThird))
		rfEventually(t, "the adapter lists the tools of the restarted server", func() bool {
			return tr.lists(rfLiveFirst, rfLiveThird)
		})
	})
}

// A reading that finds the list as it was says nothing and reports no
// change, so that the periodic reading costs a listing and nothing more.
func TestMCPAdapter_UnchangedListIsNoChange(t *testing.T) {
	pace := rfPace()
	pace.refresh = 10 * time.Millisecond
	host := newRFHost(t, true, rfServer(rfSilent(), rfFirst))
	tr := rfConnected(t, pace, host.entry(rfLive))
	before := tr.changes.Load()

	listed := host.lists.Load()
	rfEventually(t, "the list has been read several times more", func() bool {
		return host.lists.Load() >= listed+5
	})
	if got := tr.changes.Load(); got != before {
		t.Errorf("changes reported = %d, want none", got-before)
	}
	if logs := tr.logs.String(); strings.Contains(logs, rfChangedLine) {
		t.Errorf("an unchanged list was logged as changed:\n%s", logs)
	}
}

// A backend with sessions that restarts with another tool list no longer
// knows the session. The adapter connects again on its own, without a call
// having to fail first, and lists what the backend offers now. A call made
// right after the restart reaches the new server as well.
func TestMCPAdapter_BackendRestartsWithAnotherToolList(t *testing.T) {
	host := newRFHost(t, false, rfServer(nil, rfFirst, rfSecond))
	tr := rfConnected(t, rfPace(), host.entry(rfLive))
	before := tr.currentSession(tr.backends[rfLive])

	host.restart(rfServer(nil, rfFirst, rfThird))

	result, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{})
	if err != nil || result.IsError {
		t.Fatalf("call after the restart: %v %+v", err, result)
	}
	rfEventually(t, "the adapter lists the tools of the restarted backend", func() bool {
		return tr.lists(rfLiveFirst, rfLiveThird)
	})
	if got := tr.currentSession(tr.backends[rfLive]); got == nil || got == before {
		t.Error("the backend was not connected again")
	}
	if result, err := tr.Execute(context.Background(), rfLiveThird, map[string]any{}); err != nil || result.IsError {
		t.Fatalf("call of the tool the restart brought: %v %+v", err, result)
	}
}

// The same restart with nobody calling: the lost session alone has the
// adapter connect again.
func TestMCPAdapter_ReconnectsWithoutACall(t *testing.T) {
	host := newRFHost(t, false, rfServer(nil, rfFirst))
	tr := rfConnected(t, rfPace(), host.entry(rfLive))

	host.restart(rfServer(nil, rfThird))
	rfEventually(t, "the adapter lists the tools of the restarted backend", func() bool {
		return tr.lists(rfLiveThird)
	})
}

// A backend that is down when ToolMesh starts is connected once it is up.
func TestMCPAdapter_ConnectsBackendThatWasDownAtStart(t *testing.T) {
	rfGenerations(t, func(t *testing.T, stateless bool) {
		host := newRFHost(t, stateless, rfServer(nil, rfFirst))
		host.down.Store(true)
		tr := rfConnected(t, rfPace(), host.entry(rfLive))
		if tr.currentSession(tr.backends[rfLive]) != nil {
			t.Fatal("the backend is connected although it is down")
		}
		if len(tr.toolNames()) != 0 {
			t.Fatalf("tools of a backend that is down: %v", tr.toolNames())
		}

		// A few attempts fail before the backend comes up.
		rfEventually(t, "the adapter has tried again", func() bool {
			return strings.Count(tr.logs.String(), "trying again later") >= 2
		})
		host.down.Store(false)

		rfEventually(t, "the adapter lists the tools of the backend", func() bool {
			return tr.lists(rfLiveFirst)
		})
		if tr.changes.Load() == 0 {
			t.Error("the tools of the backend were not reported to the follower of the tool set")
		}
		if result, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{}); err != nil || result.IsError {
			t.Fatalf("call: %v %+v", err, result)
		}
	})
}

// A backend decides how often it says that its list has changed, not how
// often ToolMesh reads it: however many notifications arrive, the list is
// read once per gap.
func TestMCPAdapter_NotificationsDoNotSetThePace(t *testing.T) {
	pace := rfPace()
	pace.minGap = 200 * time.Millisecond
	server := rfServer(nil, rfFirst)
	host := newRFHost(t, false, server)
	tr := rfConnected(t, pace, host.entry(rfLive))
	afterConnect := host.lists.Load()

	// The server sends a notification about every 10ms for a second.
	const flood = time.Second
	start := time.Now()
	for i := 0; time.Since(start) < flood; i++ {
		if i%2 == 0 {
			rfAddTool(server, rfSecond, "runs "+rfSecond)
		} else {
			server.RemoveTools(rfSecond)
		}
		time.Sleep(15 * time.Millisecond)
	}
	elapsed := time.Since(start)

	// One reading at once, then one per gap, and one more for the reading
	// that the last notice may still have coming.
	allowed := int64(elapsed/pace.minGap) + 2
	if got := host.lists.Load() - afterConnect; got > allowed {
		t.Errorf("the list was read %d times in %s, more than the %d the gap of %s allows", got, elapsed, allowed, pace.minGap)
	}
	if got := host.lists.Load() - afterConnect; got == 0 {
		t.Error("the list was not read at all")
	}
	if tr.currentSession(tr.backends[rfLive]) == nil {
		t.Error("the backend lost its session")
	}
}

// Every reading goes through the checks of the first one: a tool that
// include_tools does not admit stays hidden and cannot be called when the
// backend adds it later, and a tool whose name is routed to another backend
// is left out.
func TestMCPAdapter_LaterReadingsRunTheStartupChecks(t *testing.T) {
	const (
		short     = "git"
		long      = "git_hub"
		admitted  = "status"
		later     = "push"
		shadowed  = "hub_search"
		longsTool = "search"
	)
	shortServer := rfServer(nil, admitted)
	shortHost := newRFHost(t, false, shortServer)
	longHost := newRFHost(t, false, rfServer(nil, longsTool))

	restricted := shortHost.entry(short)
	restricted.IncludeTools = []string{admitted, later, shadowed}
	restricted.ExposeTools = []string{later}
	tr := rfConnected(t, rfPace(), restricted, longHost.entry(long))

	// The backend adds a tool the operator admitted, one the operator did
	// not, and one whose prefixed name belongs to the other backend.
	const hidden = "delete_repository"
	rfAddTool(shortServer, later, "runs "+later)
	rfAddTool(shortServer, hidden, "runs "+hidden)
	rfAddTool(shortServer, shadowed, "runs "+shadowed)
	rfEventually(t, "the adapter lists the admitted tool", func() bool {
		return slices.Contains(tr.toolNames(), short+"_"+later)
	})

	if !tr.lists(short+"_"+admitted, short+"_"+later, long+"_"+longsTool) {
		t.Errorf("tools = %v; the hidden and the shadowed tool must stay out", tr.toolNames())
	}
	if _, err := tr.Execute(context.Background(), short+"_"+hidden, map[string]any{}); err == nil {
		t.Error("a tool that include_tools does not admit was called")
	}
	// The promotion the operator configured for a tool the backend did not
	// offer at startup takes effect once the backend offers it.
	promoted := tr.PromotedTools()
	if len(promoted) != 1 || promoted[0].Canonical != short+"_"+later {
		t.Errorf("promoted tools = %+v", promoted)
	}
	if logs := tr.logs.String(); !strings.Contains(logs, "routed to another backend") {
		t.Errorf("the shadowed tool was not reported:\n%s", logs)
	}
}

// While one backend takes its time to answer a listing, calls to another
// backend and the listing of all tools go on.
func TestMCPAdapter_SlowBackendHoldsUpNothingElse(t *testing.T) {
	slow := rfServer(nil, rfFirst)
	var listings atomic.Int64
	release := make(chan struct{})
	slow.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			// The listing at connect is answered, every later one waits.
			if method == testMethodToolsList && listings.Add(1) > 1 {
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			return next(ctx, method, req)
		}
	})
	slowHost := newRFHost(t, false, slow)
	steadyHost := newRFHost(t, false, rfServer(nil, rfFirst))
	tr := rfConnected(t, rfPace(), slowHost.entry(rfLive), steadyHost.entry(rfOther))
	defer close(release)

	rfAddTool(slow, rfSecond, "runs "+rfSecond)
	rfEventually(t, "the slow backend is asked for its list again", func() bool { return listings.Load() > 1 })

	done := make(chan error, 1)
	go func() {
		if tools, err := tr.ListTools(context.Background()); err != nil || len(tools) == 0 {
			done <- err
			return
		}
		// The slow backend itself still takes calls: only its listing waits.
		for _, tool := range []string{rfOther + "_" + rfFirst, rfLiveFirst} {
			result, err := tr.Execute(context.Background(), tool, map[string]any{})
			if err != nil || result.IsError {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("call while a backend is slow: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a listing that one backend has not answered held up the others")
	}
}

// Close ends the background work, also while a backend is being connected,
// and nothing is connected afterwards.
func TestMCPAdapter_CloseEndsBackgroundWork(t *testing.T) {
	// A backend that accepts the request and never answers it.
	hang := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}))
	defer silent.Close()
	defer close(hang)
	host := newRFHost(t, false, rfServer(nil, rfFirst))

	tr := rfAdapter(t, rfPace(), host.entry(rfLive),
		BackendEntry{Name: rfOther, Transport: transportTypeHTTP, URL: silent.URL})
	connected := make(chan struct{})
	go func() {
		_ = tr.Connect(context.Background())
		close(connected)
	}()
	rfEventually(t, "the reachable backend is connected", func() bool { return tr.lists(rfLiveFirst) })

	closed := make(chan struct{})
	go func() {
		tr.Close()
		close(closed)
	}()
	// The attempt in progress is given up well before the 15 seconds a
	// handshake may take; the SDK takes a few seconds of its own to let go
	// of a connection whose peer says nothing.
	for _, step := range []struct {
		what   string
		done   <-chan struct{}
		within time.Duration
	}{{"Close", closed, 5 * time.Second}, {"Connect", connected, 10 * time.Second}} {
		select {
		case <-step.done:
		case <-time.After(step.within):
			t.Fatalf("%s did not return while a backend left a connect unanswered:\n%s", step.what, tr.logs.String())
		}
	}

	if err := tr.connectBackend(context.Background(), rfLive, tr.backends[rfLive]); err == nil {
		t.Error("a backend was connected after Close")
	}
	if tr.currentSession(tr.backends[rfLive]) != nil {
		t.Error("a session is left after Close")
	}
	if _, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{}); err == nil {
		t.Error("a call ran on a closed adapter")
	}
	tr.Close() // a second Close is harmless
}

// Several calls that fail on one lost connection open one new connection.
func TestMCPAdapter_OneReconnectForManyFailedCalls(t *testing.T) {
	host := newRFHost(t, false, rfServer(nil, rfFirst))
	// The watcher would reconnect on its own; this test is about the calls.
	tr := rfAdapter(t, rfPace(), host.entry(rfLive))
	conn := tr.backends[rfLive]
	if err := tr.connectBackend(context.Background(), rfLive, conn); err != nil {
		t.Fatal(err)
	}
	lost := tr.currentSession(conn)
	host.restart(rfServer(nil, rfFirst))

	const callers = 8
	sessions := make([]*mcp.ClientSession, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Go(func() {
			session, err := tr.reconnectAfter(context.Background(), rfLive, conn, lost)
			if err != nil {
				t.Errorf("reconnect: %v", err)
			}
			sessions[i] = session
		})
	}
	wg.Wait()
	for _, session := range sessions {
		if session == nil || session == lost || session != sessions[0] {
			t.Fatalf("the callers did not end up on one new session: %v", sessions)
		}
	}
	if got := strings.Count(tr.logs.String(), `msg="connected to backend"`); got != 2 {
		t.Errorf("the backend was connected %d times, want 2: once at the start and once after the loss", got)
	}
}

// The URL of a backend can carry a credential in its query string. A log
// line about a failed connect names the host and leaves the query out.
func TestMCPAdapter_ConnectErrorLogLeavesTheQueryOut(t *testing.T) {
	const marker = "plain-words-in-the-query"
	closed := httptest.NewServer(http.NotFoundHandler())
	url := closed.URL + "/mcp?api_key=" + marker
	closed.Close()

	tr := rfConnected(t, rfPace(), BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: url})
	rfEventually(t, "a later attempt has failed as well", func() bool {
		return strings.Contains(tr.logs.String(), "trying again later")
	})
	tr.Close()

	logs := tr.logs.String()
	if !strings.Contains(logs, "failed to connect backend") {
		t.Fatalf("the failed connect was not logged:\n%s", logs)
	}
	if strings.Contains(logs, marker) {
		t.Errorf("the log carries the query of the backend URL:\n%s", logs)
	}
}

// A stdio backend that is connected again while a call waits for it keeps
// running when that call has ended: its child is not tied to the call.
func TestMCPAdapter_StdioChildOutlivesTheCallThatConnectedIt(t *testing.T) {
	adapter := helperStdioAdapter(t, mcpHelperClosing, io.Discard)
	pace := rfPace()
	adapter.pace = &pace
	conn := adapter.backends[testBackendNameTest]

	callCtx, endCall := context.WithCancel(context.Background())
	if err := adapter.connectBackend(callCtx, testBackendNameTest, conn); err != nil {
		t.Fatal(err)
	}
	session := adapter.currentSession(conn)
	endCall()

	// A child tied to the call would be gone by now, and the call below
	// would find the connection closed and open another.
	time.Sleep(300 * time.Millisecond)
	result, err := adapter.Execute(context.Background(), testBackendNameTest+"_"+testToolQuery, map[string]any{})
	if err != nil || result.IsError {
		t.Fatalf("call after the connecting call ended: %v %+v", err, result)
	}
	if adapter.currentSession(conn) != session {
		t.Error("the backend had to be connected again")
	}
}

func TestDiffTools(t *testing.T) {
	tool := func(name, description string, schema map[string]any) ToolDescriptor {
		return ToolDescriptor{Name: name, Description: description, InputSchema: schema}
	}
	object := func() map[string]any { return map[string]any{schemaKeyType: schemaTypeObject} }
	withParam := map[string]any{schemaKeyType: schemaTypeObject, schemaKeyProperties: map[string]any{"q": object()}}

	tests := []struct {
		name          string
		before, after []ToolDescriptor
		want          toolListChange
	}{
		{name: "both empty"},
		{
			name:  "first list",
			after: []ToolDescriptor{tool(rfSecond, "", nil), tool(rfFirst, "", nil)},
			want:  toolListChange{added: []string{rfFirst, rfSecond}},
		},
		{
			name:   "same tools in another order",
			before: []ToolDescriptor{tool(rfFirst, "a", object()), tool(rfSecond, "b", object())},
			after:  []ToolDescriptor{tool(rfSecond, "b", object()), tool(rfFirst, "a", object())},
		},
		{
			name:   "added, removed and kept",
			before: []ToolDescriptor{tool(rfFirst, "a", object()), tool(rfSecond, "b", object())},
			after:  []ToolDescriptor{tool(rfFirst, "a", object()), tool(rfThird, "c", object())},
			want:   toolListChange{added: []string{rfThird}, removed: []string{rfSecond}},
		},
		{
			name:   "another description",
			before: []ToolDescriptor{tool(rfFirst, "a", object())},
			after:  []ToolDescriptor{tool(rfFirst, "b", object())},
			want:   toolListChange{changed: []string{rfFirst}},
		},
		{
			name:   "another schema",
			before: []ToolDescriptor{tool(rfFirst, "a", object())},
			after:  []ToolDescriptor{tool(rfFirst, "a", withParam)},
			want:   toolListChange{changed: []string{rfFirst}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := diffTools(tt.before, tt.after)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("diffTools = %+v, want %+v", got, tt.want)
			}
			if got.empty() != (len(tt.want.added)+len(tt.want.removed)+len(tt.want.changed) == 0) {
				t.Errorf("empty() = %v for %+v", got.empty(), got)
			}
		})
	}
}

// The names in a log line come from the backend; a line carries a bounded
// number of them and says how many it left out.
func TestLoggedToolNames(t *testing.T) {
	few := []string{rfFirst, rfSecond}
	if got := loggedToolNames(few); !slices.Equal(got, few) {
		t.Errorf("few names = %v", got)
	}

	many := make([]string, maxLoggedToolNames+7)
	for i := range many {
		many[i] = rfFirst
	}
	got := loggedToolNames(many)
	if len(got) != maxLoggedToolNames+1 || got[len(got)-1] != "and 7 more" {
		t.Errorf("many names = %v", got)
	}

	// A name is cut at a byte bound without leaving half a character.
	long := strings.Repeat("ä", maxLoggedToolNameLen)
	cut := loggedToolNames([]string{long})[0]
	if len(cut) > maxLoggedToolNameLen+3 || !strings.HasSuffix(cut, "...") || strings.ToValidUTF8(cut, "") != cut {
		t.Errorf("long name logged as %q (%d bytes)", cut, len(cut))
	}
}

func TestRefreshIntervalFromEnv(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
	}{
		{"", mcpRefreshInterval},
		{"15", 15 * time.Second},
		{"0", 0},
		{"86401", mcpRefreshMax},
		{"9223372036854775807", mcpRefreshMax},
		{"-5", mcpRefreshInterval},
		{"soon", mcpRefreshInterval},
	}
	for _, tt := range tests {
		t.Run("value "+tt.value, func(t *testing.T) {
			t.Setenv(mcpRefreshEnv, tt.value)
			if got := refreshIntervalFromEnv(); got != tt.want {
				t.Errorf("interval = %s, want %s", got, tt.want)
			}
		})
	}
}
