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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	rfSlow     = "slow"
	rfLiveSlow = rfLive + "_" + rfSlow

	// Log lines the tests below count.
	rfLostLine      = "backend connection lost"
	rfConnectedLine = `msg="connected to backend"`

	rfMethodDiscover = "server/discover"

	// Answers of rfFake, as the JSON that goes into the "result" of the
	// JSON-RPC answer. The discover answer announces that the server says
	// when its tool list changes; a page of the tool list ends with the
	// cursor of the next one, or without one.
	rfFakeDiscover = `{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{"listChanged":true}},"ttlMs":0,"cacheScope":"private"}`
	rfFakePage     = `{"resultType":"complete","ttlMs":0,"cacheScope":"private","tools":[{"name":"first","description":"a tool","inputSchema":{"type":"object"}}]%s}`
)

// rfSlowTool adds a tool that answers after wait, or when release is closed,
// and counts how often it ran.
func rfSlowTool(server *mcp.Server, runs *atomic.Int64, wait time.Duration, release <-chan struct{}) {
	server.AddTool(
		&mcp.Tool{Name: rfSlow, Description: "takes its time", InputSchema: map[string]any{schemaKeyType: schemaTypeObject}},
		func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			runs.Add(1)
			select {
			case <-time.After(wait):
			case <-release:
			case <-ctx.Done():
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: rfSlow + " ran"}}}, nil
		},
	)
}

// rfFake is an MCP server of the stateless revision written by hand. answer
// returns the result of a request as JSON, or "" for a method the server
// does not have; it may block to leave a request unanswered.
func rfFake(t *testing.T, answer func(r *http.Request, method, cursor string) string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		status, field, value := http.StatusOK, "result", answer(r, req.Method, req.Params.Cursor)
		if value == "" {
			status, field, value = http.StatusNotFound, "error", helperMethodNotFound
		}
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, rpcAnswer(req.ID, field, value))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// A call that is running when another request finds the session gone is not
// sent a second time. The backend has taken it and may have run it; only its
// answer is lost.
func TestMCPAdapter_CallInFlightIsNotSentAgain(t *testing.T) {
	var runs atomic.Int64
	server := rfServer(nil, rfFirst)
	rfSlowTool(server, &runs, 400*time.Millisecond, nil)
	inner := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)

	// Once gone is set, the next listing is told that the session is not
	// known, as a server does that has let the session go.
	var gone atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte(testMethodToolsList)) && gone.CompareAndSwap(true, false) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	tr := rfConnected(t, rfPace(), BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: ts.URL})
	conn := tr.backends[rfLive]
	before := tr.currentSession(conn)

	done := make(chan error, 1)
	go func() {
		_, err := tr.Execute(context.Background(), rfLiveSlow, map[string]any{})
		done <- err
	}()
	rfEventually(t, "the call is running on the backend", func() bool { return runs.Load() == 1 })
	gone.Store(true)
	tr.wakeWatcher(conn) // a reading, as the watcher makes one at every interval

	if err := <-done; err == nil {
		t.Error("the call returned a result although its session ended under it")
	}
	rfEventually(t, "the backend is connected again", func() bool {
		s := tr.currentSession(conn)
		return s != nil && s != before
	})
	// Long enough for a second run to have started.
	time.Sleep(300 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Errorf("the tool ran %d times for one call", got)
	}
}

// An error of a listing is no reason to end a session, whatever its text
// says: the backend chooses the text. The session stays, calls go on, and
// the backend keeps the list it had.
func TestMCPAdapter_ListingErrorLeavesTheSessionAlone(t *testing.T) {
	var (
		runs     atomic.Int64
		failList atomic.Bool
	)
	server := rfServer(nil, rfFirst)
	release := make(chan struct{})
	rfSlowTool(server, &runs, 5*time.Second, release)
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == testMethodToolsList && failList.Load() {
				return nil, errors.New("upstream: read tcp 192.0.2.1:1234: connection reset by peer")
			}
			return next(ctx, method, req)
		}
	})
	host := newRFHost(t, false, server)
	tr := rfConnected(t, rfPace(), host.entry(rfLive))
	conn := tr.backends[rfLive]
	session := tr.currentSession(conn)

	slow := make(chan error, 1)
	go func() {
		_, err := tr.Execute(context.Background(), rfLiveSlow, map[string]any{})
		slow <- err
	}()
	rfEventually(t, "the slow call is running", func() bool { return runs.Load() == 1 })

	failList.Store(true)
	tr.wakeWatcher(conn)
	rfEventually(t, "the failed reading is logged", func() bool {
		return strings.Contains(tr.logs.String(), "reading the tool list of backend failed")
	})

	// The backend still takes calls, on the session it had.
	if result, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{}); err != nil || result.IsError {
		t.Fatalf("call after the failed reading: %v %+v", err, result)
	}
	close(release)
	if err := <-slow; err != nil {
		t.Errorf("the call that was running failed: %v", err)
	}
	if tr.currentSession(conn) != session {
		t.Error("the session was replaced over the text of an error")
	}
	if !tr.lists(rfLiveFirst, rfLiveSlow) {
		t.Errorf("tools = %v, want the list the backend had", tr.toolNames())
	}
	if logs := tr.logs.String(); strings.Contains(logs, rfLostLine) {
		t.Errorf("the connection was taken for lost:\n%s", logs)
	}
}

// A backend that can be connected and whose session then ends at once is
// connected again at growing intervals, like one that cannot be connected
// at all, and not as fast as its sessions end.
func TestMCPAdapter_SessionsThatDoNotLastAreRetriedAtGrowingIntervals(t *testing.T) {
	server := rfServer(nil, rfFirst)
	inner := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, nil)
	// Every listing is told that the session is not known.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			if bytes.Contains(body, []byte(testMethodToolsList)) {
				http.Error(w, "session not found", http.StatusNotFound)
				return
			}
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)

	pace := rfPace()
	pace.stable = time.Hour
	pace.retryMin = 50 * time.Millisecond
	pace.retryMax = 400 * time.Millisecond
	tr := rfConnected(t, pace, BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: ts.URL})

	const watched = 1500 * time.Millisecond
	time.Sleep(watched)
	tr.Close()

	// At the start, then after 50, 100, 200 and 400ms, and every 400ms from
	// there: seven connects in the time watched. A watcher that connects as
	// fast as the sessions end would make dozens.
	connects := strings.Count(tr.logs.String(), rfConnectedLine)
	if connects < 3 || connects > 9 {
		t.Errorf("%d connects in %s, want the handful that growing intervals allow:\n%s", connects, watched, tr.logs.String())
	}
}

// A backend on the HTTP+SSE transport keeps its event stream for as long as
// the session lasts: the stream is opened under the context of the connect,
// and that context is the session's, not one that ends when the connect
// returns.
func TestMCPAdapter_SSETransportKeepsItsStream(t *testing.T) {
	server := rfServer(nil, rfFirst)
	mux := http.NewServeMux()
	mux.Handle("/sse", mcp.NewSSEHandler(func(*http.Request) *mcp.Server { return server }, nil))
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	tr := rfConnected(t, rfPace(), BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: ts.URL + "/sse"})
	conn := tr.backends[rfLive]
	session := tr.currentSession(conn)
	if session == nil || !tr.lists(rfLiveFirst) {
		t.Fatalf("backend not connected or tools not read:\n%s", tr.logs.String())
	}

	time.Sleep(300 * time.Millisecond)
	result, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{})
	if err != nil || result.IsError {
		t.Fatalf("call: %v %+v", err, result)
	}
	if tr.currentSession(conn) != session {
		t.Error("the backend had to be connected again")
	}
	if got := strings.Count(tr.logs.String(), rfConnectedLine); got != 1 {
		t.Errorf("the backend was connected %d times, want once", got)
	}
}

// The streams a server sends its notifications on are not cut off by
// TOOLMESH_MCP_TIMEOUT, which bounds a call: a change announced long after
// that time still arrives, in both generations, over the session of the
// start.
func TestMCPAdapter_NotificationsOutliveTheCallTimeout(t *testing.T) {
	rfGenerations(t, func(t *testing.T, stateless bool) {
		t.Setenv("TOOLMESH_MCP_TIMEOUT", "1")
		server := rfServer(nil, rfFirst)
		host := newRFHost(t, stateless, server)
		tr := rfConnected(t, rfPace(), host.entry(rfLive))
		conn := tr.backends[rfLive]
		session := tr.currentSession(conn)

		time.Sleep(2500 * time.Millisecond)
		rfAddTool(server, rfSecond, "runs "+rfSecond)
		rfEventually(t, "the adapter lists the tool announced after the timeout", func() bool {
			return tr.lists(rfLiveFirst, rfLiveSecond)
		})
		if tr.currentSession(conn) != session {
			t.Error("the backend was connected again in the meantime")
		}
	})
}

// A server that leaves the subscription to its notifications unanswered
// holds up a connect no longer than a connect may take, and Close no longer
// than its grace period. The SDK sends that request under no context, so
// neither would otherwise reach it before TOOLMESH_MCP_TIMEOUT.
func TestMCPAdapter_UnansweredSubscriptionHoldsUpNeitherConnectNorClose(t *testing.T) {
	t.Setenv("TOOLMESH_MCP_TIMEOUT", "60")
	ts := rfFake(t, func(r *http.Request, method, _ string) string {
		switch method {
		case rfMethodDiscover:
			return rfFakeDiscover
		case mcpMethodListen:
			<-r.Context().Done()
		case testMethodToolsList:
			return fmt.Sprintf(rfFakePage, "")
		}
		return ""
	})

	pace := rfPace()
	pace.handshake = 300 * time.Millisecond
	pace.closeGrace = 300 * time.Millisecond
	tr := rfAdapter(t, pace, BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: ts.URL})

	within := func(what string, limit time.Duration, do func()) {
		t.Helper()
		done := make(chan struct{})
		go func() {
			do()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(limit):
			t.Fatalf("%s did not return within %s:\n%s", what, limit, tr.logs.String())
		}
	}
	within("Connect", 10*time.Second, func() { _ = tr.Connect(context.Background()) })
	if tr.currentSession(tr.backends[rfLive]) != nil {
		t.Error("the backend counts as connected although its connect was given up")
	}
	// The watcher is trying again by now, and may be in the middle of it.
	rfEventually(t, "the watcher has tried again", func() bool {
		return strings.Contains(tr.logs.String(), "trying again later")
	})
	within("Close", 10*time.Second, tr.Close)
}

// Close gives a running call its grace period and then cuts it off; it does
// not wait for a backend that never answers.
func TestMCPAdapter_CloseCutsOffACallThatDoesNotReturn(t *testing.T) {
	var runs atomic.Int64
	server := rfServer(nil, rfFirst)
	never := make(chan struct{})
	defer close(never)
	rfSlowTool(server, &runs, time.Hour, never)
	host := newRFHost(t, false, server)

	pace := rfPace()
	pace.closeGrace = 300 * time.Millisecond
	tr := rfConnected(t, pace, host.entry(rfLive))

	call := make(chan error, 1)
	go func() {
		_, err := tr.Execute(context.Background(), rfLiveSlow, map[string]any{})
		call <- err
	}()
	rfEventually(t, "the call is running on the backend", func() bool { return runs.Load() == 1 })

	closed := make(chan struct{})
	go func() {
		tr.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatalf("Close waited for a call that does not return:\n%s", tr.logs.String())
	}
	select {
	case err := <-call:
		if err == nil {
			t.Error("the call that was cut off returned a result")
		}
	case <-time.After(5 * time.Second):
		t.Error("the call is still waiting after Close")
	}
}

// A session of the stateless revision that has read many pages of tool
// lists is replaced by a new one, in the background and without a gap: the
// SDK keeps every page it read under its cursor, and a server whose cursors
// are new with every listing would make a session grow without end.
func TestMCPAdapter_SessionThatReadManyPagesIsReplaced(t *testing.T) {
	// Three pages per listing; no cursor is used twice.
	var cursors atomic.Int64
	ts := rfFake(t, func(_ *http.Request, method, cursor string) string {
		switch method {
		case rfMethodDiscover:
			return fakeDiscoverResult
		case testMethodToolsList:
			if strings.HasSuffix(cursor, "-last") {
				return fmt.Sprintf(rfFakePage, "")
			}
			next := fmt.Sprintf("c%d", cursors.Add(1))
			if cursor != "" {
				next += "-last"
			}
			return fmt.Sprintf(rfFakePage, `,"nextCursor":"`+next+`"`)
		}
		return ""
	})

	pace := rfPace()
	pace.refresh = 20 * time.Millisecond
	pace.maxCursorPages = 5
	tr := rfConnected(t, pace, BackendEntry{Name: rfLive, Transport: transportTypeHTTP, URL: ts.URL})
	conn := tr.backends[rfLive]
	first := tr.currentSession(conn)
	if first == nil || !tr.lists(rfLiveFirst) {
		t.Fatalf("backend not connected or tools not read:\n%s", tr.logs.String())
	}

	rfEventually(t, "the session is replaced", func() bool {
		s := tr.currentSession(conn)
		return s != nil && s != first
	})
	if !tr.lists(rfLiveFirst) {
		t.Errorf("tools after the replacement = %v", tr.toolNames())
	}
	logs := tr.logs.String()
	if !strings.Contains(logs, "replacing the session of backend") {
		t.Errorf("the replacement was not logged:\n%s", logs)
	}
	if strings.Contains(logs, rfLostLine) || strings.Contains(logs, rfChangedLine) {
		t.Errorf("the replacement was taken for a lost connection or a changed list:\n%s", logs)
	}
}

// Whoever is about to connect a backend and finds it connected leaves the
// session in place: a call and the watcher that both notice a lost
// connection make one new connection between them.
func TestMCPAdapter_ConnectLeavesASessionInPlace(t *testing.T) {
	host := newRFHost(t, false, rfServer(nil, rfFirst))
	tr := rfAdapter(t, rfPace(), host.entry(rfLive))
	conn := tr.backends[rfLive]
	for range 3 {
		if err := tr.connectBackend(context.Background(), rfLive, conn); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Count(tr.logs.String(), rfConnectedLine); got != 1 {
		t.Errorf("the backend was connected %d times, want once", got)
	}
}

// A call that finds a backend without a session fails at once and has the
// watcher try the backend soon.
func TestMCPAdapter_CallOnADisconnectedBackendAsksForIt(t *testing.T) {
	host := newRFHost(t, false, rfServer(nil, rfFirst))
	tr := rfAdapter(t, rfPace(), host.entry(rfLive))
	conn := tr.backends[rfLive]

	_, err := tr.Execute(context.Background(), rfLiveFirst, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "is not connected") {
		t.Fatalf("call on a backend without a session: %v", err)
	}
	if len(conn.want) != 1 {
		t.Error("the watcher was not asked to connect the backend")
	}
}

func TestAwaitRetry(t *testing.T) {
	const (
		wait  = 400 * time.Millisecond
		floor = 100 * time.Millisecond
	)
	wanted := func() chan struct{} {
		ch := make(chan struct{}, 1)
		ch <- struct{}{}
		return ch
	}
	tests := []struct {
		name string
		want chan struct{}
		// last is how long ago the last attempt was.
		last           time.Duration
		atLeast, below time.Duration
	}{
		{name: "nobody asks: the whole wait", want: make(chan struct{}, 1), last: time.Hour, atLeast: wait, below: 5 * wait},
		{name: "a call asks long after the last attempt: at once", want: wanted(), last: time.Hour, below: floor},
		{name: "a call asks right after an attempt: the floor", want: wanted(), last: 0, atLeast: floor - 10*time.Millisecond, below: wait},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			if !awaitRetry(context.Background(), tt.want, wait, floor, start.Add(-tt.last)) {
				t.Fatal("awaitRetry reported an ended context")
			}
			if took := time.Since(start); took < tt.atLeast || took >= tt.below {
				t.Errorf("waited %s, want at least %s and less than %s", took, tt.atLeast, tt.below)
			}
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if awaitRetry(ctx, make(chan struct{}, 1), wait, floor, time.Now()) {
		t.Error("awaitRetry went on after its context had ended")
	}
}

// sessionTransport bounds a call by the timeout, from the request to the end
// of its answer, leaves the streams of notifications unbounded, and ends
// everything with the scope of the connection.
func TestSessionTransport(t *testing.T) {
	const (
		timeout  = 150 * time.Millisecond
		pause    = 500 * time.Millisecond
		pathLate = "/late" // the answer starts after the pause
		pathBody = "/body" // the answer starts at once, its end comes after the pause
		payload  = "data"
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == pathBody {
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		select {
		case <-time.After(pause):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(ts.Close)

	scope, endScope := context.WithCancel(context.Background())
	defer endScope()
	client := &http.Client{Transport: &sessionTransport{base: http.DefaultTransport, scope: scope, timeout: timeout}}
	// fetch sends a request and reads its answer to the end.
	fetch := func(method, path, mcpMethod string) (string, error) {
		req, err := http.NewRequestWithContext(context.Background(), method, ts.URL+path, http.NoBody)
		if err != nil {
			return "", err
		}
		if mcpMethod != "" {
			req.Header.Set(mcpMethodHeader, mcpMethod)
		}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		return string(body), err
	}

	tests := []struct {
		name      string
		method    string
		path      string
		mcpMethod string
		wantCut   bool
	}{
		{"a call whose answer does not come", http.MethodPost, pathLate, testMethodToolsCall, true},
		{"a call whose answer does not end", http.MethodPost, pathBody, testMethodToolsCall, true},
		{"a request without a method header", http.MethodPost, pathLate, "", true},
		{"the stream of a server with sessions", http.MethodGet, pathBody, "", false},
		{"the subscription of the stateless revision", http.MethodPost, pathBody, mcpMethodListen, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := fetch(tt.method, tt.path, tt.mcpMethod)
			switch {
			case tt.wantCut && !errors.Is(err, context.DeadlineExceeded):
				t.Errorf("got %q, %v; want the request cut off at the timeout", body, err)
			case !tt.wantCut && (err != nil || body != payload):
				t.Errorf("got %q, %v; want the whole answer", body, err)
			}
		})
	}

	t.Run("the end of the scope ends a stream", func(t *testing.T) {
		time.AfterFunc(100*time.Millisecond, endScope)
		start := time.Now()
		if _, err := fetch(http.MethodGet, pathLate, ""); !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want the request canceled", err)
		}
		if took := time.Since(start); took >= pause {
			t.Errorf("the request ended after %s, with its answer and not with the scope", took)
		}
	})
}

// The log of a reading names a bounded number of the tools a backend lists
// under names that are routed elsewhere, and says how many more there are.
func TestMCPAdapter_ShadowedToolsAreLoggedInBounds(t *testing.T) {
	logs := &rfLogs{}
	adapter := NewMCPAdapterFromEntries([]BackendEntry{{Name: prShort}, {Name: prLong}}, nil,
		slog.New(slog.NewTextHandler(logs, nil)))
	listed := listedTools{upstream: map[string]struct{}{}}
	for i := range maxLoggedToolNames + 5 {
		listed.shadowed = append(listed.shadowed, shadowedTool{tool: fmt.Sprintf("b_%d", i), owner: prLong})
	}
	adapter.reportListing(prShort, adapter.backends[prShort], listed, toolListChange{}, true)

	if got := strings.Count(logs.String(), "tool is not reachable"); got != maxLoggedToolNames {
		t.Errorf("%d tools named, want %d", got, maxLoggedToolNames)
	}
	if !strings.Contains(logs.String(), "more=5") {
		t.Errorf("the log does not say how many more there are:\n%s", logs.String())
	}
}
