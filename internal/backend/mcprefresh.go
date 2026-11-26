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
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The tools of an MCP server are not fixed for the life of a connection: a
// server adds and removes tools while it runs, and it comes back from a
// restart with another list. The adapter therefore keeps one goroutine per
// backend, its watcher, that
//
//   - connects a backend that is not connected, at growing intervals, so a
//     backend that was down when ToolMesh started is there once it is up;
//   - connects a backend again whose session has ended on its own;
//   - reads the tool list again when the backend says it has changed
//     (notifications/tools/list_changed);
//   - reads it again at an interval all the same, because not every change
//     is announced: a server may not send the notification at all, the
//     stream it would arrive on may be down, and a server of the stateless
//     revision that restarts looks, call by call, like the one before.
//
// Every reading goes through the checks of the first (include_tools,
// shadowed names) and is reported by name when it changed something.

const (
	// mcpRefreshEnv sets the interval of the periodic reading in seconds;
	// 0 turns it off.
	mcpRefreshEnv = "TOOLMESH_MCP_REFRESH_INTERVAL"
	// mcpRefreshInterval is the interval when mcpRefreshEnv does not say,
	// and mcpRefreshMax the longest one it can set.
	mcpRefreshInterval = 60 * time.Second
	mcpRefreshMax      = 24 * time.Hour
	// mcpRefreshMinGap is the least time between two readings that a
	// backend asks for. The backend decides how often it says its list has
	// changed; this keeps what follows on each notice, a listing of every
	// page and whatever is rebuilt from a changed list, to a rate ToolMesh
	// chooses.
	mcpRefreshMinGap = 5 * time.Second
	// mcpListTimeout bounds one reading of a tool list, all pages of it.
	mcpListTimeout = 60 * time.Second
	// mcpRetryMin and mcpRetryMax bound the wait before the next attempt to
	// connect a backend that is not connected. It starts at the lower value
	// and doubles with every attempt, and with every session that did not
	// last. A call that needs the backend has it tried after the lower
	// value.
	mcpRetryMin = 5 * time.Second
	mcpRetryMax = 5 * time.Minute
	// mcpStableSession is how long a session has to last to count as one
	// that worked. A backend whose session ends after that is connected
	// again at once; one whose sessions end sooner is connected at the
	// growing intervals of a backend that cannot be connected at all.
	mcpStableSession = time.Minute
	// mcpCloseGrace is how long Close waits for running calls to return and
	// for the children of stdio backends to end before it cuts them off.
	mcpCloseGrace = 5 * time.Second
	// mcpMaxCursorPages is how many pages asked for with a cursor a session
	// of the stateless revision serves before it is replaced; see
	// renewSession.
	mcpMaxCursorPages = 1000

	// maxLoggedToolNames bounds how many names one log line about a changed
	// tool list carries per kind of change, and maxLoggedToolNameLen how
	// much of a name: 128 bytes is as long as MCP lets a tool name be.
	maxLoggedToolNames   = 20
	maxLoggedToolNameLen = 128
)

var (
	// errNotConnected is the answer to a reading of the tool list of a
	// backend that has no session.
	errNotConnected = errors.New("not connected")
	// errAdapterClosed is the answer to a connect after Close.
	errAdapterClosed = errors.New("MCP adapter is closed")
	// errSessionReplaced ends a reading of a tool list whose session was
	// replaced or closed while the backend answered.
	errSessionReplaced = errors.New("the session was replaced while the tool list was read")
)

// mcpPace is the timing of the background work for the backends.
type mcpPace struct {
	refresh        time.Duration // interval of the periodic reading; 0 turns it off
	minGap         time.Duration
	list           time.Duration
	handshake      time.Duration // bound of one attempt to connect
	retryMin       time.Duration
	retryMax       time.Duration
	stable         time.Duration
	closeGrace     time.Duration
	maxCursorPages int
}

// currentPace returns the timing in force: the defaults, with the interval
// of the periodic reading from the environment, unless a test set its own.
func (a *MCPAdapter) currentPace() mcpPace {
	if a.pace != nil {
		return *a.pace
	}
	return mcpPace{
		refresh:        refreshIntervalFromEnv(),
		minGap:         mcpRefreshMinGap,
		list:           mcpListTimeout,
		handshake:      mcpHandshakeTimeout,
		retryMin:       mcpRetryMin,
		retryMax:       mcpRetryMax,
		stable:         mcpStableSession,
		closeGrace:     mcpCloseGrace,
		maxCursorPages: mcpMaxCursorPages,
	}
}

// refreshIntervalFromEnv reads mcpRefreshEnv: a number of seconds, 0 for no
// periodic reading, and no more than a day. Anything that is no number, and
// a negative one, leaves the default in place.
func refreshIntervalFromEnv() time.Duration {
	v := os.Getenv(mcpRefreshEnv)
	if v == "" {
		return mcpRefreshInterval
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return mcpRefreshInterval
	}
	if secs > int(mcpRefreshMax/time.Second) {
		return mcpRefreshMax
	}
	return time.Duration(secs) * time.Second
}

// lifetime returns the context that ends when Close begins.
func (a *MCPAdapter) lifetime() context.Context {
	a.lifeOnce.Do(func() {
		a.life, a.lifeCancel = context.WithCancel(context.Background())
		a.hard, a.hardCancel = context.WithCancel(context.Background())
	})
	return a.life
}

// untilStopped returns the context that ends when Close stops waiting: the
// context of the child processes of stdio backends and of the connections
// to the others.
func (a *MCPAdapter) untilStopped() context.Context {
	a.lifetime()
	return a.hard
}

// isClosed reports whether Close has run.
func (a *MCPAdapter) isClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

// currentSession returns the session of a backend, nil while it has none.
func (a *MCPAdapter) currentSession(conn *backendConn) *mcp.ClientSession {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return conn.session
}

// sessionState returns the session of a backend and whether that session
// has ended on its own.
func (a *MCPAdapter) sessionState(conn *backendConn) (session *mcp.ClientSession, ended bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return conn.session, conn.ended
}

// sessionEnded records that a session is over and has the watcher look at
// the backend. It is called for every session, also for one that was closed
// here and is no longer the session of its backend; only the session in
// place is marked.
func (a *MCPAdapter) sessionEnded(conn *backendConn, session *mcp.ClientSession) {
	a.mu.Lock()
	if conn.session == session {
		conn.ended = true
	}
	a.mu.Unlock()
	a.wakeWatcher(conn)
}

// dropSession takes an ended session away from its backend, which is then
// without one: a call fails at once instead of running into the dead
// connection, and the watcher connects the backend again.
func (a *MCPAdapter) dropSession(conn *backendConn, session *mcp.ClientSession) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || conn.session != session {
		return
	}
	conn.session, conn.ended = nil, false
	a.retireLocked(session)
}

// OnToolSetChange implements [ToolSetChangeNotifier]: fn is called after the
// tool list of one of the backends has changed, be it because the backend
// said so, because it was connected again or because the periodic reading
// found another list. A reading that finds the list as it was does not call
// it.
//
// fn runs while the connection of that backend is held. It may list the
// tools; it must not call a tool, and it should return at once.
func (a *MCPAdapter) OnToolSetChange(fn func()) {
	if fn == nil {
		a.onChange.Store(nil)
		return
	}
	a.onChange.Store(&fn)
}

// toolSetChanged tells whoever follows the tool set that it has changed. The
// new list is in place by then.
func (a *MCPAdapter) toolSetChanged() {
	if fn := a.onChange.Load(); fn != nil {
		(*fn)()
	}
}

// toolListChanged handles notifications/tools/list_changed of a backend: the
// watcher of the backend reads the list again. Nothing is read here, on the
// goroutine that delivers the messages of the connection, and however many
// notices arrive before the watcher gets to it, it reads once.
func (a *MCPAdapter) toolListChanged(name string) {
	conn, ok := a.backends[name]
	if !ok {
		return
	}
	a.logger.Debug("backend says its tool list has changed", "backend", name)
	a.wakeWatcher(conn)
}

// wakeWatcher tells the watcher of a backend to look at it now.
func (a *MCPAdapter) wakeWatcher(conn *backendConn) {
	signal(conn.wake)
}

// signal leaves a note in a channel that holds one. It never blocks: a note
// that is already there covers this one.
func signal(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// startWatchers starts the watcher of every backend, once. The adapter lock
// is held meanwhile, so that Close either finds every watcher started or
// keeps all of them from starting.
func (a *MCPAdapter) startWatchers() {
	a.watchOnce.Do(func() {
		a.mu.RLock()
		defer a.mu.RUnlock()
		if a.closed {
			return
		}
		ctx := a.lifetime()
		for name, conn := range a.backends {
			a.watchers.Go(func() { a.watchBackend(ctx, name, conn) })
		}
	})
}

// usesListCache reports whether the SDK keeps the tool lists it reads over a
// session, which it does in the stateless revision.
func usesListCache(session *mcp.ClientSession) bool {
	return sessionRevision(session) >= mcpRevisionStateless
}

// renewSession replaces the session of a backend with a new one once the
// session has served more pages of tool lists than the pace allows.
//
// In the stateless revision the SDK keeps every page of a tool list it has
// read, under the cursor the page was asked for with, and lets go of a page
// only when the same cursor is asked again. A server whose cursors are new
// with every listing therefore makes a session grow with each reading, and
// the SDK looks through all of it on every call. A session is read for as
// long as it lives, so it is replaced before that adds up: the new session
// starts empty, and the old one ends when the calls running on it have
// returned.
func (a *MCPAdapter) renewSession(ctx context.Context, name string, conn *backendConn) {
	conn.op.Lock()
	defer conn.op.Unlock()
	if conn.cursorPages <= a.currentPace().maxCursorPages {
		return
	}
	a.logger.Info("replacing the session of backend: it has read many pages of tool lists",
		"name", name, "pages", conn.cursorPages)
	if err := a.connectLocked(ctx, name, conn); err != nil && ctx.Err() == nil {
		a.logger.Warn("replacing the session of backend failed, keeping the one it has",
			"name", name, "error", loggableError(err))
	}
}

// watchBackend is the background work for one backend, until ctx ends. See
// the comment at the top of this file for what it does and why.
//
// It is the only place that reads a tool list unasked, and it reads for one
// backend at a time, so what a backend can make ToolMesh do by announcing
// changes is one listing per mcpRefreshMinGap, on top of the periodic one.
// A session is taken for lost only when it has ended, never for what an
// error says: a backend chooses the text of its errors.
func (a *MCPAdapter) watchBackend(ctx context.Context, name string, conn *backendConn) {
	pace := a.currentPace()
	var (
		// retry is the wait before the next attempt to connect.
		retry = pace.retryMin
		// lastAttempt is when the watcher last tried to connect.
		lastAttempt time.Time
		// seen is the session the watcher last found in place, since when.
		seen      *mcp.ClientSession
		seenSince time.Time
		// lastAsked is when the list was last read because the backend
		// asked.
		lastAsked time.Time
		// failing remembers that the latest reading failed, so that a
		// failure is logged when it starts and when it ends, not at every
		// interval.
		failing bool
	)

	for ctx.Err() == nil {
		session, ended := a.sessionState(conn)
		if session != nil && session != seen {
			seen, seenSince, failing = session, time.Now(), false
		}
		if session != nil && ended {
			a.logger.Warn("backend connection lost", "name", name)
			a.dropSession(conn, session)
			session = nil
		}

		if session == nil {
			lasted := seen != nil && time.Since(seenSince) >= pace.stable
			seen = nil
			if lasted {
				// A connection that had worked is made again at once.
				retry = pace.retryMin
			} else {
				if !awaitRetry(ctx, conn.want, retry, pace.retryMin, lastAttempt) {
					return
				}
				retry = min(retry*2, pace.retryMax)
			}
			lastAttempt = time.Now()
			if err := a.connectBackend(ctx, name, conn); err != nil {
				if ctx.Err() != nil {
					return
				}
				a.logger.Warn("backend is not connected, trying again later",
					"name", name, "error", loggableError(err), "retry_in", retry.String())
			}
			continue
		}

		asked, ok := awaitWake(ctx, conn.wake, pace.refresh)
		if !ok {
			return
		}
		if _, ended := a.sessionState(conn); ended {
			continue
		}
		if asked {
			// The first notice is acted on at once, the next ones no
			// sooner than the gap after it.
			if gap := pace.minGap - time.Since(lastAsked); gap > 0 && !sleepCtx(ctx, gap) {
				return
			}
			// One reading answers every notice that came in before it.
			select {
			case <-conn.wake:
			default:
			}
			lastAsked = time.Now()
		}

		err := a.discoverTools(ctx, name, conn)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			if failing {
				a.logger.Info("tool list of backend can be read again", "name", name)
			}
			failing = false
			a.renewSession(ctx, name, conn)
		case errors.Is(err, errNotConnected), errors.Is(err, errSessionReplaced):
			// A call found the connection lost and has connected the
			// backend again, which read the list, or has left it without a
			// session, which the next round takes up.
		default:
			// The backend keeps the list it had. If the session is gone,
			// it ends, and the next round finds it so.
			if !failing {
				a.logger.Warn("reading the tool list of backend failed, keeping the list it had",
					"name", name, "error", loggableError(err))
			}
			failing = true
		}
	}
}

// awaitRetry waits before the next attempt to connect a backend: for wait,
// or until a call wants the backend, but then no sooner than floor after
// the last attempt. It reports false when ctx ended first.
func awaitRetry(ctx context.Context, want <-chan struct{}, wait, floor time.Duration, last time.Time) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	case <-want:
		if rest := floor - time.Since(last); rest > 0 {
			return sleepCtx(ctx, rest)
		}
		return true
	}
}

// awaitWake waits for a wake, for the interval to pass or for ctx to end. It
// reports whether a wake ended the wait, and ok false when ctx did. An
// interval of zero waits for a wake only.
func awaitWake(ctx context.Context, wake <-chan struct{}, interval time.Duration) (woken, ok bool) {
	var tick <-chan time.Time
	if interval > 0 {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		tick = timer.C
	}
	select {
	case <-ctx.Done():
		return false, false
	case <-wake:
		return true, true
	case <-tick:
		return false, true
	}
}

// sleepCtx waits for d and reports false when ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// toolListChange names what a reading of a tool list changed, each kind in
// ascending order.
type toolListChange struct {
	added   []string
	removed []string
	// changed holds the tools that kept their name and got another
	// description or another input schema.
	changed []string
}

func (c toolListChange) empty() bool {
	return len(c.added) == 0 && len(c.removed) == 0 && len(c.changed) == 0
}

// diffTools compares the tool list a backend had with the one just read.
// The order of a list is no part of the comparison.
func diffTools(before, after []ToolDescriptor) toolListChange {
	old := make(map[string]ToolDescriptor, len(before))
	for _, t := range before {
		old[t.Name] = t
	}

	var change toolListChange
	kept := make(map[string]struct{}, len(after))
	for _, t := range after {
		kept[t.Name] = struct{}{}
		prev, known := old[t.Name]
		switch {
		case !known:
			change.added = append(change.added, t.Name)
		case prev.Description != t.Description || !reflect.DeepEqual(prev.InputSchema, t.InputSchema):
			change.changed = append(change.changed, t.Name)
		}
	}
	for name := range old {
		if _, ok := kept[name]; !ok {
			change.removed = append(change.removed, name)
		}
	}

	sort.Strings(change.added)
	sort.Strings(change.removed)
	sort.Strings(change.changed)
	return change
}

// loggedToolNames returns names as they go into a log line: all of them up
// to maxLoggedToolNames, beyond that the first ones and how many more there
// are. A backend chooses the names and their number, so both are bounded
// here.
func loggedToolNames(names []string) []string {
	shown := min(len(names), maxLoggedToolNames)
	out := make([]string, 0, shown+1)
	for _, name := range names[:shown] {
		out = append(out, loggedToolName(name))
	}
	if rest := len(names) - shown; rest > 0 {
		out = append(out, fmt.Sprintf("and %d more", rest))
	}
	return out
}

// loggedToolName returns a tool name as it goes into a log line: no more
// than maxLoggedToolNameLen bytes of it.
func loggedToolName(name string) string {
	if len(name) > maxLoggedToolNameLen {
		return strings.ToValidUTF8(name[:maxLoggedToolNameLen], "") + "..."
	}
	return name
}
