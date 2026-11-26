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
	// and doubles with every failed attempt.
	mcpRetryMin = 5 * time.Second
	mcpRetryMax = 5 * time.Minute

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
	refresh  time.Duration // interval of the periodic reading; 0 turns it off
	minGap   time.Duration
	list     time.Duration
	retryMin time.Duration
	retryMax time.Duration
}

// currentPace returns the timing in force: the defaults, with the interval
// of the periodic reading from the environment, unless a test set its own.
func (a *MCPAdapter) currentPace() mcpPace {
	if a.pace != nil {
		return *a.pace
	}
	return mcpPace{
		refresh:  refreshIntervalFromEnv(),
		minGap:   mcpRefreshMinGap,
		list:     mcpListTimeout,
		retryMin: mcpRetryMin,
		retryMax: mcpRetryMax,
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
		a.procs, a.procsCancel = context.WithCancel(context.Background())
	})
	return a.life
}

// processes returns the context of the child processes of stdio backends,
// which ends when Close is done.
func (a *MCPAdapter) processes() context.Context {
	a.lifetime()
	return a.procs
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

// wakeWatcher tells the watcher of a backend to look at it now. It never
// blocks: a wake that is already pending covers this one.
func (a *MCPAdapter) wakeWatcher(conn *backendConn) {
	select {
	case conn.wake <- struct{}{}:
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

// refreshBackend reads the tool list of a connected backend again and
// returns the session it asked; see listLocked.
func (a *MCPAdapter) refreshBackend(ctx context.Context, name string, conn *backendConn) (*mcp.ClientSession, error) {
	conn.op.Lock()
	defer conn.op.Unlock()
	session := a.currentSession(conn)
	if session == nil {
		return nil, errNotConnected
	}
	return session, a.listLocked(ctx, name, conn, session)
}

// watchBackend is the background work for one backend, until ctx ends. See
// the comment at the top of this file for what it does and why.
//
// It is the only place that reads a tool list unasked, and it reads for one
// backend at a time, so what a backend can make ToolMesh do by announcing
// changes is one listing per mcpRefreshMinGap, on top of the periodic one.
func (a *MCPAdapter) watchBackend(ctx context.Context, name string, conn *backendConn) {
	pace := a.currentPace()
	retry := pace.retryMin
	// lastAsked is when the list was last read because the backend asked.
	var lastAsked time.Time
	// failing remembers that the latest reading failed, so that a failure is
	// logged when it starts and when it ends, not at every interval.
	failing := false

	for ctx.Err() == nil {
		if a.currentSession(conn) == nil {
			if !sleepCtx(ctx, retry) {
				return
			}
			if a.currentSession(conn) != nil {
				// A call has connected the backend meanwhile.
				retry = pace.retryMin
				continue
			}
			if err := a.connectBackend(ctx, name, conn); err != nil {
				if ctx.Err() != nil {
					return
				}
				retry = min(retry*2, pace.retryMax)
				a.logger.Warn("backend is not connected, trying again later",
					"name", name, "error", loggableError(err), "retry_in", retry.String())
				continue
			}
			retry = pace.retryMin
			failing = false
			continue
		}

		asked, ok := awaitWake(ctx, conn.wake, pace.refresh)
		if !ok {
			return
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

		session, err := a.refreshBackend(ctx, name, conn)
		switch {
		case ctx.Err() != nil:
			return
		case err == nil:
			if failing {
				a.logger.Info("tool list of backend can be read again", "name", name)
			}
			failing = false
		case errors.Is(err, errNotConnected), errors.Is(err, errSessionReplaced):
			// A call found the connection lost before the watcher did. It
			// has connected the backend again, which read the list, or has
			// left it without a session, which the next round takes up.
		case isConnectionClosed(err):
			// Replaced at once, without waiting for a call to run into it.
			a.logger.Warn("backend connection lost, connecting again", "name", name, "error", loggableError(err))
			if _, rerr := a.reconnectAfter(ctx, name, conn, session); rerr != nil && ctx.Err() == nil {
				a.logger.Warn("backend is not connected, trying again later",
					"name", name, "error", loggableError(rerr), "retry_in", retry.String())
			}
			failing = false
		default:
			// The backend keeps the list it had.
			if !failing {
				a.logger.Warn("reading the tool list of backend failed, keeping the list it had",
					"name", name, "error", loggableError(err))
			}
			failing = true
		}
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
// are, and of a name no more than maxLoggedToolNameLen bytes. A backend
// chooses the names and their number, so both are bounded here.
func loggedToolNames(names []string) []string {
	shown := min(len(names), maxLoggedToolNames)
	out := make([]string, 0, shown+1)
	for _, name := range names[:shown] {
		if len(name) > maxLoggedToolNameLen {
			name = strings.ToValidUTF8(name[:maxLoggedToolNameLen], "") + "..."
		}
		out = append(out, name)
	}
	if rest := len(names) - shown; rest > 0 {
		out = append(out, fmt.Sprintf("and %d more", rest))
	}
	return out
}
