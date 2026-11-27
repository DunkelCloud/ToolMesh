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
	"sort"
	"strings"
	"sync"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/health"
)

// healthTargetReplacer is the part of the health monitor a reload uses.
type healthTargetReplacer interface {
	Replace(ctx context.Context, targets []health.Target)
}

// backendsReloader applies a changed backends.yaml to the running server.
//
// backends.yaml describes only part of the composite's children. The echo
// backend and the units are added once at startup and are not rebuilt by a
// reload, so the reloader puts them back into every new state. Units are
// kept, not loaded again: the watcher follows backends.yaml only, and a
// unit's sub-backend sessions should not restart because an unrelated entry
// changed. Changes to the units themselves take a restart.
//
// Every rebuild opens new sessions to all MCP backends, in an MCPAdapter of
// its own. The reloader closes the adapter a reload replaces, once the
// calls already running on it have returned (see retireLocked), and close ends
// the adapter in use at shutdown.
type backendsReloader struct {
	// build rebuilds the backends from backends.yaml (buildBackends).
	build     func(ctx context.Context) (*backendsResult, error)
	composite *backend.CompositeBackend
	echo      backend.ToolBackend
	// units are the units loaded at startup, by name.
	units        map[string]backend.ToolBackend
	userBackends *userBackendRegistry
	health       healthTargetReplacer
	// applied, when set, runs after a new state has been published.
	applied func(ctx context.Context, res *backendsResult)

	// mu guards the fields below.
	mu sync.Mutex
	// adapter is the MCPAdapter of the backends the composite routes to
	// now: set at startup, replaced by every successful reload.
	adapter *backend.MCPAdapter
	// retiring holds the adapters of replaced backends that still run calls.
	retiring map[*backend.MCPAdapter]struct{}
	// stop is closed by close, which ends the waits for retiring adapters.
	stop chan struct{}
	// closed is set by close; a reload after it publishes nothing.
	closed bool
	// closing counts the waits for retiring adapters, for the tests.
	closing sync.WaitGroup
}

// reload rebuilds the backends from backends.yaml and swaps them in, together
// with the echo backend and the units. When it returns an error, the
// composite, the user backend registry and the health monitor keep the
// backends they had. (A rebuild that got as far as dividing the credential
// names leaves the new division in place; buildBackends explains why that is
// safe.)
//
// A configuration that loads a backend under the name of a running unit is
// refused as a whole, and the MCP sessions it opened are closed. Applying it
// would either take the name away from the unit or leave the backend
// shadowed by it. On a restart the backend wins and the unit is skipped, as
// loadUnits does at startup.
//
// After a successful reload the MCPAdapter of the previous backends is
// closed once the calls running on it have returned; a failed reload leaves
// it running.
func (r *backendsReloader) reload(ctx context.Context) error {
	res, err := r.build(ctx)
	if err != nil {
		return err
	}
	if clashes := unitNameClashes(res, r.units); len(clashes) > 0 {
		closeAdapter(res.mcpAdapter)
		return fmt.Errorf("backends.yaml loads a backend under the name of a running unit (%s): rename the entry, or restart ToolMesh to let the entry replace the unit", strings.Join(clashes, ", "))
	}

	// The echo backend replaces an entry of the same name, as at startup.
	res.named["echo"] = r.echo
	for name, u := range r.units {
		res.named[name] = u
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		closeAdapter(res.mcpAdapter)
		return errors.New("ToolMesh is shutting down")
	}
	drained := r.composite.Swap(res.named, res.passthroughs)
	previous := r.adapter
	r.adapter = res.mcpAdapter
	r.retireLocked(previous, drained)
	r.mu.Unlock()

	r.userBackends.set(res.named)
	r.health.Replace(ctx, res.healthTargets)
	if r.applied != nil {
		r.applied(ctx, res)
	}
	return nil
}

// retireLocked closes a, the MCPAdapter of backends a reload has replaced,
// once drained is closed: when every call the composite routed to a before
// the swap has returned. Calls that start after the swap reach the new
// adapter, a script in execute_code included, so the wait ends with the
// slowest call that was running, at the latest after the call timeout
// (TOOLMESH_EXEC_TIMEOUT) the executor sets for each backend call. Closing
// earlier, after a fixed grace period, would cut off a longer call, and the
// adapter's reconnect on a closed session would open a new one that nobody
// closes. The caller holds r.mu.
func (r *backendsReloader) retireLocked(a *backend.MCPAdapter, drained <-chan struct{}) {
	if a == nil {
		return
	}
	if r.retiring == nil {
		r.retiring = make(map[*backend.MCPAdapter]struct{})
	}
	r.retiring[a] = struct{}{}
	stop := r.stopLocked()
	r.closing.Add(1)
	go func() {
		defer r.closing.Done()
		select {
		case <-drained:
		case <-stop:
			return // close has taken the adapter over
		}
		r.mu.Lock()
		_, ok := r.retiring[a]
		delete(r.retiring, a)
		r.mu.Unlock()
		if ok {
			a.Close()
		}
	}()
}

// stopLocked returns r.stop, made on first use. The caller holds r.mu.
func (r *backendsReloader) stopLocked() chan struct{} {
	if r.stop == nil {
		r.stop = make(chan struct{})
	}
	return r.stop
}

// close closes the MCPAdapter of the current backends and those of replaced
// backends whose calls have not all returned yet. A reload that finishes
// afterwards closes the adapter it built and publishes nothing. main runs
// close at shutdown.
func (r *backendsReloader) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	adapters := make([]*backend.MCPAdapter, 0, len(r.retiring)+1)
	if r.adapter != nil {
		adapters = append(adapters, r.adapter)
	}
	for a := range r.retiring {
		adapters = append(adapters, a)
	}
	r.adapter, r.retiring = nil, nil
	close(r.stopLocked())
	r.mu.Unlock()
	for _, a := range adapters {
		a.Close()
	}
}

// currentAdapter returns the MCPAdapter of the backends the composite
// routes to now.
func (r *backendsReloader) currentAdapter() *backend.MCPAdapter {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.adapter
}

// closeAdapter closes a, when there is one.
func closeAdapter(a *backend.MCPAdapter) {
	if a != nil {
		a.Close()
	}
}

// unitNameClashes returns, sorted, the names of units that a rebuilt
// configuration also routes: a named REST or SSH backend, or an MCP backend
// of a passthrough. These are the names loadUnits refuses at startup.
func unitNameClashes(res *backendsResult, units map[string]backend.ToolBackend) []string {
	if len(units) == 0 {
		return nil
	}
	taken := make(map[string]struct{}, len(res.named))
	for name := range res.named {
		taken[name] = struct{}{}
	}
	for _, p := range res.passthroughs {
		sum, ok := p.(backend.BackendSummarizer)
		if !ok {
			continue
		}
		for _, info := range sum.BackendSummaries() {
			taken[info.Name] = struct{}{}
		}
	}
	var clashes []string
	for name := range units {
		if _, ok := taken[name]; ok {
			clashes = append(clashes, name)
		}
	}
	sort.Strings(clashes)
	return clashes
}
