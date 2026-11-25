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
	"fmt"
	"sort"
	"strings"

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
func (r *backendsReloader) reload(ctx context.Context) error {
	res, err := r.build(ctx)
	if err != nil {
		return err
	}
	if clashes := unitNameClashes(res, r.units); len(clashes) > 0 {
		if res.mcpAdapter != nil {
			res.mcpAdapter.Close()
		}
		return fmt.Errorf("backends.yaml loads a backend under the name of a running unit (%s): rename the entry, or restart ToolMesh to let the entry replace the unit", strings.Join(clashes, ", "))
	}

	// The echo backend replaces an entry of the same name, as at startup.
	res.named["echo"] = r.echo
	for name, u := range r.units {
		res.named[name] = u
	}
	r.composite.Swap(res.named, res.passthroughs)
	r.userBackends.set(res.named)
	r.health.Replace(ctx, res.healthTargets)
	if r.applied != nil {
		r.applied(ctx, res)
	}
	return nil
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
