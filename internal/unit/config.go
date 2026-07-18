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

// Package unit implements Unit-Backends: a top-level construct that bundles
// several private MCP/REST sub-backends behind a single JavaScript glue
// module. The glue calls api.<sub_backend>.<tool>(args) to compose calls,
// and exports its own tool surface via describe().
//
// Unit-Backends are loaded from <units_dir>/<name>/unit.yaml. Their
// sub-backends are not registered in the global ToolBackend registry — they
// are reachable only from within the owning unit's sandbox.
package unit

import (
	"github.com/DunkelCloud/ToolMesh/internal/backend"
)

// Config is the on-disk YAML schema for one unit.yaml file.
//
// The Backends field reuses the same BackendEntry shape as the top-level
// config/backends.yaml so unit authors do not need to learn a new syntax for
// declaring private MCP or REST dependencies.
type Config struct {
	// Unit is the unit's external name; tools are surfaced as
	// "<unit>_<tool>" by the composite backend, matching the convention
	// applied to MCP and REST backends.
	Unit string `yaml:"unit"`

	// Implementation is the path to the JavaScript glue file, resolved
	// relative to the unit.yaml's own directory.
	Implementation string `yaml:"implementation"`

	// Expose controls how the unit's _meta block is propagated to the
	// caller and to the audit trail. The fields are intentionally generic;
	// trust-tier mapping lives entirely in the tenant-config and the
	// output gate, never in the unit.
	Expose ExposeConfig `yaml:"expose"`

	// Backends declares the unit's private dependencies. The entries use
	// the exact same shape as config/backends.yaml entries; the only
	// difference is scope — these backends are not reachable from the
	// global tool surface and are not subject to OpenFGA permissions
	// independently from the owning unit.
	Backends []backend.BackendEntry `yaml:"backends"`
}

// ExposeConfig controls the unit's externally observable side channels.
type ExposeConfig struct {
	// MetaSignals lists the raw signal keys that the unit may emit in
	// the result's _meta block. The output gate uses this list to decide
	// what to pass through versus strip; tenant-config maps these signals
	// to internal trust tiers.
	MetaSignals []string `yaml:"meta_signals"`

	// Audit selects the audit detail level. One of "full", "compact",
	// "none". Empty defaults to "full".
	Audit string `yaml:"audit"`

	// Tools lists the describe()-declared tool names to promote to direct
	// top-level MCP tools, in addition to their always-available reachability
	// through discover_tools / execute_code. This mirrors the backends.yaml
	// expose_tools field but lives under expose: so a unit keeps a single
	// expose block.
	//
	// Unlike REST/MCP backends, unit tools are promoted under their full
	// "<unit>_<tool>" name, never a bare alias: unit tool names are frequently
	// generic ("search", "roll"), so a bare root-level name would be ambiguous
	// or collide. The promoted name therefore matches what discover_tools and
	// execute_code already show. An entry that names no describe() tool is
	// logged once at load time and skipped.
	Tools []string `yaml:"tools"`
}
