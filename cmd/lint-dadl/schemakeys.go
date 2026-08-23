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
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// defaultSchemaPath is where the canonical schema lives in this repository.
// Resolved relative to the working directory, so running the linter from the
// repository root picks it up with no flag.
const defaultSchemaPath = "docs/schema/dadl-v0.2.schema.json"

// unknownKeyNameRe pulls the offending key out of a §15.3 warning, whose shape
// is fixed by dadl.unknownKeyWarnings: `unknown key "<name>" in <context> …`.
var unknownKeyNameRe = regexp.MustCompile(`^unknown key "([^"]+)"`)

// specKeys is the set of property names the canonical DADL schema defines,
// anywhere in the document. It answers one question about a key the runtime
// did not implement: is this something the spec defines, or something the
// author invented?
//
// The two look identical in a runtime warning and call for opposite fixes. A
// spec-defined key means the file is correct and the runtime is behind — that
// is a ToolMesh task, and failing the author's build for it would be wrong.
// An invented key means the file is wrong, and nothing will ever honor it.
// `max_body_size` was the former for months; `next_link_header` is the latter.
//
// Deliberate limitation: the check is by name, not by position. A key the spec
// defines somewhere else but that is misplaced here reads as spec-defined and
// is reported as a warning. Catching placement needs the full schema, which
// the registry's Ajv pass already applies to everything published; this is the
// slice that works with no schema engine and no second copy of the rules.
type specKeys map[string]bool

// loadSpecKeys reads the canonical schema and collects every property name it
// declares. A nil result (with no error) means classification is unavailable
// and every unimplemented key stays an error — the fail-closed reading.
func loadSpecKeys(path string) (specKeys, error) {
	explicit := path != ""
	if !explicit {
		path = defaultSchemaPath
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path to a local schema file
	if err != nil {
		if !explicit && os.IsNotExist(err) {
			return nil, nil // no schema at hand; caller degrades to strict
		}
		return nil, fmt.Errorf("read schema %q: %w", path, err)
	}

	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse schema %q: %w", path, err)
	}

	keys := make(specKeys)
	collectPropertyNames(root, keys)
	if len(keys) == 0 {
		return nil, fmt.Errorf("schema %q declares no properties", path)
	}
	return keys, nil
}

// collectPropertyNames walks a decoded JSON Schema and records the name of
// every entry under a "properties" object, at any depth.
func collectPropertyNames(node any, into specKeys) {
	switch n := node.(type) {
	case map[string]any:
		for key, value := range n {
			if key == "properties" {
				if props, ok := value.(map[string]any); ok {
					for name := range props {
						into[name] = true
					}
				}
			}
			collectPropertyNames(value, into)
		}
	case []any:
		for _, item := range n {
			collectPropertyNames(item, into)
		}
	}
}

// definedBySpec reports whether a §15.3 unknown-key warning names a key the
// spec defines. False when the key is unknown to the spec, or when the
// warning is not of that shape, or when no schema was loaded.
func (s specKeys) definedBySpec(warning string) bool {
	if s == nil {
		return false
	}
	m := unknownKeyNameRe.FindStringSubmatch(warning)
	if m == nil {
		return false
	}
	return s[m[1]]
}
