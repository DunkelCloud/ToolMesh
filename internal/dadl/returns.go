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

package dadl

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// typeNameRe is the identifier grammar for `types` names (spec §6.5): they
// must be usable as TypeScript identifiers.
var typeNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// typesRefPrefix is the JSON Schema pointer prefix that resolves into the
// backend's `types` map (spec §6.5).
const typesRefPrefix = "#/backend/types/"

// schemaKeyRef is the JSON Schema $ref key.
const schemaKeyRef = "$ref"

// ReturnsToTS renders a tool's `returns` declaration (spec §6.5) as a
// TypeScript type, resolving bare type names and `$ref` pointers against
// the backend's `types` map. It errors on references that do not resolve —
// validators reject such documents (§15.2). A nil returns yields "any".
func ReturnsToTS(returns any, types map[string]any) (string, error) {
	if returns == nil {
		return tsAny, nil
	}
	return schemaToTS(returns, types, 0)
}

// maxSchemaDepth bounds inline-schema nesting so a malicious or cyclic
// document cannot recurse unboundedly.
const maxSchemaDepth = 20

// schemaToTS renders one schema node: a bare type name, a $ref pointer, or
// an inline schema map of the Section 10 subset.
func schemaToTS(node any, types map[string]any, depth int) (string, error) {
	if depth > maxSchemaDepth {
		return "", fmt.Errorf("schema nesting exceeds %d levels", maxSchemaDepth)
	}
	switch v := node.(type) {
	case string:
		// Bare type name — the DADL shorthand for a `types` entry.
		if !typeNameRe.MatchString(v) {
			return "", fmt.Errorf("type name %q is not a valid identifier", v)
		}
		if _, ok := types[v]; !ok {
			return "", fmt.Errorf("type %q is not declared in types", v)
		}
		return v, nil
	case map[string]any:
		return schemaMapToTS(v, types, depth)
	default:
		return "", fmt.Errorf("schema must be a type name or an object, got %T", node)
	}
}

// schemaMapToTS renders an inline schema object.
func schemaMapToTS(schema, types map[string]any, depth int) (string, error) {
	if ref, ok := schema[schemaKeyRef].(string); ok {
		name, found := strings.CutPrefix(ref, typesRefPrefix)
		if !found {
			return "", fmt.Errorf("$ref %q must start with %q", ref, typesRefPrefix)
		}
		if _, ok := types[name]; !ok {
			return "", fmt.Errorf("$ref %q does not resolve to a declared type", ref)
		}
		return name, nil
	}

	typ, _ := schema[schemaKeyType].(string)
	switch typ {
	case jsTypeArray:
		items, ok := schema[schemaKeyItems]
		if !ok {
			return tsAnyArray, nil
		}
		itemTS, err := schemaToTS(items, types, depth+1)
		if err != nil {
			return "", err
		}
		// Parenthesize compound item types so the [] binds correctly.
		if strings.ContainsAny(itemTS, " {|") {
			return "(" + itemTS + ")[]", nil
		}
		return itemTS + "[]", nil
	case jsTypeObject:
		props, _ := schema[schemaKeyProperties].(map[string]any)
		if len(props) == 0 {
			return tsRecordAny, nil
		}
		requiredSet := make(map[string]bool)
		if reqList, ok := schema[schemaKeyRequired].([]any); ok {
			for _, r := range reqList {
				if s, ok := r.(string); ok {
					requiredSet[s] = true
				}
			}
		}
		names := make([]string, 0, len(props))
		for name := range props {
			names = append(names, name)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			propTS, err := schemaToTS(props[name], types, depth+1)
			if err != nil {
				return "", fmt.Errorf("property %q: %w", name, err)
			}
			opt := "?"
			if requiredSet[name] {
				opt = ""
			}
			parts = append(parts, fmt.Sprintf("%s%s: %s", name, opt, propTS))
		}
		return "{ " + strings.Join(parts, "; ") + " }", nil
	case "":
		return "", fmt.Errorf("inline schema needs a type (or $ref)")
	default:
		return dadlTypeToTS(typ), nil
	}
}

// collectReferencedTypes walks a returns declaration and gathers every
// named `types` entry it references, following references between type
// definitions transitively.
func collectReferencedTypes(node any, types map[string]any, seen map[string]bool) {
	switch v := node.(type) {
	case string:
		if _, ok := types[v]; ok && !seen[v] {
			seen[v] = true
			collectReferencedTypes(types[v], types, seen)
		}
	case map[string]any:
		if ref, ok := v[schemaKeyRef].(string); ok {
			if name, found := strings.CutPrefix(ref, typesRefPrefix); found {
				collectReferencedTypes(name, types, seen)
			}
			return
		}
		for _, key := range []string{schemaKeyItems, schemaKeyProperties} {
			if sub, ok := v[key]; ok {
				if props, isMap := sub.(map[string]any); isMap && key == schemaKeyProperties {
					for _, propSchema := range props {
						collectReferencedTypes(propSchema, types, seen)
					}
					continue
				}
				collectReferencedTypes(sub, types, seen)
			}
		}
	}
}
