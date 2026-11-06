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
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// schemaKeyPatternProperties is the JSON Schema keyword that admits
// properties by name pattern; a schema using it leaves its property set open.
const schemaKeyPatternProperties = "patternProperties"

// validateMCPParams checks a call's arguments against the input schema the
// MCP backend advertised for the tool at discovery, so the call fails here,
// with the same error a REST tool raises for the same mistake, instead of
// at the backend with whatever the backend says. The backend's own
// complaint was the only signal before, and it rarely names the parameters
// it would have accepted — the caller was left to guess again.
//
// The check reuses the DADL parameter check: an undeclared argument and a
// missing required one are reported together, the closest declared name is
// suggested for a misspelling (`topK` for `top_k`), and the declared set
// is listed. Only the top level of the schema is read.
//
// An absent `additionalProperties` means "allowed" in JSON Schema, but the
// servers built on the common MCP SDKs do not use such an argument: the Go
// and TypeScript SDKs close their schemas and reject it, the Python SDK
// ignores it. Either way the call does not do what the caller wrote, so an
// undeclared argument is an error unless the schema opens its property set
// on purpose (`additionalProperties` true or a schema, or
// `patternProperties`), where only the required rule applies. A schema that
// declares no properties and does not close the set is not checked at all.
func validateMCPParams(toolName string, schema, params map[string]any) error {
	declared, ok := schemaParamDefs(schema)
	if !ok {
		return nil
	}
	if schemaAdmitsUnknown(schema) {
		return dadl.ValidateRequiredParams(toolName, declared, params)
	}
	return dadl.ValidateParams(toolName, declared, params)
}

// schemaParamDefs derives the parameter declaration the DADL check works
// on from a JSON Schema object: one entry per property, with its type where
// the schema names one, and required where the schema lists it. ok is false
// when there is nothing to check against — no properties, no required
// names, and the set not closed explicitly.
func schemaParamDefs(schema map[string]any) (map[string]dadl.ParamDef, bool) {
	props, _ := schema[schemaKeyProperties].(map[string]any)
	required := schemaRequiredNames(schema)
	declared := make(map[string]dadl.ParamDef, len(props)+len(required))
	for name, raw := range props {
		declared[name] = dadl.ParamDef{Type: schemaPropertyType(raw)}
	}
	for _, name := range required {
		def := declared[name]
		def.Required = true
		declared[name] = def
	}
	if len(declared) == 0 && !schemaClosesSet(schema) {
		return nil, false
	}
	return declared, true
}

// schemaClosesSet reports an explicit `additionalProperties: false`: with
// nothing declared, every argument is then undeclared, which is worth
// saying before the backend says it less clearly.
func schemaClosesSet(schema map[string]any) bool {
	v, ok := schema[schemaKeyAdditionalProperties].(bool)
	return ok && !v
}

// schemaAdmitsUnknown reports whether the schema admits properties beyond
// the declared ones on purpose: `additionalProperties` set to true or to a
// schema, or `patternProperties` naming any pattern.
func schemaAdmitsUnknown(schema map[string]any) bool {
	switch v := schema[schemaKeyAdditionalProperties].(type) {
	case bool:
		if v {
			return true
		}
	case map[string]any:
		return true
	}
	patterns, ok := schema[schemaKeyPatternProperties].(map[string]any)
	return ok && len(patterns) > 0
}

// schemaRequiredNames reads the `required` list, which arrives as []any
// from JSON and as []string from Go-built schemas.
func schemaRequiredNames(schema map[string]any) []string {
	switch list := schema[schemaKeyRequired].(type) {
	case []string:
		return list
	case []any:
		names := make([]string, 0, len(list))
		for _, item := range list {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
		return names
	}
	return nil
}

// schemaPropertyType renders a property's `type` for the error message: the
// name as declared, a union joined with "|" where the schema allows several,
// or "" where the property says nothing about its type.
func schemaPropertyType(raw any) string {
	prop, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	switch t := prop[schemaKeyType].(type) {
	case string:
		return t
	case []any:
		names := make([]string, 0, len(t))
		for _, item := range t {
			if name, ok := item.(string); ok {
				names = append(names, name)
			}
		}
		return strings.Join(names, "|")
	case []string:
		return strings.Join(t, "|")
	}
	return ""
}
