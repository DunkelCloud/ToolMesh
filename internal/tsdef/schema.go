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

package tsdef

import "github.com/DunkelCloud/ToolMesh/internal/backend"

// ToInputSchema converts a ToolDef to a JSON Schema map.
func (t ToolDef) ToInputSchema() map[string]any {
	schema := map[string]any{
		"type": "object",
	}

	if len(t.Params) == 0 {
		schema["properties"] = map[string]any{}
		return schema
	}

	props := make(map[string]any)
	var required []any

	for _, p := range t.Params {
		props[p.Name] = paramToSchema(p)
		if p.Required {
			required = append(required, p.Name)
		}
	}

	schema["properties"] = props
	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}

// ToToolDescriptor converts a ToolDef to a backend.ToolDescriptor.
func (t ToolDef) ToToolDescriptor(backendName string) backend.ToolDescriptor {
	return backend.ToolDescriptor{
		Name:        t.Name,
		Description: t.Description,
		InputSchema: t.ToInputSchema(),
		Backend:     backendName,
	}
}

func paramToSchema(p ParamDef) map[string]any {
	s := make(map[string]any)

	if p.Description != "" {
		s["description"] = p.Description
	}

	if len(p.Enum) > 0 {
		s["type"] = kindString
		enumVals := make([]any, len(p.Enum))
		for i, v := range p.Enum {
			enumVals[i] = v
		}
		s["enum"] = enumVals
		return s
	}

	switch p.Type.Kind {
	case kindString:
		s["type"] = kindString
	case kindNumber:
		s["type"] = kindNumber
	case kindBoolean:
		s["type"] = kindBoolean
	case kindArray:
		s["type"] = kindArray
		if p.Type.ItemKind != "" && p.Type.ItemKind != kindAny {
			s["items"] = map[string]any{"type": p.Type.ItemKind}
		}
	case kindObject:
		s["type"] = kindObject
		if len(p.Type.Properties) > 0 {
			nested := make(map[string]any)
			var req []any
			for _, np := range p.Type.Properties {
				nested[np.Name] = paramToSchema(np)
				if np.Required {
					req = append(req, np.Name)
				}
			}
			s["properties"] = nested
			if len(req) > 0 {
				s["required"] = req
			}
		}
	default:
		// "any" — no type constraint
	}

	return s
}

// ToolDefFromSchema creates a ToolDef from a JSON Schema, enabling
// type coercion for externally discovered tools.
func ToolDefFromSchema(name, description string, schema map[string]any) ToolDef {
	td := ToolDef{
		Name:        name,
		Description: description,
	}

	props, _ := schema["properties"].(map[string]any)
	required := make(map[string]bool)
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if s, ok := r.(string); ok {
				required[s] = true
			}
		}
	}

	for pname, pval := range props {
		propMap, ok := pval.(map[string]any)
		if !ok {
			continue
		}

		param := ParamDef{
			Name:     pname,
			Required: required[pname],
		}

		if desc, ok := propMap["description"].(string); ok {
			param.Description = desc
		}

		if enumVals, ok := propMap["enum"].([]any); ok {
			for _, v := range enumVals {
				if s, ok := v.(string); ok {
					param.Enum = append(param.Enum, s)
				}
			}
			param.Type = ParamType{Kind: kindString}
		} else {
			param.Type = schemaTypeToParamType(propMap)
		}

		td.Params = append(td.Params, param)
	}

	return td
}

func schemaTypeToParamType(schema map[string]any) ParamType {
	t, _ := schema["type"].(string)
	switch t {
	case kindString:
		return ParamType{Kind: kindString}
	case kindNumber, "integer":
		return ParamType{Kind: kindNumber}
	case kindBoolean:
		return ParamType{Kind: kindBoolean}
	case kindArray:
		itemKind := kindAny
		if items, ok := schema["items"].(map[string]any); ok {
			if it, ok := items["type"].(string); ok {
				itemKind = it
			}
		}
		return ParamType{Kind: kindArray, ItemKind: itemKind}
	case kindObject:
		return ParamType{Kind: kindObject}
	default:
		return ParamType{Kind: kindAny}
	}
}
