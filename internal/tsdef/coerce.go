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

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

// Coercer applies type coercion to tool parameters based on ToolDef definitions.
// This provides tolerance for LLM-generated tool calls where types may not match
// exactly (e.g., sending "5" instead of 5 for a number parameter).
type Coercer struct {
	defs   map[string]ToolDef
	logger *slog.Logger
}

// NewCoercer creates a Coercer from a list of tool definitions.
func NewCoercer(defs []ToolDef, logger *slog.Logger) *Coercer {
	m := make(map[string]ToolDef, len(defs))
	for _, d := range defs {
		m[d.Name] = d
	}
	return &Coercer{defs: m, logger: logger}
}

// AddDef registers an additional tool definition for coercion.
func (c *Coercer) AddDef(def ToolDef) {
	c.defs[def.Name] = def
}

// Coerce applies type coercion to the given parameters based on the tool definition.
// If no definition exists for the tool, params are returned unchanged.
func (c *Coercer) Coerce(toolName string, params map[string]any) (map[string]any, error) {
	def, ok := c.defs[toolName]
	if !ok {
		return params, nil
	}

	result := make(map[string]any)
	knownParams := make(map[string]bool)

	for _, p := range def.Params {
		knownParams[p.Name] = true
		val, exists := params[p.Name]

		if !exists {
			if p.Required {
				return nil, fmt.Errorf("missing required parameter %q for tool %q", p.Name, toolName)
			}
			continue
		}

		coerced, err := coerceValue(val, p)
		if err != nil {
			return nil, fmt.Errorf("parameter %q: %w", p.Name, err)
		}
		result[p.Name] = coerced
	}

	// Strip unknown fields with a warning
	for k, v := range params {
		if !knownParams[k] {
			c.logger.Warn("stripping unknown parameter",
				"tool", toolName,
				"param", k,
				"value", v,
			)
		}
	}

	return result, nil
}

func coerceValue(val any, p ParamDef) (any, error) {
	// Handle enum with case-insensitive matching
	if len(p.Enum) > 0 {
		s := fmt.Sprintf("%v", val)
		for _, e := range p.Enum {
			if strings.EqualFold(s, e) {
				return e, nil
			}
		}
		return val, nil // pass through, let backend reject if needed
	}

	switch p.Type.Kind {
	case "number":
		return coerceToNumber(val)
	case "boolean":
		return coerceToBoolean(val)
	case "string":
		return coerceToString(val), nil
	case "array":
		return coerceToArray(val, p.Type.ItemKind)
	case "any":
		return val, nil
	default:
		return val, nil
	}
}

func coerceToNumber(val any) (any, error) {
	switch v := val.(type) {
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case int64:
		return float64(v), nil
	case json.Number:
		return v.Float64()
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, fmt.Errorf("cannot coerce %q to number", v)
		}
		return f, nil
	case bool:
		if v {
			return float64(1), nil
		}
		return float64(0), nil
	default:
		return val, nil
	}
}

func coerceToBoolean(val any) (any, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			return true, nil
		case "false", "0", "no":
			return false, nil
		default:
			return nil, fmt.Errorf("cannot coerce %q to boolean", v)
		}
	case float64:
		return v != 0, nil
	case int:
		return v != 0, nil
	default:
		return val, nil
	}
}

func coerceToString(val any) any {
	switch v := val.(type) {
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}

func coerceToArray(val any, itemKind string) (any, error) {
	// If already a slice, return as-is
	if arr, ok := val.([]any); ok {
		return arr, nil
	}
	// Wrap single value in array
	return []any{val}, nil
}
