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
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func init() {
	Register("echo", func(_ map[string]any) (ToolBackend, error) {
		return NewEchoBackend(), nil
	})
}

// EchoBackend is a built-in backend for testing and demonstration.
// It provides simple tools that work without any external dependencies.
// Tool definitions are loaded from TypeScript files when available,
// falling back to hardcoded schemas.
type EchoBackend struct {
	toolDefs []ToolDescriptor // populated from TS defs or fallback
}

// NewEchoBackend creates a new EchoBackend with fallback hardcoded schemas.
func NewEchoBackend() *EchoBackend {
	return &EchoBackend{toolDefs: defaultEchoTools()}
}

// NewEchoBackendWithDefs creates an EchoBackend with tool definitions
// sourced from parsed TypeScript files.
func NewEchoBackendWithDefs(defs []ToolDescriptor) *EchoBackend {
	return &EchoBackend{toolDefs: defs}
}

// Execute runs the specified echo tool.
func (b *EchoBackend) Execute(_ context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	switch toolName {
	case "echo":
		return b.echo(params)
	case "add":
		return b.add(params)
	case "time":
		return b.currentTime()
	default:
		return nil, fmt.Errorf("unknown echo tool: %s", toolName)
	}
}

// ListTools returns the tools provided by the echo backend.
func (b *EchoBackend) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	return b.toolDefs, nil
}

// defaultEchoTools returns fallback tool definitions when no TS files are available.
func defaultEchoTools() []ToolDescriptor {
	return []ToolDescriptor{
		{
			Name:        "echo",
			Description: "Echoes back the input message",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message": map[string]any{
						"type":        "string",
						"description": "Message to echo back",
					},
				},
				"required": []any{"message"},
			},
			Backend: "builtin:echo",
		},
		{
			Name:        "add",
			Description: "Adds two numbers",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"a": map[string]any{"type": "number", "description": "First number"},
					"b": map[string]any{"type": "number", "description": "Second number"},
				},
				"required": []any{"a", "b"},
			},
			Backend: "builtin:echo",
		},
		{
			Name:        "time",
			Description: "Returns the current UTC time",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			Backend: "builtin:echo",
		},
	}
}

// Healthy always returns nil.
func (b *EchoBackend) Healthy(_ context.Context) error {
	return nil
}

func (b *EchoBackend) echo(params map[string]any) (*ToolResult, error) {
	msg, _ := params["message"].(string)
	if msg == "" {
		msg = "(empty)"
	}
	return textResult(msg), nil
}

func (b *EchoBackend) add(params map[string]any) (*ToolResult, error) {
	a, okA := toFloat64(params["a"])
	bv, okB := toFloat64(params["b"])
	if !okA || !okB {
		return textResult("error: both 'a' and 'b' must be numbers"), nil
	}
	sum := a + bv

	// Format without trailing zeros
	text := strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", sum), "0"), ".")
	return textResult(text), nil
}

func (b *EchoBackend) currentTime() (*ToolResult, error) {
	return textResult(time.Now().UTC().Format(time.RFC3339)), nil
}

func textResult(text string) *ToolResult {
	return &ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": text,
		}},
	}
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
