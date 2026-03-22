package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// EchoBackend is a built-in backend for testing and demonstration.
// It provides simple tools that work without any external dependencies.
type EchoBackend struct{}

// NewEchoBackend creates a new EchoBackend.
func NewEchoBackend() *EchoBackend {
	return &EchoBackend{}
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
	}, nil
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
