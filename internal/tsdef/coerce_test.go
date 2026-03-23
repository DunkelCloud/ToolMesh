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
	"log/slog"
	"os"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestCoerce_StringToNumber(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "n", Type: ParamType{Kind: "number"}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{"n": "42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["n"] != float64(42) {
		t.Errorf("n = %v (%T), want float64(42)", result["n"], result["n"])
	}
}

func TestCoerce_StringToBoolean(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "b", Type: ParamType{Kind: "boolean"}, Required: true}},
	}}, testLogger())

	tests := []struct {
		input string
		want  bool
	}{
		{"true", true},
		{"false", false},
		{"1", true},
		{"0", false},
		{"yes", true},
		{"no", false},
	}

	for _, tt := range tests {
		result, err := c.Coerce("test", map[string]any{"b": tt.input})
		if err != nil {
			t.Fatalf("input %q: unexpected error: %v", tt.input, err)
		}
		if result["b"] != tt.want {
			t.Errorf("input %q: got %v, want %v", tt.input, result["b"], tt.want)
		}
	}
}

func TestCoerce_NumberToString(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "s", Type: ParamType{Kind: "string"}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{"s": 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["s"] != "42" {
		t.Errorf("s = %v, want \"42\"", result["s"])
	}
}

func TestCoerce_SingleToArray(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "tags", Type: ParamType{Kind: "array", ItemKind: "string"}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{"tags": "single"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := result["tags"].([]any)
	if !ok || len(arr) != 1 {
		t.Errorf("expected array with 1 element, got %v", result["tags"])
	}
}

func TestCoerce_StripExtraFields(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "a", Type: ParamType{Kind: "string"}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{"a": "ok", "unknown": "strip me"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result["unknown"]; exists {
		t.Error("unknown field should be stripped")
	}
	if result["a"] != "ok" {
		t.Error("known field should be preserved")
	}
}

func TestCoerce_MissingRequired(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "req", Type: ParamType{Kind: "string"}, Required: true}},
	}}, testLogger())

	_, err := c.Coerce("test", map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing required param")
	}
}

func TestCoerce_MissingOptional(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   "test",
		Params: []ParamDef{{Name: "opt", Type: ParamType{Kind: "string"}, Required: false}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result["opt"]; exists {
		t.Error("optional missing param should not be in result")
	}
}

func TestCoerce_EnumCaseInsensitive(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name: "test",
		Params: []ParamDef{{
			Name: "dir", Type: ParamType{Kind: "string"}, Required: true,
			Enum: []string{"up", "down"},
		}},
	}}, testLogger())

	result, err := c.Coerce("test", map[string]any{"dir": "UP"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["dir"] != "up" {
		t.Errorf("dir = %v, want \"up\"", result["dir"])
	}
}

func TestCoerce_UnknownTool(t *testing.T) {
	c := NewCoercer(nil, testLogger())

	result, err := c.Coerce("unknown", map[string]any{"a": "b"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["a"] != "b" {
		t.Error("unknown tool params should pass through unchanged")
	}
}
