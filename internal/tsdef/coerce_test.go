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
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestCoerce_StringToNumber(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: "n", Type: ParamType{Kind: kindNumber}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce(testToolName, map[string]any{"n": "42"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["n"] != float64(42) {
		t.Errorf("n = %v (%T), want float64(42)", result["n"], result["n"])
	}
}

func TestCoerce_StringToBoolean(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: "b", Type: ParamType{Kind: kindBoolean}, Required: true}},
	}}, testLogger())

	tests := []struct {
		input string
		want  bool
	}{
		{boolTrue, true},
		{boolFalse, false},
		{"1", true},
		{"0", false},
		{testTokenYes, true},
		{"no", false},
	}

	for _, tt := range tests {
		result, err := c.Coerce(testToolName, map[string]any{"b": tt.input})
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
		Name:   testToolName,
		Params: []ParamDef{{Name: "s", Type: ParamType{Kind: kindString}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce(testToolName, map[string]any{"s": 42})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["s"] != "42" {
		t.Errorf("s = %v, want \"42\"", result["s"])
	}
}

func TestCoerce_SingleToArray(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: testParamTags, Type: ParamType{Kind: kindArray, ItemKind: kindString}, Required: true}},
	}}, testLogger())

	result, err := c.Coerce(testToolName, map[string]any{testParamTags: "single"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	arr, ok := result[testParamTags].([]any)
	if !ok || len(arr) != 1 {
		t.Errorf("expected array with 1 element, got %v", result[testParamTags])
	}
}

// TestCoerce_RejectsExtraFields covers an argument the definition does not
// declare. Coercion rebuilds the parameter map from the declared set, so such
// an argument can never reach the tool — the call has to fail rather than run
// with the argument quietly discarded.
func TestCoerce_RejectsExtraFields(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: "a", Type: ParamType{Kind: kindString}, Required: true}},
	}}, testLogger())

	_, err := c.Coerce(testToolName, map[string]any{"a": "ok", "unknown": "drop me"})
	if err == nil {
		t.Fatal("err = nil, want the undeclared parameter rejected")
	}
	for _, want := range []string{`unknown parameter(s) "unknown"`, `declared parameters: "a"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want substring %q", err, want)
		}
	}
}

func TestCoerce_MissingRequired(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: "req", Type: ParamType{Kind: kindString}, Required: true}},
	}}, testLogger())

	_, err := c.Coerce(testToolName, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing required param")
	}
}

func TestCoerce_MissingOptional(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name:   testToolName,
		Params: []ParamDef{{Name: "opt", Type: ParamType{Kind: kindString}, Required: false}},
	}}, testLogger())

	result, err := c.Coerce(testToolName, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, exists := result["opt"]; exists {
		t.Error("optional missing param should not be in result")
	}
}

func TestCoerce_EnumCaseInsensitive(t *testing.T) {
	c := NewCoercer([]ToolDef{{
		Name: testToolName,
		Params: []ParamDef{{
			Name: testParamDir, Type: ParamType{Kind: kindString}, Required: true,
			Enum: []string{"up", "down"},
		}},
	}}, testLogger())

	result, err := c.Coerce(testToolName, map[string]any{testParamDir: "UP"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result[testParamDir] != "up" {
		t.Errorf("dir = %v, want \"up\"", result[testParamDir])
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
