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
	"io"
	"log/slog"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestCoerceToNumber(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
		err  bool
	}{
		{"float64", 3.14, 3.14, false},
		{"int", 42, float64(42), false},
		{"int64", int64(9), float64(9), false},
		{"json.Number", json.Number("1.5"), 1.5, false},
		{"string", "2.5", 2.5, false},
		{"invalid string", "nope", nil, true},
		{"bool true", true, float64(1), false},
		{"bool false", false, float64(0), false},
		{"other", []int{1}, []int{1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coerceToNumber(tc.in)
			if tc.err {
				if err == nil {
					t.Errorf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			switch w := tc.want.(type) {
			case float64:
				if got != w {
					t.Errorf("got %v, want %v", got, w)
				}
			}
		})
	}
}

func TestCoerceToBoolean(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want any
		err  bool
	}{
		{"bool", true, true, false},
		{"string true", "true", true, false},
		{"string yes", "yes", true, false},
		{"string 1", "1", true, false},
		{"string false", "false", false, false},
		{"string no", "no", false, false},
		{"string 0", "0", false, false},
		{"invalid string", "maybe", nil, true},
		{"float zero", 0.0, false, false},
		{"float nonzero", 1.0, true, false},
		{"int zero", 0, false, false},
		{"int nonzero", 5, true, false},
		{"pass through", []int{}, []int{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := coerceToBoolean(tc.in)
			if tc.err {
				if err == nil {
					t.Errorf("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if b, ok := tc.want.(bool); ok {
				if got != b {
					t.Errorf("got %v, want %v", got, b)
				}
			}
		})
	}
}

func TestCoerce_EnumMatching(t *testing.T) {
	c := NewCoercer([]ToolDef{
		{
			Name: "t",
			Params: []ParamDef{
				{Name: "x", Type: ParamType{Kind: "string"}, Enum: []string{"Alpha", "Beta"}},
			},
		},
	}, quietLogger())

	// Case-insensitive enum match returns canonical value.
	out, err := c.Coerce("t", map[string]any{"x": "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	if out["x"] != "Alpha" {
		t.Errorf("got %v, want Alpha", out["x"])
	}

	// Unknown enum value passes through.
	out, _ = c.Coerce("t", map[string]any{"x": "gamma"})
	if out["x"] != "gamma" {
		t.Errorf("got %v", out["x"])
	}
}

func TestCoerce_MissingRequiredExtra(t *testing.T) {
	c := NewCoercer([]ToolDef{
		{
			Name: "t",
			Params: []ParamDef{
				{Name: "x", Required: true, Type: ParamType{Kind: "string"}},
			},
		},
	}, quietLogger())

	_, err := c.Coerce("t", map[string]any{})
	if err == nil {
		t.Error("expected missing-required error")
	}
}

func TestCoerce_StripsUnknownFields(t *testing.T) {
	c := NewCoercer([]ToolDef{
		{
			Name: "t",
			Params: []ParamDef{
				{Name: "known", Type: ParamType{Kind: "string"}},
			},
		},
	}, quietLogger())

	out, _ := c.Coerce("t", map[string]any{"known": "v", "extra": "removed"})
	if _, ok := out["extra"]; ok {
		t.Error("extra field should be stripped")
	}
}

func TestCoerce_UnknownToolExtra(t *testing.T) {
	c := NewCoercer(nil, quietLogger())
	out, err := c.Coerce("unknown", map[string]any{"x": 1})
	if err != nil {
		t.Fatal(err)
	}
	if out["x"] != 1 {
		t.Error("expected unchanged passthrough")
	}
}

func TestAddDef(t *testing.T) {
	c := NewCoercer(nil, quietLogger())
	c.AddDef(ToolDef{Name: "new", Params: []ParamDef{{Name: "a", Type: ParamType{Kind: "number"}}}})
	out, err := c.Coerce("new", map[string]any{"a": "42"})
	if err != nil {
		t.Fatal(err)
	}
	if out["a"] != float64(42) {
		t.Errorf("got %v", out["a"])
	}
}

func TestCoerce_ArrayWrapping(t *testing.T) {
	c := NewCoercer([]ToolDef{
		{
			Name:   "t",
			Params: []ParamDef{{Name: "x", Type: ParamType{Kind: "array", ItemKind: "string"}}},
		},
	}, quietLogger())

	out, _ := c.Coerce("t", map[string]any{"x": "solo"})
	arr, ok := out["x"].([]any)
	if !ok || len(arr) != 1 || arr[0] != "solo" {
		t.Errorf("expected [solo], got %v", out["x"])
	}

	out, _ = c.Coerce("t", map[string]any{"x": []any{"a", "b"}})
	if arr, _ := out["x"].([]any); len(arr) != 2 {
		t.Errorf("expected 2 elements")
	}
}
