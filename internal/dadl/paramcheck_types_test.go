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
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
)

const (
	typesOn    = "on"
	typesCount = "item_count"
	typesRatio = "ratio"
	typesList  = "labels"
	typesAttrs = "attrs"
	typesTitle = "title"
	typesQuery = "query"
	expLiteral = "1e3"
)

func TestValidateParams_DeclaredTypes(t *testing.T) {
	declared := map[string]ParamDef{
		typesOn:    {Type: jsTypeBoolean, In: testParamBody},
		typesCount: {Type: jsTypeInteger, In: typesQuery},
		typesRatio: {Type: jsTypeNumber, In: typesQuery},
		typesList:  {Type: jsTypeArray, In: testParamBody},
		typesAttrs: {Type: jsTypeObject, In: testParamBody},
		typesTitle: {Type: jsTypeString, In: typesQuery},
	}
	cases := []struct {
		name  string
		param string
		val   any
		ok    bool
	}{
		{"bool true", typesOn, true, true},
		{"bool false", typesOn, false, true},
		{"string false for boolean", typesOn, "false", false},
		{"number for boolean", typesOn, float64(0), false},
		{"whole float for integer", typesCount, float64(3), true},
		{"fraction for integer", typesCount, 3.5, false},
		{"digits for integer", typesCount, "9007199254740993", true},
		{"signed digits for integer", typesCount, "-12", true},
		{"non-digits for integer", typesCount, "12a", false},
		{"json.Number for integer", typesCount, json.Number("42"), true},
		{"bool for integer", typesCount, true, false},
		{"float for number", typesRatio, 1.5, true},
		{"numeric string for number", typesRatio, "1.5", true},
		{"text for number", typesRatio, "abc", false},
		{"NaN string for number", typesRatio, "NaN", false},
		{"double sign for integer", typesCount, "-+5", false},
		{"exponent for integer", typesCount, expLiteral, false},
		{"padded integer", typesCount, " 5", false},
		{"exponent for number", typesRatio, expLiteral, true},
		{"padded number", typesRatio, " 5 ", false},
		{"hex float for number", typesRatio, "0x1p3", false},
		{"hex for number", typesRatio, "0x10", false},
		{"digit separator for number", typesRatio, "1_000", false},
		{"Infinity for number", typesRatio, "Infinity", false},
		{"inf for number", typesRatio, "inf", false},
		{"overflowing number", typesRatio, "1e999", false},
		{"array", typesList, []any{"a"}, true},
		{"string for array", typesList, "a", false},
		{"object", typesAttrs, map[string]any{"k": "v"}, true},
		{"array for object", typesAttrs, []any{}, false},
		{"number for string passes", typesTitle, float64(7), true},
		{"boolean for string passes", typesTitle, false, true},
		{"json.Number for string passes", typesTitle, json.Number("7"), true},
		{"array for string", typesTitle, []any{"a"}, false},
		{"object for string", typesTitle, map[string]any{"k": "v"}, false},
		{"BigInt for string", typesTitle, big.NewInt(42), false},
		{"null is not type-checked", typesOn, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateParams("t", declared, map[string]any{tc.param: tc.val})
			if tc.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.ok {
				if err == nil {
					t.Fatal("expected a type error")
				}
				var pe *ParamError
				if !errors.As(err, &pe) || pe.WrongType[tc.param] == "" {
					t.Fatalf("error does not name the parameter: %v", err)
				}
				if !strings.Contains(err.Error(), `parameter "`+tc.param+`" must be`) {
					t.Errorf("message = %q", err.Error())
				}
			}
		})
	}
}

func TestNormalizeParams(t *testing.T) {
	declared := map[string]ParamDef{
		typesOn:    {Type: jsTypeBoolean, In: testParamBody, Default: false},
		typesCount: {Type: jsTypeInteger, In: typesQuery},
		typesRatio: {Type: jsTypeNumber, In: typesQuery, Default: 0.5},
		typesTitle: {Type: jsTypeString, In: typesQuery},
		typesAttrs: {Type: jsTypeObject, In: testParamBody, Default: map[string]any{"k": "v"}},
	}
	in := map[string]any{typesCount: "+42", typesTitle: "007", typesAttrs: nil}
	out := NormalizeParams(declared, in)
	if out[typesOn] != false {
		t.Errorf("omitted boolean with default: %v", out[typesOn])
	}
	if out[typesCount] != float64(42) {
		t.Errorf("integer string: %v (%T), want 42", out[typesCount], out[typesCount])
	}
	if out[typesRatio] != 0.5 {
		t.Errorf("omitted number with default: %v", out[typesRatio])
	}
	if out[typesTitle] != "007" {
		t.Errorf("string parameter changed: %v", out[typesTitle])
	}
	if out[typesAttrs] != nil {
		t.Errorf("explicit null in the body must stay null: %v", out[typesAttrs])
	}
	if _, changed := in[typesOn]; changed {
		t.Error("NormalizeParams modified its input")
	}

	big := NormalizeParams(declared, map[string]any{typesCount: "9007199254740993"})
	if big[typesCount] != "9007199254740993" {
		t.Errorf("integer beyond 2^53 must stay an exact string: %v", big[typesCount])
	}
	num := NormalizeParams(declared, map[string]any{typesRatio: expLiteral})
	if num[typesRatio] != float64(1000) {
		t.Errorf("number string: %v", num[typesRatio])
	}
}

// TestNormalizeParams_StringParams pins that a number or boolean given for a
// string parameter reaches the gate as the text the request carries. Left
// as a number, a policy that forbids "42" was passed with 42 while the URL
// still read /projects/42.
func TestNormalizeParams_StringParams(t *testing.T) {
	declared := map[string]ParamDef{typesTitle: {Type: jsTypeString, In: typesQuery}}
	cases := []struct {
		name string
		val  any
		want string
	}{
		{"whole number", float64(42), "42"},
		{"fraction", 4.5, "4.5"},
		{"boolean true", true, "true"},
		{"boolean false", false, "false"},
		{"goja integer", int64(42), "42"},
		{"json.Number", json.Number("42"), "42"},
		{"large integer without exponent", float64(1234567), "1234567"},
		{"negative whole number", float64(-3), "-3"},
		{"string unchanged", "007", "007"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateParams("t", declared, map[string]any{typesTitle: tc.val}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			out := NormalizeParams(declared, map[string]any{typesTitle: tc.val})
			if got, ok := out[typesTitle].(string); !ok || got != tc.want {
				t.Errorf("normalized = %#v, want %q", out[typesTitle], tc.want)
			}
			if got := FormatScalar(tc.val); got != tc.want {
				t.Errorf("FormatScalar = %q, want the text the gate saw, %q", got, tc.want)
			}
		})
	}
}
