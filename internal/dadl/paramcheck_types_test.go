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
		{"array", typesList, []any{"a"}, true},
		{"string for array", typesList, "a", false},
		{"object", typesAttrs, map[string]any{"k": "v"}, true},
		{"array for object", typesAttrs, []any{}, false},
		{"number for string passes", typesTitle, float64(7), true},
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
