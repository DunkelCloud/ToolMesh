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
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// searchParams is the fixture the original report describes: a required
// object time window next to a required query and an optional limit.
func searchParams() map[string]ParamDef {
	return map[string]ParamDef{
		testParamQuery:     {Type: jsTypeString, In: paramInBody, Required: true},
		testParamTimeRange: {Type: "object", In: paramInBody, Required: true},
		testParamLimit:     {Type: "integer", In: testParamInQuery},
	}
}

func TestValidateParams(t *testing.T) {
	tests := []struct {
		name        string
		declared    map[string]ParamDef
		params      map[string]any
		wantUnknown []string
		wantMissing []string
	}{
		{
			name:     "complete call passes",
			declared: searchParams(),
			params:   map[string]any{testParamQuery: "x", testParamTimeRange: map[string]any{}, testParamLimit: 10},
		},
		{
			name:     "optional param may be omitted",
			declared: searchParams(),
			params:   map[string]any{testParamQuery: "x", testParamTimeRange: map[string]any{}},
		},
		{
			name:        "undeclared param is reported",
			declared:    searchParams(),
			params:      map[string]any{testParamQuery: "x", testParamTimeRange: map[string]any{}, testParamRange: 14400},
			wantUnknown: []string{testParamRange},
		},
		{
			name:        "missing required param is reported",
			declared:    searchParams(),
			params:      map[string]any{testParamQuery: "x"},
			wantMissing: []string{testParamTimeRange},
		},
		{
			name:        "both faults are reported together, each sorted",
			declared:    searchParams(),
			params:      map[string]any{"zzz": 1, "aaa": 2},
			wantUnknown: []string{"aaa", "zzz"},
			wantMissing: []string{testParamQuery, testParamTimeRange},
		},
		{
			name:        "path param is required without the flag",
			declared:    map[string]ParamDef{"id": {Type: jsTypeString, In: paramInPath}},
			params:      map[string]any{},
			wantMissing: []string{"id"},
		},
		{
			name:     "declared default satisfies required",
			declared: map[string]ParamDef{"v": {Type: jsTypeString, In: testParamInQuery, Required: true, Default: "2.0"}},
			params:   map[string]any{},
		},
		{
			name:     "explicit null satisfies a required body param",
			declared: map[string]ParamDef{testParamNote: {Type: jsTypeString, In: paramInBody, Required: true}},
			params:   map[string]any{testParamNote: nil},
		},
		{
			name:        "explicit null does not satisfy a required query param",
			declared:    map[string]ParamDef{testParamNote: {Type: jsTypeString, In: testParamInQuery, Required: true}},
			params:      map[string]any{testParamNote: nil},
			wantMissing: []string{testParamNote},
		},
		{
			name:        "explicit null does not satisfy a path param",
			declared:    map[string]ParamDef{"id": {Type: jsTypeString, In: paramInPath}},
			params:      map[string]any{"id": nil},
			wantMissing: []string{"id"},
		},
		{
			name:        "a tool without parameters rejects arguments",
			declared:    nil,
			params:      map[string]any{"anything": 1},
			wantUnknown: []string{"anything"},
		},
		{
			name:     "a tool without parameters accepts an empty call",
			declared: nil,
			params:   map[string]any{},
		},
		{
			name:     "composite params use required alone",
			declared: map[string]ParamDef{"q": {Type: jsTypeString, Required: true}, "n": {Type: "integer"}},
			params:   map[string]any{"q": "x"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateParams("t", tt.declared, tt.params)
			if len(tt.wantUnknown) == 0 && len(tt.wantMissing) == 0 {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			var perr *ParamError
			if !errors.As(err, &perr) {
				t.Fatalf("err = %v, want *ParamError", err)
			}
			if got := strings.Join(perr.Unknown, ","); got != strings.Join(tt.wantUnknown, ",") {
				t.Errorf("Unknown = %v, want %v", perr.Unknown, tt.wantUnknown)
			}
			if got := strings.Join(perr.MissingRequired, ","); got != strings.Join(tt.wantMissing, ",") {
				t.Errorf("MissingRequired = %v, want %v", perr.MissingRequired, tt.wantMissing)
			}
		})
	}
}

// TestParamError_UnwrapsToAPIError pins the §8.2 contract: a rejection has to
// reach composite JavaScript and Code Mode through the same fields as a 400
// the API itself returned, so errors.As must find the structured form.
func TestParamError_UnwrapsToAPIError(t *testing.T) {
	err := ValidateParams("search_messages", searchParams(), map[string]any{testParamRange: 1})

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("errors.As found no *APIError in %v", err)
	}
	if apiErr.Code != ErrCodeInvalidInput {
		t.Errorf("Code = %q, want %q", apiErr.Code, ErrCodeInvalidInput)
	}
	if apiErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want %d", apiErr.HTTPStatus, http.StatusBadRequest)
	}
	if apiErr.Message != err.Error() {
		t.Errorf("Message = %q, want the full complaint %q", apiErr.Message, err.Error())
	}
}

// TestParamError_Message checks that the text carries everything a caller
// needs to rewrite the call: the fault, the likely intended name, and the
// declared parameter set with its types and locations.
func TestParamError_Message(t *testing.T) {
	err := ValidateParams("search_messages", searchParams(), map[string]any{testParamQuery: "x", testParamRange: 14400})

	for _, want := range []string{
		`tool "search_messages"`,
		`unknown parameter "range" (did you mean "time_range"?)`,
		`missing required parameter "time_range"`,
		"declared parameters:",
		"limit (integer, in: query)",
		"query (string, in: body, required)",
		"time_range (object, in: body, required)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message = %q, want substring %q", err.Error(), want)
		}
	}
}

// TestParamError_MessageTruncatesWideTools keeps a tool with a very wide
// parameter set from burying the complaint under its own declaration.
func TestParamError_MessageTruncatesWideTools(t *testing.T) {
	declared := make(map[string]ParamDef, maxDeclaredParamsListed+5)
	for i := range maxDeclaredParamsListed + 5 {
		declared[fmt.Sprintf("p%03d", i)] = ParamDef{Type: jsTypeString, In: paramInBody}
	}

	err := ValidateParams("wide", declared, map[string]any{"nope": 1})
	if !strings.HasSuffix(err.Error(), "and 5 more") {
		t.Errorf("message = %q, want it to end by counting the parameters it did not list", err.Error())
	}
}

// TestParamError_NoParamsTool spells out the case where naming the declared
// set would produce an empty list.
func TestParamError_NoParamsTool(t *testing.T) {
	err := ValidateParams("ping", nil, map[string]any{"x": 1})
	if !strings.Contains(err.Error(), "this tool declares no parameters") {
		t.Errorf("message = %q, want it to say the tool declares no parameters", err.Error())
	}
}

func TestSuggestParam(t *testing.T) {
	declared := []string{testParamTimeRange, testParamQuery, testParamLimit, "project_id", testParamStreams}

	tests := []struct {
		name    string
		unknown string
		want    string
	}{
		{name: "dropped prefix", unknown: testParamRange, want: testParamTimeRange},
		{name: "camel case spelling", unknown: "timeRange", want: testParamTimeRange},
		{name: "kebab case spelling", unknown: "TIME-RANGE", want: testParamTimeRange},
		{name: "bare id", unknown: "id", want: "project_id"},
		{name: "typo within budget", unknown: "streems", want: testParamStreams},
		{name: "plural of a declared name", unknown: "limits", want: testParamLimit},
		{name: "nothing close enough", unknown: "authorization", want: ""},
		{name: "empty name", unknown: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := suggestParam(tt.unknown, declared); got != tt.want {
				t.Errorf("suggestParam(%q) = %q, want %q", tt.unknown, got, tt.want)
			}
		})
	}
}

func TestEditDistance(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{a: "", b: "", want: 0},
		{a: testStringABC, b: testStringABC, want: 0},
		{a: "", b: testStringABC, want: 3},
		{a: testStringABC, b: "", want: 3},
		{a: "kitten", b: "sitting", want: 3},
		{a: "streems", b: testParamStreams, want: 1},
		{a: "gruß", b: "gruss", want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.a+"/"+tt.b, func(t *testing.T) {
			if got := editDistance(tt.a, tt.b); got != tt.want {
				t.Errorf("editDistance(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
