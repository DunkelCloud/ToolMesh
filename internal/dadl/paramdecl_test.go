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
	"reflect"
	"strings"
	"testing"
)

// declDoc is a DADL with one tool and one composite, each with a parameter
// "p" whose declaration replaces TOOLDECL and COMPDECL.
const declDoc = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: decl
  type: rest
  base_url: "https://api.example.com"
  description: "Declarations"
  auth:
    type: bearer
    credential: none
  tools:
    list_things:
      method: GET
      path: /things
      description: "List"
      params:
        p:
TOOLDECL
  composites:
    summarize:
      description: "Summarize"
      code: "return 1;"
      params:
        p:
COMPDECL
`

// declPlain is the declaration of a parameter that needs no attention.
const declPlain = "type: string"

// declYAML renders declDoc with decl, one YAML line per element of its
// lines, as the declaration of the tool's parameter or, with composite, of
// the composite's. The other parameter is declared plainly.
func declYAML(decl string, composite bool) string {
	indent := func(d string) string {
		return "          " + strings.ReplaceAll(d, "\n", "\n          ")
	}
	const where = "\nin: query"
	tool, comp := declPlain+where, declPlain
	if composite {
		comp = decl
	} else {
		tool = decl + where
	}
	return strings.NewReplacer("TOOLDECL", indent(tool), "COMPDECL", indent(comp)).Replace(declDoc)
}

// TestParse_ParamTypesAndDefaults pins what a DADL may declare for a
// parameter, of a tool and of a composite alike: one of the types of the
// DADL schema, and a default that fits it. A parameter without a type or
// with a type the runtime does not know would take any value unchecked,
// and a default of another type would reach a gate policy and the API in a
// form no caller may send.
func TestParse_ParamTypesAndDefaults(t *testing.T) {
	cases := []struct {
		name    string
		decl    string
		wantErr string
	}{
		{"plain text", declPlain, ""},
		{"whole number with default", "type: integer\ndefault: 10", ""},
		{"whole number with digits as text", "type: integer\ndefault: \"10\"", ""},
		{"decimal with default", "type: number\ndefault: 0.5", ""},
		{"switch with default", "type: boolean\ndefault: false", ""},
		{"text with a number as default", "type: string\ndefault: 42", ""},
		{"list with default", "type: array\ndefault: [a, b]", ""},
		{"map with default", "type: object\ndefault: {a: 1}", ""},
		{"no type", "description: \"untyped\"", "has no type"},
		{"short name of boolean", "type: bool", `unknown type "bool"`},
		{"short name of integer", "type: int", `unknown type "int"`},
		{"capitalized type", "type: String", `unknown type "String"`},
		{"switch with text default", "type: boolean\ndefault: \"false\"", "declared boolean, but its default is a string"},
		{"whole number with word default", "type: integer\ndefault: ten", "declared integer, but its default is a string"},
		{"whole number with fraction default", "type: integer\ndefault: 1.5", "declared integer, but its default is a number"},
		{"list with scalar default", "type: array\ndefault: a", "declared array, but its default is a string"},
		{"text with list default", "type: string\ndefault: [a]", "declared string, but its default is a array"},
	}
	for _, c := range cases {
		for _, composite := range []bool{false, true} {
			where := `tool "list_things"`
			if composite {
				where = `composite "summarize"`
			}
			t.Run(c.name+"/"+where, func(t *testing.T) {
				_, err := ParseBytes([]byte(declYAML(c.decl, composite)))
				switch {
				case c.wantErr == "" && err != nil:
					t.Fatalf("refused: %v", err)
				case c.wantErr != "" && err == nil:
					t.Fatalf("accepted, want an error with %q", c.wantErr)
				case c.wantErr != "" && (!strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), where) || !strings.Contains(err.Error(), `parameter "p"`)):
					t.Errorf("error %q does not name %s, the parameter and %q", err, where, c.wantErr)
				}
			})
		}
	}

	// The file types are parameter types too.
	files := map[string]ParamDef{"upload": {Type: ParamTypeFileURL, In: paramInBody}, "local": {Type: paramTypeFile, In: paramInBody}}
	if err := validateParamDecls("tool", files); err != nil {
		t.Errorf("file parameter types refused: %v", err)
	}
}

// TestNormalizeParams_DefaultsTakeTheDeclaredForm pins that a default that
// is filled in takes the form a supplied value takes before the gate. A
// DADL may write the default of an integer parameter as text or that of a
// string parameter as a number; a policy must see the same type for the
// default as for the same value sent by the caller.
func TestNormalizeParams_DefaultsTakeTheDeclaredForm(t *testing.T) {
	const (
		count     = "decl_count"
		share     = "decl_share"
		revision  = "decl_revision"
		strict    = "decl_strict"
		overwrite = "decl_overwrite"
		pageNo    = "decl_page"
		labels    = "decl_labels"
	)
	declared := map[string]ParamDef{
		count:     {Type: jsTypeInteger, In: testParamInQuery, Default: "5"},
		share:     {Type: jsTypeNumber, In: testParamInQuery, Default: "0.25"},
		revision:  {Type: jsTypeString, In: testParamInQuery, Default: 2},
		strict:    {Type: jsTypeString, In: testParamInQuery, Default: true},
		overwrite: {Type: jsTypeBoolean, In: paramInBody, Default: false},
		pageNo:    {Type: jsTypeInteger, In: testParamInQuery, Default: 1},
		labels:    {Type: jsTypeArray, In: paramInBody, Default: []any{"a"}},
	}
	got := NormalizeParams(declared, map[string]any{})
	want := map[string]any{
		count:     float64(5),
		share:     0.25,
		revision:  "2",
		strict:    FormatScalar(true),
		overwrite: false,
		pageNo:    1,
		labels:    []any{"a"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("defaults = %#v\nwant       %#v", got, want)
	}
	if _, isText := got[strict].(string); !isText {
		t.Errorf("the boolean default of a string parameter stays a %T", got[strict])
	}

	// The same values sent by the caller take the same form.
	sent := NormalizeParams(declared, map[string]any{count: "5", share: "0.25", revision: float64(2), strict: true})
	for _, name := range []string{count, share, revision, strict} {
		if !reflect.DeepEqual(sent[name], want[name]) {
			t.Errorf("%s: sent value becomes %#v, default becomes %#v", name, sent[name], want[name])
		}
	}

	// A null outside the body takes the default, in its declared form; a
	// null in the body stays null.
	nulls := NormalizeParams(declared, map[string]any{count: nil, overwrite: nil})
	if nulls[count] != float64(5) {
		t.Errorf("null query parameter: %#v, want the default as a number", nulls[count])
	}
	if v, ok := nulls[overwrite]; !ok || v != nil {
		t.Errorf("null body parameter: %#v, want null", v)
	}
}
