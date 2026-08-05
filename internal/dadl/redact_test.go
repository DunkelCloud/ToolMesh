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
	"reflect"
	"strings"
	"testing"
)

func TestNewJSONPath_WildcardForms(t *testing.T) {
	tests := []struct {
		expr    string
		wantErr string
	}{
		{expr: "$[*]"},
		{expr: testRedactPathSecret},
		{expr: "$.data[*].id"},
		{expr: "$.settings.*"},
		{expr: "$.data[-1].id"},
		{expr: "$..id", wantErr: "empty segment"},
		{expr: "$.a..b", wantErr: "empty segment"},
		{expr: "$[1:3]", wantErr: "invalid array index"},
		{expr: "$[?(@.a)]", wantErr: "unclosed bracket"},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			_, err := NewJSONPath(tt.expr)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewJSONPath(%q) unexpected error: %v", tt.expr, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("NewJSONPath(%q) error = %v, want containing %q", tt.expr, err, tt.wantErr)
			}
		})
	}
}

func TestExtract_Wildcard(t *testing.T) {
	tests := []struct {
		name string
		expr string
		json string
		want []any
	}{
		{
			name: "array wildcard with trailing field skips non-matching",
			expr: "$.data[*].id",
			json: `{"data": [{"id": 1}, {"id": 2}, {"other": 3}]}`,
			want: []any{float64(1), float64(2)},
		},
		{
			name: "bare root wildcard",
			expr: "$[*]",
			json: `[1, 2]`,
			want: []any{float64(1), float64(2)},
		},
		{
			name: "object wildcard is key-sorted",
			expr: "$.settings.*",
			json: `{"settings": {"b": 2, "a": 1}}`,
			want: []any{float64(1), float64(2)},
		},
		{
			name: "missing field yields empty nodelist",
			expr: "$.missing[*]",
			json: `{"data": [1]}`,
			want: nil,
		},
		{
			name: "wildcard on scalar yields empty nodelist",
			expr: "$.count[*]",
			json: `{"count": 5}`,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jp, err := NewJSONPath(tt.expr)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var data any
			if err := json.Unmarshal([]byte(tt.json), &data); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			got, err := jp.Extract(data)
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			gotList, ok := got.([]any)
			if !ok {
				t.Fatalf("wildcard Extract returned %T, want []any", got)
			}
			if len(gotList) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(gotList, tt.want) {
				t.Errorf("Extract(%q) = %v, want %v", tt.expr, gotList, tt.want)
			}
		})
	}
}

func TestRedactResult(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		paths []string
		want  string
	}{
		{
			name:  "spec example masks secrets across array",
			body:  `[{"url":"https://a","secret":"s1","auth":{"password":"p1","user":"u1"}},{"url":"https://b","secret":"s2","auth":{"user":"u2"}}]`,
			paths: []string{testRedactPathSecret, "$[*].auth.password"},
			want:  `[{"auth":{"password":"[REDACTED]","user":"u1"},"secret":"[REDACTED]","url":"https://a"},{"auth":{"user":"u2"},"secret":"[REDACTED]","url":"https://b"}]`,
		},
		{
			name:  "scalar field",
			body:  `{"token":"abc","name":"n"}`,
			paths: []string{"$.token"},
			want:  `{"name":"n","token":"[REDACTED]"}`,
		},
		{
			name:  "root path masks everything",
			body:  testJSONTinyObject,
			paths: []string{"$"},
			want:  `"[REDACTED]"`,
		},
		{
			name:  "index and negative index",
			body:  `{"items":[{"key":"k0"},{"key":"k1"},{"key":"k2"}]}`,
			paths: []string{"$.items[0].key", "$.items[-1].key"},
			want:  `{"items":[{"key":"[REDACTED]"},{"key":"k1"},{"key":"[REDACTED]"}]}`,
		},
		{
			name:  "absent path is a no-op",
			body:  `{"a":{"b":1}}`,
			paths: []string{"$.a.missing", "$.x[*].y", "$.a.b.c"},
			want:  `{"a":{"b":1}}`,
		},
		{
			name:  "index out of bounds is a no-op",
			body:  `{"items":[1]}`,
			paths: []string{"$.items[5]"},
			want:  `{"items":[1]}`,
		},
		{
			name:  "object wildcard masks every member value",
			body:  `{"smtp":{"host":"h","password":"p"}}`,
			paths: []string{"$.smtp.*"},
			want:  `{"smtp":{"host":"[REDACTED]","password":"[REDACTED]"}}`,
		},
		{
			name:  "wildcard array elements replaced entirely",
			body:  `{"keys":["a","b"]}`,
			paths: []string{"$.keys[*]"},
			want:  `{"keys":["[REDACTED]","[REDACTED]"]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RedactResult([]byte(tt.body), tt.paths)
			if err != nil {
				t.Fatalf("RedactResult: %v", err)
			}
			// Normalize both sides through the JSON round-trip so key order
			// does not matter.
			var gotV, wantV any
			if err := json.Unmarshal(got, &gotV); err != nil {
				t.Fatalf("output not JSON: %v", err)
			}
			if err := json.Unmarshal([]byte(tt.want), &wantV); err != nil {
				t.Fatalf("fixture: %v", err)
			}
			if !reflect.DeepEqual(gotV, wantV) {
				t.Errorf("RedactResult = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestRedactResult_Errors(t *testing.T) {
	if _, err := RedactResult([]byte(`{}`), []string{"$..secret"}); err == nil {
		t.Error("descendant path must error, not silently no-op")
	}
	if _, err := RedactResult([]byte(`not json`), []string{"$.a"}); err == nil {
		t.Error("invalid JSON must error")
	}
	out, err := RedactResult([]byte(testJSONTinyObject), nil)
	if err != nil || string(out) != testJSONTinyObject {
		t.Errorf("empty path list must pass body through, got %s, %v", out, err)
	}
}

func TestParseBytes_RedactValidation(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    list_hooks:
      method: GET
      path: /hooks
      response:
        %s
`
	t.Run("valid redact loads without warnings", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "result_path: \"$.data\"\n        redact: [\"$[*].secret\"]", 1)
		spec, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 0 {
			t.Errorf("redact is implemented and must not warn, got: %v", spec.Warnings)
		}
		if got := spec.Backend.Tools["list_hooks"].Response.Redact; len(got) != 1 || got[0] != testRedactPathSecret {
			t.Errorf("redact not parsed, got %v", got)
		}
	})
	t.Run("invalid redact path fails load", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "redact: [\"$..secret\"]", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "redact path") {
			t.Fatalf("error = %v, want redact path rejection", err)
		}
	})
	t.Run("redact with binary rejected", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "binary: true\n        redact: [\"$.secret\"]", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with binary or file_url") {
			t.Fatalf("error = %v, want binary/file_url rejection", err)
		}
	})
	t.Run("redact with file_url rejected", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "type: file_url\n        redact: [\"$.secret\"]", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "cannot be combined with binary or file_url") {
			t.Fatalf("error = %v, want binary/file_url rejection", err)
		}
	})
	t.Run("defaults-level redact validated", func(t *testing.T) {
		yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  defaults:
    response:
      redact: ["$[1:3]"]
  tools:
    t:
      method: GET
      path: /x
`
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "defaults.response.redact path") {
			t.Fatalf("error = %v, want defaults.response.redact rejection", err)
		}
	})
	t.Run("requires feature redact now satisfied", func(t *testing.T) {
		yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
requires:
  features: [redact]
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    t:
      method: GET
      path: /x
`
		if _, err := ParseBytes([]byte(yaml)); err != nil {
			t.Fatalf("redact is implemented, requires must pass: %v", err)
		}
	})
}
