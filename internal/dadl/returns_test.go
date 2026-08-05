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
	"strings"
	"testing"
)

func TestReturnsToTS(t *testing.T) {
	types := map[string]any{
		testTypeCustomer: map[string]any{
			schemaKeyType: jsTypeObject,
			schemaKeyProperties: map[string]any{
				"id":    map[string]any{schemaKeyType: jsTypeString},
				"email": map[string]any{schemaKeyType: jsTypeString},
			},
			schemaKeyRequired: []any{"id"},
		},
		"Tag": map[string]any{schemaKeyType: jsTypeString},
	}
	tests := []struct {
		name    string
		returns any
		want    string
		wantErr string
	}{
		{name: "nil is any", returns: nil, want: tsAny},
		{name: "bare name", returns: testTypeCustomer, want: testTypeCustomer},
		{name: "unresolved bare name", returns: "Missing", wantErr: `not declared in types`},
		{name: "invalid identifier", returns: "3bad", wantErr: "not a valid identifier"},
		{
			name:    "array of named type",
			returns: map[string]any{schemaKeyType: jsTypeArray, schemaKeyItems: testTypeCustomer},
			want:    "Customer[]",
		},
		{
			name:    "ref pointer",
			returns: map[string]any{schemaKeyRef: "#/backend/types/Customer"},
			want:    testTypeCustomer,
		},
		{
			name:    "ref with wrong prefix",
			returns: map[string]any{schemaKeyRef: "#/types/Customer"},
			wantErr: "must start with",
		},
		{
			name:    "unresolved ref",
			returns: map[string]any{schemaKeyRef: "#/backend/types/Nope"},
			wantErr: "does not resolve",
		},
		{
			name: "inline object",
			returns: map[string]any{
				schemaKeyType: jsTypeObject,
				schemaKeyProperties: map[string]any{
					testFieldTotal: map[string]any{schemaKeyType: jsTypeInteger},
					schemaKeyItems: map[string]any{schemaKeyType: jsTypeArray, schemaKeyItems: "Tag"},
				},
				schemaKeyRequired: []any{testFieldTotal},
			},
			want: "{ items?: Tag[]; total: number }",
		},
		{name: "primitive", returns: map[string]any{schemaKeyType: jsTypeString}, want: "string"},
		{name: "object without properties", returns: map[string]any{schemaKeyType: jsTypeObject}, want: "Record<string, any>"},
		{name: "array without items", returns: map[string]any{schemaKeyType: jsTypeArray}, want: "any[]"},
		{name: "typeless schema", returns: map[string]any{schemaKeyProperties: map[string]any{}}, wantErr: "needs a type"},
		{name: "wrong node kind", returns: 42, wantErr: "must be a type name or an object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReturnsToTS(tt.returns, types)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ReturnsToTS = %q, want %q", got, tt.want)
			}
		})
	}
}

const returnsSpecYAML = `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  types:
    Customer:
      type: object
      properties:
        id: { type: string }
        email: { type: string }
      required: [id]
  tools:
    get_customer:
      method: GET
      path: /customers/{id}
      description: "Retrieve a single customer"
      returns: Customer
      params:
        id: { type: string, in: path, required: true }
    list_customers:
      method: GET
      path: /customers
      description: "List customers"
      returns:
        type: array
        items: Customer
    get_customer_v1:
      method: GET
      path: /v1/customers/{id}
      description: "Old customer endpoint"
      deprecated: "unpaginated and slow"
      replaced_by: get_customer
      params:
        id: { type: string, in: path, required: true }
`

func TestParseBytes_ReturnsAndDeprecation(t *testing.T) {
	spec, err := ParseBytes([]byte(returnsSpecYAML))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Warnings) != 0 {
		t.Errorf("returns/deprecated/replaced_by are implemented and must not warn, got: %v", spec.Warnings)
	}
	v1 := spec.Backend.Tools["get_customer_v1"]
	reason, deprecated := v1.DeprecationInfo()
	if !deprecated || reason != "unpaginated and slow" {
		t.Errorf("DeprecationInfo = %q/%v", reason, deprecated)
	}

	tests := []struct {
		name    string
		mutate  string
		wantErr string
	}{
		{name: "unresolved returns", mutate: "returns: Customer", wantErr: ""},
		{
			name:    "returns names unknown type",
			mutate:  "returns: Ghost",
			wantErr: `returns: type "Ghost" is not declared`,
		},
		{
			name:    "replaced_by names unknown tool",
			mutate:  "replaced_by: nonexistent",
			wantErr: `replaced_by "nonexistent" does not name a tool`,
		},
		{
			name:    "deprecated wrong type",
			mutate:  "deprecated: [broken]",
			wantErr: "deprecated must be true/false or a reason string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := strings.Replace(returnsSpecYAML, "returns: Customer", tt.mutate, 1)
			_, err := ParseBytes([]byte(yaml))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateTypeScript_ReturnsAndDeprecation(t *testing.T) {
	spec, err := ParseBytes([]byte(returnsSpecYAML))
	if err != nil {
		t.Fatal(err)
	}
	ts := GenerateTypeScript(spec)

	for _, want := range []string{
		"type Customer = { email?: string; id: string };",
		"function test-api_get_customer(params: { id: string }): Promise<Customer>;",
		"function test-api_list_customers(params: {  }): Promise<Customer[]>;",
		"@deprecated unpaginated and slow — use get_customer instead",
	} {
		if !strings.Contains(ts, want) {
			t.Errorf("generated TS missing %q:\n%s", want, ts)
		}
	}
	if strings.Contains(ts, "Promise<any>;\n\n  /**") && strings.Contains(ts, "get_customer(") {
		t.Log(ts) // aid debugging on failures above
	}
}
