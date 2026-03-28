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

func TestParseBytes_ValidMinimal(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    get_item:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.Backend.Name != "test-api" {
		t.Errorf("got name %q, want %q", spec.Backend.Name, "test-api")
	}
	if len(spec.Backend.Tools) != 1 {
		t.Errorf("got %d tools, want 1", len(spec.Backend.Tools))
	}
	tool := spec.Backend.Tools["get_item"]
	if tool.Method != "GET" {
		t.Errorf("got method %q, want GET", tool.Method)
	}
	if tool.Path != "/items/{id}" {
		t.Errorf("got path %q, want /items/{id}", tool.Path)
	}
}

func TestParseBytes_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "wrong spec",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v99.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "unsupported spec",
		},
		{
			name: "wrong type",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: graphql
  base_url: https://api.example.com
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "backend.type must be \"rest\"",
		},
		{
			name: "empty name",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: ""
  type: rest
  base_url: https://api.example.com
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "backend.name must not be empty",
		},
		{
			name: "no tools",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools: {}
`,
			wantErr: "at least one tool",
		},
		{
			name: "tool missing method",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
    bad_tool:
      path: /x
`,
			wantErr: "method is required",
		},
		{
			name: "tool missing path",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
    bad_tool:
      method: GET
`,
			wantErr: "path is required",
		},
		{
			name: "undeclared path param",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
    bad_tool:
      method: GET
      path: /items/{id}
`,
			wantErr: "path parameter {id} not declared",
		},
		{
			name: "path param wrong in",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
    bad_tool:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: query }
`,
			wantErr: "used in path but declared as in=\"query\"",
		},
		{
			name: "invalid auth type",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  auth:
    type: magic
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "auth.type must be one of",
		},
		{
			name: "invalid pagination strategy",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  defaults:
    pagination:
      strategy: magic
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "strategy must be one of",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(tt.yaml))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseBytes_FullSpec(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: myapi
  type: rest
  base_url: https://api.example.com/v1
  description: "Test API"
  auth:
    type: bearer
    credential: my-token
    inject_into: header
    header_name: Authorization
    prefix: "Bearer "
  defaults:
    headers:
      Content-Type: application/json
    pagination:
      strategy: page
      request:
        page_param: page
        limit_param: per_page
        limit_default: 50
      response:
        total_pages_header: x-total-pages
      behavior: auto
      max_pages: 10
    errors:
      format: json
      message_path: "$.message"
      retry_on: [429, 503]
      terminal: [400, 404]
      retry_strategy:
        max_retries: 3
        backoff: exponential
        initial_delay: 1s
  tools:
    list_items:
      method: GET
      path: /items
      description: "List all items"
      params:
        page: { type: integer, in: query }
        per_page: { type: integer, in: query, default: 50 }
    get_item:
      method: GET
      path: /items/{id}
      description: "Get a single item"
      params:
        id: { type: integer, in: path, required: true }
      pagination: none
    create_item:
      method: POST
      path: /items
      description: "Create an item"
      params:
        name: { type: string, in: body, required: true }
        tags: { type: array, in: body }
      pagination: none
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b := &spec.Backend
	if b.Name != "myapi" {
		t.Errorf("name = %q, want myapi", b.Name)
	}
	if b.Auth.Type != "bearer" {
		t.Errorf("auth.type = %q, want bearer", b.Auth.Type)
	}
	if b.Auth.Prefix != "Bearer " {
		t.Errorf("auth.prefix = %q, want \"Bearer \"", b.Auth.Prefix)
	}
	if b.Defaults.Pagination == nil {
		t.Fatal("defaults.pagination is nil")
	}
	if b.Defaults.Pagination.Strategy != "page" {
		t.Errorf("pagination.strategy = %q, want page", b.Defaults.Pagination.Strategy)
	}
	if b.Defaults.Pagination.MaxPages != 10 {
		t.Errorf("pagination.max_pages = %d, want 10", b.Defaults.Pagination.MaxPages)
	}
	if len(b.Tools) != 3 {
		t.Errorf("got %d tools, want 3", len(b.Tools))
	}
	if b.Defaults.Errors == nil {
		t.Fatal("defaults.errors is nil")
	}
	if len(b.Defaults.Errors.RetryOn) != 2 {
		t.Errorf("retry_on length = %d, want 2", len(b.Defaults.Errors.RetryOn))
	}
}

func TestParseBytes_CompositeValid(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    list_items:
      method: GET
      path: /items
    get_status:
      method: GET
      path: /status
  composites:
    combined_status:
      description: "Get items with status"
      depends_on: [list_items, get_status]
      timeout: 15s
      params:
        filter:
          type: boolean
          default: false
      code: |
        const items = await api.list_items();
        const status = await api.get_status();
        return { items, status };
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Backend.Composites) != 1 {
		t.Fatalf("got %d composites, want 1", len(spec.Backend.Composites))
	}
	comp := spec.Backend.Composites["combined_status"]
	if comp.Description != "Get items with status" {
		t.Errorf("description = %q", comp.Description)
	}
	if len(comp.DependsOn) != 2 {
		t.Errorf("depends_on = %v, want [list_items, get_status]", comp.DependsOn)
	}
	if comp.Timeout != "15s" {
		t.Errorf("timeout = %q, want 15s", comp.Timeout)
	}
	if !spec.ContainsCode() {
		t.Error("ContainsCode() = false, want true")
	}
}

func TestParseBytes_CompositeValidationErrors(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    list_items:
      method: GET
      path: /items
`
	tests := []struct {
		name    string
		extra   string
		wantErr string
	}{
		{
			name: "empty description",
			extra: `  composites:
    bad:
      description: ""
      code: "return 1;"
`,
			wantErr: "description is required",
		},
		{
			name: "empty code",
			extra: `  composites:
    bad:
      description: "test"
      code: ""
`,
			wantErr: "code must not be empty",
		},
		{
			name: "whitespace-only code",
			extra: `  composites:
    bad:
      description: "test"
      code: "   "
`,
			wantErr: "code must not be empty",
		},
		{
			name: "timeout too large",
			extra: `  composites:
    bad:
      description: "test"
      code: "return 1;"
      timeout: 300s
`,
			wantErr: "exceeds maximum",
		},
		{
			name: "negative timeout",
			extra: `  composites:
    bad:
      description: "test"
      code: "return 1;"
      timeout: -5s
`,
			wantErr: "timeout must be positive",
		},
		{
			name: "invalid timeout format",
			extra: `  composites:
    bad:
      description: "test"
      code: "return 1;"
      timeout: "forever"
`,
			wantErr: "invalid timeout",
		},
		{
			name: "unknown dependency",
			extra: `  composites:
    bad:
      description: "test"
      code: "return 1;"
      depends_on: [nonexistent]
`,
			wantErr: "unknown tool",
		},
		{
			name: "name conflicts with primitive",
			extra: `  composites:
    list_items:
      description: "test"
      code: "return 1;"
`,
			wantErr: "conflicts with a primitive tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(base + tt.extra))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestContainsCode_NoComposites(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    get_item:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if spec.ContainsCode() {
		t.Error("ContainsCode() = true, want false")
	}
}
