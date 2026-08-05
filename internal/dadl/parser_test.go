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
	"fmt"
	"strings"
	"testing"
	"time"
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
	if tool.Method != httpMethodGET {
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
		{
			name: "invalid oauth2 flow",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    flow: implicit
    token_url: https://api.example.com/token
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "auth.flow must be one of client_credentials, refresh_token, jwt_bearer, authorization_code",
		},
		{
			name: "v0.2 oauth2 flow under v0.1 declaration",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    flow: jwt_bearer
    service_account_credential: sa
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "requires spec v0.2",
		},
		{
			name: "refresh_token flow without refresh_token_credential",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    flow: refresh_token
    token_url: https://api.example.com/token
    client_id_credential: cid
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "requires auth.refresh_token_credential",
		},
		{
			name: "refresh_token flow under v0.1 spec declaration",
			yaml: `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  auth:
    type: oauth2
    flow: refresh_token
    token_url: https://api.example.com/token
    client_id_credential: cid
    refresh_token_credential: rt
  tools:
    t1:
      method: GET
      path: /x
`,
			wantErr: "requires spec v0.2",
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

func TestParseBytes_OAuth2RefreshTokenFlow(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: googleapi
  type: rest
  base_url: https://www.googleapis.com
  auth:
    type: oauth2
    flow: refresh_token
    token_url: https://oauth2.googleapis.com/token
    client_id_credential: google_client_id
    client_secret_credential: google_client_secret
    refresh_token_credential: google_refresh_token
    refresh_before_expiry: 60s
  tools:
    t1:
      method: GET
      path: /x
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	a := spec.Backend.Auth
	if a.Flow != oauth2FlowRefreshToken {
		t.Errorf("flow = %q, want refresh_token", a.Flow)
	}
	if a.RefreshTokenCredential != "google_refresh_token" {
		t.Errorf("refresh_token_credential = %q", a.RefreshTokenCredential)
	}
	if a.ClientSecretCredential != "google_client_secret" {
		t.Errorf("client_secret_credential = %q", a.ClientSecretCredential)
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
      message_path: testJSONPathMessage
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
	if b.Auth.Type != authTypeBearer {
		t.Errorf("auth.type = %q, want bearer", b.Auth.Type)
	}
	if b.Auth.Prefix != "Bearer " {
		t.Errorf("auth.prefix = %q, want \"Bearer \"", b.Auth.Prefix)
	}
	if b.Defaults.Pagination == nil {
		t.Fatal("defaults.pagination is nil")
	}
	if b.Defaults.Pagination.Strategy != paginationStrategyPage {
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

// TestParseBytes_BackendVersion exercises the optional backend.version field:
// it must be parsed onto BackendDef.Version, accept MAJOR.MINOR and
// MAJOR.MINOR.PATCH, reject malformed strings, and remain optional.
func TestParseBytes_BackendVersion(t *testing.T) {
	const tmpl = `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: test-api
  type: rest%s
  base_url: https://api.example.com
  tools:
    get_item:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
`

	t.Run("accepts MAJOR.MINOR", func(t *testing.T) {
		spec, err := ParseBytes([]byte(fmt.Sprintf(tmpl, "\n  version: \"1.0\"")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if spec.Backend.Version != "1.0" {
			t.Errorf("Version = %q, want %q", spec.Backend.Version, "1.0")
		}
	})

	t.Run("accepts MAJOR.MINOR.PATCH", func(t *testing.T) {
		spec, err := ParseBytes([]byte(fmt.Sprintf(tmpl, "\n  version: \"1.2.1\"")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if spec.Backend.Version != "1.2.1" {
			t.Errorf("Version = %q, want %q", spec.Backend.Version, "1.2.1")
		}
	})

	t.Run("optional when absent", func(t *testing.T) {
		spec, err := ParseBytes([]byte(fmt.Sprintf(tmpl, "")))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if spec.Backend.Version != "" {
			t.Errorf("Version = %q, want empty", spec.Backend.Version)
		}
	})

	rejected := []struct {
		name    string
		version string
	}{
		{"missing minor", "1"},
		{"leading v", "v1.0"},
		{"too many segments", "1.0.0.0"},
		{"non-numeric pre-release", "1.0-beta"},
	}
	for _, tc := range rejected {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(fmt.Sprintf(tmpl, "\n  version: \""+tc.version+"\"")))
			if err == nil {
				t.Fatalf("expected error for version %q, got nil", tc.version)
			}
			if !strings.Contains(err.Error(), "backend.version") {
				t.Errorf("error %q should mention backend.version", err.Error())
			}
		})
	}
}

func TestParseBytes_FileURLResponse(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: tika
  type: rest
  base_url: https://tika.example.com
  tools:
    unpack:
      method: PUT
      path: /unpack
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
      response:
        type: file_url
        ttl: 24h
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	rc := spec.Backend.Tools["unpack"].Response
	if !rc.IsFileURL() {
		t.Errorf("IsFileURL() = false, want true (Type = %q)", rc.Type)
	}
	if got := rc.FileURLTTL(); got != 24*time.Hour {
		t.Errorf("FileURLTTL() = %v, want 24h", got)
	}

	file := spec.Backend.Tools["unpack"].Params["file"]
	if file.Type != ParamTypeFileURL {
		t.Errorf("param type = %q, want file_url", file.Type)
	}
}

func TestResponseConfig_FileURLHelpers_Nil(t *testing.T) {
	var rc *ResponseConfig
	if rc.IsFileURL() {
		t.Error("nil ResponseConfig IsFileURL() = true, want false")
	}
	if got := rc.FileURLTTL(); got != 0 {
		t.Errorf("nil ResponseConfig FileURLTTL() = %v, want 0", got)
	}
	if got := (&ResponseConfig{TTL: "bogus"}).FileURLTTL(); got != 0 {
		t.Errorf("invalid TTL FileURLTTL() = %v, want 0", got)
	}
}

func TestParseBytes_FileURLValidationErrors(t *testing.T) {
	const tmpl = `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
%s`

	tests := []struct {
		name    string
		tool    string
		wantErr string
	}{
		{
			name: "response type unknown",
			tool: `
    t1:
      method: GET
      path: /x
      response:
        type: base64
`,
			wantErr: `response.type must be "file_url" or empty`,
		},
		{
			name: "response ttl invalid",
			tool: `
    t1:
      method: GET
      path: /x
      response:
        type: file_url
        ttl: "3 days"
`,
			wantErr: "not a valid duration",
		},
		{
			name: "response ttl negative",
			tool: `
    t1:
      method: GET
      path: /x
      response:
        type: file_url
        ttl: -1h
`,
			wantErr: "ttl must be positive",
		},
		{
			name: "response ttl without file_url type",
			tool: `
    t1:
      method: GET
      path: /x
      response:
        ttl: 1h
`,
			wantErr: "ttl requires type: file_url",
		},
		{
			name: "file_url param not in body",
			tool: `
    t1:
      method: PUT
      path: /x
      params:
        file: { type: file_url, in: query, required: true }
`,
			wantErr: "must be in: body",
		},
		{
			name: "multiple file_url params without multipart",
			tool: `
    t1:
      method: PUT
      path: /x
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
        attachment: { type: file_url, in: body }
`,
			wantErr: "multiple file_url parameters require content_type: multipart/form-data",
		},
		{
			name: "file_url plus body param without multipart",
			tool: `
    t1:
      method: PUT
      path: /x
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
        title: { type: string, in: body }
`,
			wantErr: "must be the only body parameter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(fmt.Sprintf(tmpl, tt.tool)))
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseBytes_FileURLValid(t *testing.T) {
	tests := []struct {
		name string
		tool string
	}{
		{
			name: "raw body single file_url",
			tool: `
    t1:
      method: PUT
      path: /x
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
        Accept: { type: string, in: header, default: "text/plain" }
`,
		},
		{
			name: "multipart with file_url and form fields",
			tool: `
    t1:
      method: POST
      path: /x
      content_type: multipart/form-data
      params:
        file: { type: file_url, in: body, required: true }
        glossary: { type: file_url, in: body }
        target_lang: { type: string, in: body, required: true }
`,
		},
	}

	const tmpl = `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: x
  type: rest
  base_url: https://api.example.com
  tools:
%s`

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseBytes([]byte(fmt.Sprintf(tmpl, tt.tool))); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
