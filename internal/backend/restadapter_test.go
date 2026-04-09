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

package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// testCredStore is a simple in-memory credential store for testing.
type testCredStore struct {
	creds map[string]string
}

func (s *testCredStore) Get(_ context.Context, name string, _ credentials.TenantInfo) (string, error) {
	if v, ok := s.creds[name]; ok {
		return v, nil
	}
	return "", fmt.Errorf("credential %q not found", name)
}

func (s *testCredStore) Healthy(_ context.Context) error { return nil }

func TestRESTAdapter_ListTools(t *testing.T) {
	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools: map[string]dadl.ToolDef{
				"get_item": {
					Method:      "GET",
					Path:        "/items/{id}",
					Description: "Get an item",
					Params: map[string]dadl.ParamDef{
						"id": {Type: "integer", In: "path", Required: true},
					},
				},
				"list_items": {
					Method:      "GET",
					Path:        "/items",
					Description: "List items",
					Params: map[string]dadl.ParamDef{
						"page": {Type: "integer", In: "query"},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tools) != 2 {
		t.Fatalf("got %d tools, want 2", len(tools))
	}

	// Tools should be sorted
	if tools[0].Name != "get_item" {
		t.Errorf("first tool = %q, want get_item", tools[0].Name)
	}
	if tools[1].Name != "list_items" {
		t.Errorf("second tool = %q, want list_items", tools[1].Name)
	}

	// Check schema
	schema := tools[0].InputSchema
	if schema["type"] != "object" {
		t.Errorf("schema type = %v, want object", schema["type"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("properties is not a map")
	}
	idProp, ok := props["id"].(map[string]any)
	if !ok {
		t.Fatal("id property not found")
	}
	if idProp["type"] != "integer" {
		t.Errorf("id type = %v, want integer", idProp["type"])
	}

	// Check required
	required, ok := schema["required"].([]string)
	if !ok {
		t.Fatal("required is not a string slice")
	}
	if len(required) != 1 || required[0] != "id" {
		t.Errorf("required = %v, want [id]", required)
	}

	// Check backend label
	if tools[0].Backend != "rest:testapi" {
		t.Errorf("backend = %q, want rest:testapi", tools[0].Backend)
	}
}

func TestRESTAdapter_Execute(t *testing.T) {
	// Mock API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/items/42":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id": 42, "name": "test item"}`))
		case r.Method == "POST" && r.URL.Path == "/api/items":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id": 99, "name": "new item"}`))
		case r.Method == "GET" && r.URL.Path == "/api/items":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message": "not found"}`))
		}
	}))
	defer server.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: server.URL + "/api",
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
			},
			Tools: map[string]dadl.ToolDef{
				"get_item": {
					Method: "GET",
					Path:   "/items/{id}",
					Params: map[string]dadl.ParamDef{
						"id": {Type: "integer", In: "path", Required: true},
					},
				},
				"create_item": {
					Method: "POST",
					Path:   "/items",
					Params: map[string]dadl.ParamDef{
						"name": {Type: "string", In: "body", Required: true},
					},
				},
				"list_items": {
					Method: "GET",
					Path:   "/items",
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	t.Run("GET with path param", func(t *testing.T) {
		result, err := adapter.Execute(context.Background(), "get_item", map[string]any{"id": 42})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.IsError {
			t.Fatal("unexpected error result")
		}
		text := extractText(t, result)
		if !strings.Contains(text, `"name": "test item"`) && !strings.Contains(text, `"name":"test item"`) {
			t.Errorf("response = %s", text)
		}
	})

	t.Run("POST with body", func(t *testing.T) {
		result, err := adapter.Execute(context.Background(), "create_item", map[string]any{"name": "new item"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.IsError {
			t.Fatal("unexpected error result")
		}
		text := extractText(t, result)
		if !strings.Contains(text, "99") {
			t.Errorf("expected id 99 in response: %s", text)
		}
	})

	t.Run("tool not found", func(t *testing.T) {
		_, err := adapter.Execute(context.Background(), "nonexistent", nil)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

const contentTypeFormEncoded = "application/x-www-form-urlencoded"

func TestRESTAdapter_FormEncodedBody(t *testing.T) {
	var receivedContentType string
	var receivedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": "cus_123", "email": "jane@example.com", "name": "Jane"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: "bearer", Credential: "tok"},
			Tools: map[string]dadl.ToolDef{
				"create_customer": {
					Method:      "POST",
					Path:        "/customers",
					ContentType: contentTypeFormEncoded,
					Params: map[string]dadl.ParamDef{
						"email": {Type: "string", In: "body"},
						"name":  {Type: "string", In: "body"},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{"tok": "sk_test_123"}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "create_customer", map[string]any{
		"email": "jane@example.com",
		"name":  "Jane",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %s", extractText(t, result))
	}

	if receivedContentType != contentTypeFormEncoded {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", receivedContentType)
	}

	parsed, err := url.ParseQuery(receivedBody)
	if err != nil {
		t.Fatalf("parse form body: %v", err)
	}
	if parsed.Get("email") != "jane@example.com" {
		t.Errorf("email = %q, want jane@example.com", parsed.Get("email"))
	}
	if parsed.Get("name") != "Jane" {
		t.Errorf("name = %q, want Jane", parsed.Get("name"))
	}
}

func TestRESTAdapter_FormEncodedNestedObject(t *testing.T) {
	var receivedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": "price_123"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: "bearer", Credential: "tok"},
			Tools: map[string]dadl.ToolDef{
				"create_price": {
					Method:      "POST",
					Path:        "/prices",
					ContentType: contentTypeFormEncoded,
					Params: map[string]dadl.ParamDef{
						"unit_amount": {Type: "integer", In: "body"},
						"currency":    {Type: "string", In: "body"},
						"recurring":   {Type: "object", In: "body"},
					},
				},
			},
		},
	}

	adapter, _ := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{"tok": "sk_test_123"}}, slog.Default(), testRESTOpts)

	_, err := adapter.Execute(context.Background(), "create_price", map[string]any{
		"unit_amount": 1999,
		"currency":    "eur",
		"recurring":   map[string]any{"interval": "month", "interval_count": float64(1)},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, _ := url.ParseQuery(receivedBody)

	// Nested object must use bracket notation
	if parsed.Get("recurring[interval]") != "month" {
		t.Errorf("recurring[interval] = %q, want month (body: %s)", parsed.Get("recurring[interval]"), receivedBody)
	}
	if parsed.Get("recurring[interval_count]") != "1" {
		t.Errorf("recurring[interval_count] = %q, want 1", parsed.Get("recurring[interval_count]"))
	}
	if parsed.Get("currency") != "eur" {
		t.Errorf("currency = %q, want eur", parsed.Get("currency"))
	}
}

func TestRESTAdapter_BackendSummaries(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:        "myapi",
			Description: "My API description",
			Type:        "rest",
			BaseURL:     "https://example.com",
			Tools:       map[string]dadl.ToolDef{"t": {Method: "GET", Path: "/"}},
		},
	}
	adapter, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	summaries := adapter.BackendSummaries()
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries, want 1", len(summaries))
	}
	if summaries[0].Name != "myapi" || summaries[0].Hint != "My API description" {
		t.Errorf("summary = %+v", summaries[0])
	}
}

func extractText(t *testing.T, result *ToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("empty content")
	}
	m, ok := result.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] is %T, want map", result.Content[0])
	}
	text, _ := m["text"].(string)
	return text
}

func TestBuildInputSchema(t *testing.T) {
	tool := dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"id":     {Type: "integer", In: "path", Required: true},
			"name":   {Type: "string", In: "body", Required: true},
			"active": {Type: "boolean", In: "body"},
			"tags":   {Type: "array", In: "body"},
		},
	}

	schema := buildInputSchema(tool)

	props := schema["properties"].(map[string]any)
	if len(props) != 4 {
		t.Errorf("got %d properties, want 4", len(props))
	}

	required := schema["required"].([]string)
	if len(required) != 2 {
		t.Errorf("got %d required, want 2", len(required))
	}

	// Check JSON marshal roundtrip
	_, err := json.Marshal(schema)
	if err != nil {
		t.Fatalf("marshal schema: %v", err)
	}
}

func TestRESTAdapter_MultipartFileUpload(t *testing.T) {
	// Track what the server receives
	var receivedContentType string
	var receivedFileName string
	var receivedFileContent string
	var receivedFormField string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")

		err := r.ParseMultipartForm(32 << 20) //nolint:gosec // test server with controlled input
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// Check form field
		receivedFormField = r.FormValue("description") //nolint:gosec // test server

		// Check file
		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer func() { _ = file.Close() }()
		receivedFileName = header.Filename
		content, _ := io.ReadAll(file)
		receivedFileContent = string(content)

		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok","markdown":"# Test"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "testupload",
			Type:    "rest",
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: ""},
			Tools: map[string]dadl.ToolDef{
				"upload_file": {
					Method:      "POST",
					Path:        "/upload",
					Description: "Upload a file",
					ContentType: "multipart/form-data",
					Params: map[string]dadl.ParamDef{
						"file":        {Type: "file", In: "body", Required: true},
						"description": {Type: "string", In: "body"},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	// Create a temp file inside the allowed upload directory
	uploadDir := filepath.Join(os.TempDir(), "toolmesh-uploads-test")
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		t.Fatalf("create upload dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(uploadDir) }()
	adapter.allowedUploadDir = uploadDir
	tmpFile, err := os.CreateTemp(uploadDir, "test-upload-*.txt")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	testContent := "Hello from file upload test!"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	_ = tmpFile.Close()

	result, err := adapter.Execute(context.Background(), "upload_file", map[string]any{
		"file":        tmpFile.Name(),
		"description": "test document",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if result.IsError {
		t.Fatalf("unexpected error result: %v", result.Content)
	}

	// Verify multipart content type with boundary
	if !strings.HasPrefix(receivedContentType, "multipart/form-data; boundary=") {
		t.Errorf("content type = %q, want multipart/form-data with boundary", receivedContentType)
	}

	// Verify file was received
	if receivedFileContent != testContent {
		t.Errorf("file content = %q, want %q", receivedFileContent, testContent)
	}

	// Verify filename is just the base name
	if receivedFileName != filepath.Base(tmpFile.Name()) {
		t.Errorf("filename = %q, want %q", receivedFileName, filepath.Base(tmpFile.Name()))
	}

	// Verify form field was received
	if receivedFormField != "test document" {
		t.Errorf("description = %q, want %q", receivedFormField, "test document")
	}
}

func TestBuildQuery_URLEncoding(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools:   map[string]dadl.ToolDef{"t": {Method: "GET", Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"q": {Type: "string", In: "query"},
		},
	}

	query := adapter.buildQuery(tool, map[string]any{"q": "foo&bar=baz"})
	if !strings.Contains(query, "foo%26bar%3Dbaz") {
		t.Errorf("query not properly encoded: %s", query)
	}
	if strings.Contains(query, "foo&bar=baz") {
		t.Errorf("query contains unencoded special chars: %s", query)
	}
}

// TestBuildQuery_NilValues verifies that nil parameter values (from JS undefined)
// are skipped instead of being serialized as "<nil>". Fixes #46.
func TestBuildQuery_NilValues(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools:   map[string]dadl.ToolDef{"t": {Method: "GET", Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"q":      {Type: "string", In: "query"},
			"filter": {Type: "string", In: "query"},
		},
	}

	// filter is explicitly nil (JS undefined → Go nil)
	query := adapter.buildQuery(tool, map[string]any{"q": "test", "filter": nil})
	if strings.Contains(query, "nil") {
		t.Errorf("query contains nil value: %s", query)
	}
	if !strings.Contains(query, "q=test") {
		t.Errorf("query missing valid param: %s", query)
	}
	if strings.Contains(query, "filter") {
		t.Errorf("query should not contain nil param 'filter': %s", query)
	}
}

// TestBuildQuery_NilWithDefault verifies that nil values fall back to the default.
func TestBuildQuery_NilWithDefault(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools:   map[string]dadl.ToolDef{"t": {Method: "GET", Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"tags": {Type: "string", In: "query", Default: "story"},
		},
	}

	query := adapter.buildQuery(tool, map[string]any{"tags": nil})
	if !strings.Contains(query, "tags=story") {
		t.Errorf("nil value should fall back to default, got: %s", query)
	}
}

// TestBuildBody_NilValues verifies that nil body values are omitted. Fixes #46.
func TestBuildBody_NilValues(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools:   map[string]dadl.ToolDef{"t": {Method: "POST", Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"name":   {Type: "string", In: "body"},
			"filter": {Type: "string", In: "body"},
		},
	}

	body := adapter.buildBody(tool, map[string]any{"name": "test", "filter": nil})
	if _, exists := body["filter"]; exists {
		t.Errorf("body should not contain nil param 'filter': %v", body)
	}
	if body["name"] != "test" {
		t.Errorf("body missing valid param 'name': %v", body)
	}
}

func TestBuildPath_URLEncoding(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    "testapi",
			Type:    "rest",
			BaseURL: "https://api.example.com",
			Tools:   map[string]dadl.ToolDef{"t": {Method: "GET", Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Path: "/users/{id}/items",
		Params: map[string]dadl.ParamDef{
			"id": {Type: "string", In: "path"},
		},
	}

	path := adapter.buildPath(tool, map[string]any{"id": "../admin"})
	if strings.Contains(path, "../admin") {
		t.Errorf("path contains unencoded traversal: %s", path)
	}
	if !strings.Contains(path, "..%2Fadmin") {
		t.Errorf("path not properly encoded: %s", path)
	}
}
