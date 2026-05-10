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
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolGetItem: {
					Method:      testMethodGET,
					Path:        testPathItemsByID,
					Description: testDescGetItem,
					Params: map[string]dadl.ParamDef{
						"id": {Type: schemaTypeInteger, In: paramInPath, Required: true},
					},
				},
				testToolListItems: {
					Method:      testMethodGET,
					Path:        testPathItems,
					Description: testDescListItems,
					Params: map[string]dadl.ParamDef{
						testParamPage: {Type: schemaTypeInteger, In: paramInQuery},
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
	if tools[0].Name != testToolGetItem {
		t.Errorf("first tool = %q, want get_item", tools[0].Name)
	}
	if tools[1].Name != testToolListItems {
		t.Errorf("second tool = %q, want list_items", tools[1].Name)
	}

	// Check schema
	schema := tools[0].InputSchema
	if schema[schemaKeyType] != schemaTypeObject {
		t.Errorf("schema type = %v, want object", schema[schemaKeyType])
	}
	props, ok := schema[schemaKeyProperties].(map[string]any)
	if !ok {
		t.Fatal("properties is not a map")
	}
	idProp, ok := props["id"].(map[string]any)
	if !ok {
		t.Fatal("id property not found")
	}
	if idProp[schemaKeyType] != schemaTypeInteger {
		t.Errorf("id type = %v, want integer", idProp[schemaKeyType])
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
		case r.Method == testMethodGET && r.URL.Path == "/api/items/42":
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`{"id": 42, testParamName: "test item"}`))
		case r.Method == testMethodPOST && r.URL.Path == "/api/items":
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"id": 99, testParamName: "new item"}`))
		case r.Method == testMethodGET && r.URL.Path == "/api/items":
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`{"message": "not found"}`))
		}
	}))
	defer server.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: server.URL + "/api",
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					testHeaderContentType: testContentTypeJSON,
					testHeaderAccept:      testContentTypeJSON,
				},
			},
			Tools: map[string]dadl.ToolDef{
				testToolGetItem: {
					Method: testMethodGET,
					Path:   testPathItemsByID,
					Params: map[string]dadl.ParamDef{
						"id": {Type: schemaTypeInteger, In: paramInPath, Required: true},
					},
				},
				"create_item": {
					Method: testMethodPOST,
					Path:   testPathItems,
					Params: map[string]dadl.ParamDef{
						testParamName: {Type: schemaTypeString, In: paramInBody, Required: true},
					},
				},
				testToolListItems: {
					Method: testMethodGET,
					Path:   testPathItems,
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	t.Run("GET with path param", func(t *testing.T) {
		result, err := adapter.Execute(context.Background(), testToolGetItem, map[string]any{"id": 42})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.IsError {
			t.Fatal("unexpected error result")
		}
		text := extractText(t, result)
		if !strings.Contains(text, `testParamName: "test item"`) && !strings.Contains(text, `testParamName:"test item"`) {
			t.Errorf("response = %s", text)
		}
	})

	t.Run("POST with body", func(t *testing.T) {
		result, err := adapter.Execute(context.Background(), "create_item", map[string]any{testParamName: "new item"})
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
		receivedContentType = r.Header.Get(testHeaderContentType)
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id": "cus_123", "email": "jane@example.com", testParamName: "Jane"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: testTokenBearer, Credential: testTokenValue},
			Tools: map[string]dadl.ToolDef{
				"create_customer": {
					Method:      testMethodPOST,
					Path:        "/customers",
					ContentType: contentTypeFormEncoded,
					Params: map[string]dadl.ParamDef{
						"email":       {Type: schemaTypeString, In: paramInBody},
						testParamName: {Type: schemaTypeString, In: paramInBody},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{testTokenValue: "sk_test_123"}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "create_customer", map[string]any{
		"email":       "jane@example.com",
		testParamName: "Jane",
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
	if parsed.Get(testParamName) != "Jane" {
		t.Errorf("name = %q, want Jane", parsed.Get(testParamName))
	}
}

func TestRESTAdapter_FormEncodedNestedObject(t *testing.T) {
	var receivedBody string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"id": "price_123"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: testTokenBearer, Credential: testTokenValue},
			Tools: map[string]dadl.ToolDef{
				"create_price": {
					Method:      testMethodPOST,
					Path:        "/prices",
					ContentType: contentTypeFormEncoded,
					Params: map[string]dadl.ParamDef{
						"unit_amount": {Type: schemaTypeInteger, In: paramInBody},
						"currency":    {Type: schemaTypeString, In: paramInBody},
						"recurring":   {Type: schemaTypeObject, In: paramInBody},
					},
				},
			},
		},
	}

	adapter, _ := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{testTokenValue: "sk_test_123"}}, slog.Default(), testRESTOpts)

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

func TestRESTAdapter_PromotedTools_HappyPath(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolGetItem:   {Method: testMethodGET, Path: testPathItemsByID, Description: "Get an item"},
				testToolListItems: {Method: testMethodGET, Path: testPathItems, Description: testDescListItems},
			},
		},
	}
	opts := testRESTOpts
	opts.ExposeTools = []string{testToolListItems}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}

	promoted := adapter.PromotedTools()
	if len(promoted) != 1 {
		t.Fatalf("got %d promoted tools, want 1", len(promoted))
	}
	wantName := testBackendNameTestAPI + "_" + testToolListItems
	if promoted[0].Name != wantName {
		t.Errorf("promoted name = %q, want %q", promoted[0].Name, wantName)
	}
	if promoted[0].Description != testDescListItems {
		t.Errorf("description = %q", promoted[0].Description)
	}
	if promoted[0].InputSchema == nil {
		t.Error("promoted descriptor has nil InputSchema")
	}
}

func TestRESTAdapter_PromotedTools_DropsUnknownNames(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolGetItem: {Method: testMethodGET, Path: testPathItemsByID, Description: "Get an item"},
			},
		},
	}
	opts := testRESTOpts
	opts.ExposeTools = []string{testToolGetItem, "does_not_exist"}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}

	promoted := adapter.PromotedTools()
	if len(promoted) != 1 {
		t.Fatalf("got %d promoted tools, want 1 (unknown name should be dropped)", len(promoted))
	}
	if promoted[0].Name != testBackendNameTestAPI+"_"+testToolGetItem {
		t.Errorf("unexpected promoted tool: %q", promoted[0].Name)
	}
}

func TestRESTAdapter_PromotedTools_CollapsesWhenBackendNameEqualsToolName(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testToolWebSearch,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolWebSearch: {Method: testMethodGET, Path: "/search", Description: "Search the web"},
			},
		},
	}
	opts := testRESTOpts
	opts.ExposeTools = []string{testToolWebSearch}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}

	promoted := adapter.PromotedTools()
	if len(promoted) != 1 {
		t.Fatalf("got %d promoted tools, want 1", len(promoted))
	}
	if promoted[0].Name != testToolWebSearch {
		t.Errorf("public name = %q, want %q (collapsed, not %q)", promoted[0].Name, testToolWebSearch, "web_search_web_search")
	}
}

func TestRESTAdapter_PromotedTools_Empty(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolGetItem: {Method: testMethodGET, Path: testPathItemsByID},
			},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}
	if got := adapter.PromotedTools(); len(got) != 0 {
		t.Errorf("expected no promoted tools by default, got %d", len(got))
	}
}

func TestRESTAdapter_BackendSummaries(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:        "myapi",
			Description: "My API description",
			Type:        transportTypeREST,
			BaseURL:     "https://example.com",
			Tools:       map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
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
	text, _ := m[contentTypeText].(string)
	return text
}

func TestBuildInputSchema(t *testing.T) {
	tool := dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"id":          {Type: schemaTypeInteger, In: paramInPath, Required: true},
			testParamName: {Type: schemaTypeString, In: paramInBody, Required: true},
			"active":      {Type: schemaTypeBoolean, In: paramInBody},
			testParamTags: {Type: "array", In: paramInBody},
		},
	}

	schema := buildInputSchema(tool)

	props := schema[schemaKeyProperties].(map[string]any)
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
		receivedContentType = r.Header.Get(testHeaderContentType)

		err := r.ParseMultipartForm(32 << 20) //nolint:gosec // test server with controlled input
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// Check form field
		receivedFormField = r.FormValue("description") //nolint:gosec // test server

		// Check file
		file, header, err := r.FormFile(paramTypeFile)
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
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "testupload",
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Auth:    dadl.AuthConfig{Type: ""},
			Tools: map[string]dadl.ToolDef{
				"upload_file": {
					Method:      testMethodPOST,
					Path:        "/upload",
					Description: "Upload a file",
					ContentType: "multipart/form-data",
					Params: map[string]dadl.ParamDef{
						paramTypeFile: {Type: paramTypeFile, In: paramInBody, Required: true},
						"description": {Type: schemaTypeString, In: paramInBody},
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
		paramTypeFile: tmpFile.Name(),
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
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"q": {Type: schemaTypeString, In: paramInQuery},
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
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			"q":             {Type: schemaTypeString, In: paramInQuery},
			testParamFilter: {Type: schemaTypeString, In: paramInQuery},
		},
	}

	// filter is explicitly nil (JS undefined → Go nil)
	query := adapter.buildQuery(tool, map[string]any{"q": testBackendNameTest, testParamFilter: nil})
	if strings.Contains(query, "nil") {
		t.Errorf("query contains nil value: %s", query)
	}
	if !strings.Contains(query, "q=test") {
		t.Errorf("query missing valid param: %s", query)
	}
	if strings.Contains(query, testParamFilter) {
		t.Errorf("query should not contain nil param 'filter': %s", query)
	}
}

// TestBuildQuery_NilWithDefault verifies that nil values fall back to the default.
func TestBuildQuery_NilWithDefault(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			testParamTags: {Type: schemaTypeString, In: paramInQuery, Default: "story"},
		},
	}

	query := adapter.buildQuery(tool, map[string]any{testParamTags: nil})
	if !strings.Contains(query, "tags=story") {
		t.Errorf("nil value should fall back to default, got: %s", query)
	}
}

// TestBuildBody_NilValues verifies that nil body values are omitted. Fixes #46.
func TestBuildBody_NilValues(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodPOST, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Params: map[string]dadl.ParamDef{
			testParamName:   {Type: schemaTypeString, In: paramInBody},
			testParamFilter: {Type: schemaTypeString, In: paramInBody},
		},
	}

	body := adapter.buildBody(tool, map[string]any{testParamName: testBackendNameTest, testParamFilter: nil})
	if _, exists := body[testParamFilter]; exists {
		t.Errorf("body should not contain nil param 'filter': %v", body)
	}
	if body[testParamName] != testBackendNameTest {
		t.Errorf("body missing valid param 'name': %v", body)
	}
}

func TestBuildPath_URLEncoding(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Path: "/users/{id}/items",
		Params: map[string]dadl.ParamDef{
			"id": {Type: schemaTypeString, In: paramInPath},
		},
	}

	path, err := adapter.buildPath(tool, map[string]any{"id": "../admin"})
	if err != nil {
		t.Fatalf("buildPath: %v", err)
	}
	if strings.Contains(path, "../admin") {
		t.Errorf("path contains unencoded traversal: %s", path)
	}
	if !strings.Contains(path, "..%2Fadmin") {
		t.Errorf("path not properly encoded: %s", path)
	}
}

// TestBuildPath_MissingRequiredParam verifies that a missing path parameter
// is rejected up front with a clear error instead of leaving the literal
// {name} placeholder in the URL. Sending a request with an unsubstituted
// placeholder produces confusing backend-specific errors (400 "could not
// route", 401 auth errors, etc.) that look unrelated to the real cause.
func TestBuildPath_MissingRequiredParam(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Path: "/accounts/{account_id}/d1/database",
		Params: map[string]dadl.ParamDef{
			testParamAccountID: {Type: schemaTypeString, In: paramInPath, Required: true},
		},
	}

	// No account_id supplied.
	_, err = adapter.buildPath(tool, map[string]any{})
	if err == nil {
		t.Fatal("expected error for missing path parameter, got nil")
	}
	if !strings.Contains(err.Error(), testParamAccountID) {
		t.Errorf("error does not mention the missing parameter name: %v", err)
	}

	// Explicitly nil value.
	_, err = adapter.buildPath(tool, map[string]any{testParamAccountID: nil})
	if err == nil {
		t.Fatal("expected error for nil path parameter, got nil")
	}

	// Empty string.
	_, err = adapter.buildPath(tool, map[string]any{testParamAccountID: ""})
	if err == nil {
		t.Fatal("expected error for empty path parameter, got nil")
	}
}

// TestBuildPath_SubstitutesAllRequiredParams verifies the happy path with
// multiple path parameters.
func TestBuildPath_SubstitutesAllRequiredParams(t *testing.T) {
	spec := &dadl.Spec{
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools:   map[string]dadl.ToolDef{"t": {Method: testMethodGET, Path: "/"}},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	tool := &dadl.ToolDef{
		Path: "/accounts/{account_id}/d1/database/{database_id}/query",
		Params: map[string]dadl.ParamDef{
			testParamAccountID: {Type: schemaTypeString, In: paramInPath, Required: true},
			"database_id":      {Type: schemaTypeString, In: paramInPath, Required: true},
		},
	}

	path, err := adapter.buildPath(tool, map[string]any{
		testParamAccountID: "acct-123",
		"database_id":      "db-456",
	})
	if err != nil {
		t.Fatalf("buildPath: %v", err)
	}
	want := "/accounts/acct-123/d1/database/db-456/query"
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
}
