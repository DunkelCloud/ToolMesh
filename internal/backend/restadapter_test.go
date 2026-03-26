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
		Version: "1.0",
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

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default())
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
		Version: "1.0",
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

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default())
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
	adapter, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default())
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

		err := r.ParseMultipartForm(32 << 20)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}

		// Check form field
		receivedFormField = r.FormValue("description")

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
		Version: "1.0",
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

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default())
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	// Create a temp file to upload
	tmpFile, err := os.CreateTemp("", "test-upload-*.txt")
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
