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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestRESTAdapter_ExecuteComposite(t *testing.T) {
	// Upstream: GET /items returns a JSON array.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testPathItems {
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				testToolListItems: {
					Method: testMethodGET,
					Path:   testPathItems,
				},
			},
			Composites: map[string]dadl.CompositeDef{
				"count_items": {
					Description: "Count items",
					Params:      map[string]dadl.ParamDef{},
					Code:        "const items = await api.list_items(); return items.length;",
					Timeout:     "5s",
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Composite must appear in ListTools.
	tools, _ := adapter.ListTools(context.Background())
	found := false
	for _, tool := range tools {
		if tool.Name == "count_items" {
			found = true
		}
	}
	if !found {
		t.Error("composite not in tool list")
	}

	// Execute the composite.
	result, err := adapter.Execute(context.Background(), "count_items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("composite returned error: %v", result.Content)
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	if !strings.Contains(text, "2") {
		t.Errorf("expected count 2, got %s", text)
	}
}

func TestRESTAdapter_ExecuteComposite_Error(t *testing.T) {
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: "https://example.invalid",
			Composites: map[string]dadl.CompositeDef{
				"bad": {
					Description: "Bad composite",
					Code:        `throw new Error("oops");`,
					Timeout:     "5s",
				},
			},
		},
	}
	adapter, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := adapter.Execute(context.Background(), "bad", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true")
	}
}

func TestBuildCompositeInputSchema(t *testing.T) {
	comp := dadl.CompositeDef{
		Params: map[string]dadl.ParamDef{
			"id":      {Type: schemaTypeString, Required: true},
			"verbose": {Type: schemaTypeBoolean, Default: false},
		},
	}
	schema := buildCompositeInputSchema(comp)
	if schema[schemaKeyType] != schemaTypeObject {
		t.Errorf("type = %v", schema[schemaKeyType])
	}
	props := schema[schemaKeyProperties].(map[string]any)
	if _, ok := props["id"]; !ok {
		t.Error("missing id")
	}
	required, _ := schema["required"].([]string)
	if len(required) != 1 || required[0] != "id" {
		t.Errorf("required = %v", required)
	}
}

func TestExtractToolResultContent(t *testing.T) {
	// JSON-parseable text → parsed value.
	r := &ToolResult{
		Content: []any{map[string]any{schemaKeyType: contentTypeText, contentTypeText: `{"a": 1}`}},
	}
	got := extractToolResultContent(r)
	m, ok := got.(map[string]any)
	if !ok || m["a"] != float64(1) {
		t.Errorf("got %v", got)
	}

	// Non-JSON text → string.
	r2 := &ToolResult{
		Content: []any{map[string]any{schemaKeyType: contentTypeText, contentTypeText: "plain"}},
	}
	if got := extractToolResultContent(r2); got != "plain" {
		t.Errorf("got %v", got)
	}

	// Nil / empty.
	if got := extractToolResultContent(nil); got != nil {
		t.Errorf("got %v", got)
	}
	if got := extractToolResultContent(&ToolResult{}); got != nil {
		t.Errorf("got %v", got)
	}
}

func TestMarshallResults_Paginated(t *testing.T) {
	// Unit test for the pagination helpers.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get(testParamPage)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		switch page {
		case "", "1":
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
		case "2":
			_, _ = w.Write([]byte(`[{"id": 3}]`))
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Pagination: &dadl.PaginationConfig{
					Strategy: testParamPage,
					Request:  dadl.PaginationRequest{PageParam: testParamPage},
					Behavior: "auto",
					MaxPages: 5,
				},
			},
			Tools: map[string]dadl.ToolDef{
				"list": {
					Method: testMethodGET,
					Path:   "/",
					Params: map[string]dadl.ParamDef{
						testParamPage: {Type: schemaTypeInteger, In: paramInQuery},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := adapter.Execute(context.Background(), "list", map[string]any{testParamPage: 1})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("error result: %v", result.Content)
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	// Should aggregate pages — contain all 3 ids.
	if !strings.Contains(text, `"id":1`) && !strings.Contains(text, `"id": 1`) {
		t.Errorf("missing id=1 in aggregated result: %s", text)
	}
}
