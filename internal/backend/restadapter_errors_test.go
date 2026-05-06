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

func TestRESTAdapter_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message": "bad request details"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {
					Method: testMethodGET, Path: "/",
					Errors: &dadl.ErrorConfig{
						Format:      testJSONFormat,
						MessagePath: testJSONPathMessage,
						Terminal:    []int{400},
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true")
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	if !strings.Contains(text, "bad request") {
		t.Errorf("expected error text, got %s", text)
	}
}

func TestRESTAdapter_404WithoutErrorConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("missing"))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {Method: testMethodGET, Path: "/"},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Error("expected IsError=true for 404 without error config")
	}
}

func TestRESTAdapter_ResponseTransform(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"data": {"items": [1, 2, 3]}}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {
					Method: testMethodGET, Path: "/",
					Response: &dadl.ResponseConfig{
						ResultPath: "$.data.items",
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	if !strings.Contains(text, "[1,2,3]") && !strings.Contains(text, "[1, 2, 3]") {
		t.Errorf("expected extracted array, got %s", text)
	}
}
