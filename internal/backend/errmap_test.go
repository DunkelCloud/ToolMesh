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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestRESTAdapter_SemanticErrorCodes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": {"message": "no such customer", "code": "resource_missing"}}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_customer": {
					Method: testMethodGET, Path: "/customer",
					Errors: &dadl.ErrorConfig{
						Format:      testJSONFormat,
						MessagePath: "$.error.message",
						CodePath:    "$.error.code",
						Terminal:    []int{400},
						Map:         map[int]string{400: dadl.ErrCodeNotFound},
					},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "get_customer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := redactResultText(t, result)
	if !strings.Contains(text, "[not_found] HTTP 400: no such customer") ||
		!strings.Contains(text, "provider_code=resource_missing") {
		t.Errorf("stable error text wrong: %s", text)
	}
	if got := result.Metadata[metadataKeyErrorCode]; got != dadl.ErrCodeNotFound {
		t.Errorf("metadata error_code = %v, want not_found", got)
	}
	if got := result.Metadata[metadataKeyProviderCode]; got != "resource_missing" {
		t.Errorf("metadata provider_code = %v, want resource_missing", got)
	}
	if got := result.Metadata[metadataKeyStatusCode]; got != 400 {
		t.Errorf("metadata status = %v, want 400", got)
	}
}

func TestRESTAdapter_BareErrorGetsSemanticCode(t *testing.T) {
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
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected IsError=true")
	}
	text := redactResultText(t, result)
	if !strings.Contains(text, "[not_found] HTTP 404") {
		t.Errorf("bare error must carry the default semantic code: %s", text)
	}
	if got := result.Metadata[metadataKeyErrorCode]; got != dadl.ErrCodeNotFound {
		t.Errorf("metadata error_code = %v, want not_found", got)
	}
}

// TestRESTAdapter_CompositeCatchesSemanticCode pins the spec §8.2 promise
// for composites: a failed api.* call throws an error whose code /
// http_status / provider_code properties composite code can branch on.
func TestRESTAdapter_CompositeCatchesSemanticCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": {"message": "no such customer", "code": "resource_missing"}}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_customer": {
					Method: testMethodGET, Path: "/customer",
					Errors: &dadl.ErrorConfig{
						Format:      testJSONFormat,
						MessagePath: "$.error.message",
						CodePath:    "$.error.code",
						Terminal:    []int{400},
						Map:         map[int]string{400: dadl.ErrCodeNotFound},
					},
				},
			},
			Composites: map[string]dadl.CompositeDef{
				"find_customer": {
					Description: "Fetch a customer, treating not_found as null",
					Code: `try {
  return await api.get_customer({});
} catch (e) {
  if (e.code === "not_found") {
    return {missing: true, status: e.http_status, provider: e.provider_code};
  }
  throw e;
}`,
					Timeout: "5s",
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "find_customer", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("composite must catch the semantic error, got error result: %v", result.Content)
	}
	var out struct {
		Missing  bool   `json:"missing"`
		Status   int    `json:"status"`
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal([]byte(redactResultText(t, result)), &out); err != nil {
		t.Fatalf("composite result not JSON: %v", err)
	}
	if !out.Missing || out.Status != 400 || out.Provider != "resource_missing" {
		t.Errorf("composite saw %+v, want missing=true status=400 provider=resource_missing", out)
	}
}
