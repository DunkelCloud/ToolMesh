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

// redactResultText extracts the text content of a ToolResult.
func redactResultText(t *testing.T, result *ToolResult) string {
	t.Helper()
	content, ok := result.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected content shape %T", result.Content[0])
	}
	text, _ := content[contentTypeText].(string)
	return text
}

func TestRESTAdapter_ResponseRedact(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"data": [{"name": "hook-a", "secret": "topsecret-1"}, {"name": "hook-b", "secret": "topsecret-2"}]}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"list_hooks": {
					Method: testMethodGET, Path: "/hooks",
					Response: &dadl.ResponseConfig{
						ResultPath: "$.data",
						Redact:     []string{"$[*].secret"},
					},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "list_hooks", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %v", result.Content)
	}
	text := redactResultText(t, result)
	if strings.Contains(text, "topsecret") {
		t.Errorf("secret leaked into result: %s", text)
	}
	if !strings.Contains(text, dadl.RedactedPlaceholder) {
		t.Errorf("placeholder missing in result: %s", text)
	}
	if !strings.Contains(text, "hook-a") || !strings.Contains(text, "hook-b") {
		t.Errorf("non-secret fields must survive redaction: %s", text)
	}
}

func TestRESTAdapter_RedactMergesAdditively(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"password": "default-secret", "token": "tool-secret", "ok": "visible"}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Response: &dadl.ResponseConfig{Redact: []string{"$.password"}},
			},
			Tools: map[string]dadl.ToolDef{
				"get_config": {
					Method: testMethodGET, Path: "/config",
					// Tool-level response replaces the defaults block for
					// everything EXCEPT redact, which merges additively.
					Response: &dadl.ResponseConfig{Redact: []string{"$.token"}},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "get_config", nil)
	if err != nil {
		t.Fatal(err)
	}
	text := redactResultText(t, result)
	if strings.Contains(text, "default-secret") || strings.Contains(text, "tool-secret") {
		t.Errorf("merged redact list must mask both levels: %s", text)
	}
	if !strings.Contains(text, "visible") {
		t.Errorf("unrelated field must survive: %s", text)
	}
}

func TestRESTAdapter_RedactFailsClosedOnTransformError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"unexpected": {"secret": "leakme"}}`))
	}))
	defer srv.Close()

	makeSpec := func(redact []string) *dadl.Spec {
		return &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name:    testBackendNameAPI,
				Type:    transportTypeREST,
				BaseURL: srv.URL,
				Tools: map[string]dadl.ToolDef{
					"t": {
						Method: testMethodGET, Path: "/",
						Response: &dadl.ResponseConfig{
							ResultPath: "$.data", // absent in the response — transform fails
							Redact:     redact,
						},
					},
				},
			},
		}
	}

	// With redact declared, a transform failure must fail the call instead
	// of returning the untransformed (unredacted) body.
	a, err := NewRESTAdapter(makeSpec([]string{"$.secret"}), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("transform failure with redact declared must produce an error result")
	}
	text := redactResultText(t, result)
	if strings.Contains(text, "leakme") {
		t.Errorf("error result must not carry the unredacted body: %s", text)
	}

	// Without redact, the pre-existing warn-and-continue behavior stays.
	a2, err := NewRESTAdapter(makeSpec(nil), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result2, err := a2.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result2.IsError {
		t.Fatalf("without redact a transform error must not fail the call: %v", result2.Content)
	}
}
