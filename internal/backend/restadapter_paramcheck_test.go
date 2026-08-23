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

// resultText returns the first text content block of a ToolResult.
func resultText(t *testing.T, result *ToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("result has no content blocks")
	}
	block, ok := result.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("content[0] = %T, want map[string]any", result.Content[0])
	}
	text, ok := block[contentTypeText].(string)
	if !ok {
		t.Fatalf("content[0].text = %v, want a string", block[contentTypeText])
	}
	return text
}

// paramCheckSpec mirrors the shape that produced the original misdiagnosis: a
// primitive search tool whose time window is a required object parameter, and
// a composite over it with the same parameter surface. Guessing `range` for
// `time_range` used to run the call anyway, against whatever default window
// the API picked.
func paramCheckSpec(baseURL string) *dadl.Spec {
	searchParams := map[string]dadl.ParamDef{
		testParamQuery:     {Type: schemaTypeString, In: paramInBody, Required: true},
		testParamTimeRange: {Type: schemaTypeObject, In: paramInBody, Required: true},
		testParamLimit:     {Type: schemaTypeInteger, In: paramInQuery, Default: 50},
	}
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Tools: map[string]dadl.ToolDef{
				testToolSearchMessages: {
					Method: http.MethodPost,
					Path:   "/search",
					Params: searchParams,
				},
				"get_message": {
					Method: testMethodGET,
					Path:   "/messages/{id}",
					Params: map[string]dadl.ParamDef{
						"id": {Type: schemaTypeString, In: paramInPath},
					},
				},
			},
			Composites: map[string]dadl.CompositeDef{
				testCompositeSearchCompact: {
					Description: "Search and compact",
					Params: map[string]dadl.ParamDef{
						testParamQuery:     {Type: schemaTypeString, Required: true},
						testParamTimeRange: {Type: schemaTypeObject, Required: true},
					},
					Code: `const r = await api.search_messages({query: params.query, time_range: params.time_range});
return r;`,
				},
				"passthrough": {
					Description: "Calls a primitive with whatever it was given",
					Params: map[string]dadl.ParamDef{
						"id": {Type: schemaTypeString, Required: true},
					},
					Code: `return await api.get_message({identifier: params.id});`,
				},
			},
		},
	}
}

// newParamCheckAdapter builds an adapter over a server that fails the test if
// it is ever reached, so every case below also proves the rejection happened
// before the request went out.
func newParamCheckAdapter(t *testing.T) *RESTAdapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("backend must not be called for a call with invalid parameters")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	adapter, err := NewRESTAdapter(paramCheckSpec(srv.URL), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	return adapter
}

// TestExecute_ParamValidation covers the two faults that used to pass through
// the runtime unannounced: an argument the tool does not declare, and a
// required parameter left out.
func TestExecute_ParamValidation(t *testing.T) {
	adapter := newParamCheckAdapter(t)

	tests := []struct {
		name   string
		tool   string
		params map[string]any
		want   []string
	}{
		{
			name: "unknown param names the declared one it resembles",
			tool: testToolSearchMessages,
			params: map[string]any{
				testParamQuery:     testQueryFirewall,
				testParamTimeRange: map[string]any{schemaKeyType: "relative", testParamRange: 14400},
				testParamRange:     14400,
			},
			want: []string{testWantUnknownRange, `did you mean "time_range"`},
		},
		{
			name:   "missing required param is reported with the declared set",
			tool:   testToolSearchMessages,
			params: map[string]any{testParamQuery: testQueryFirewall},
			want:   []string{testWantMissingTimeRange, "declared parameters:", "time_range (object, in: body, required)"},
		},
		{
			name:   "both faults are reported together",
			tool:   testToolSearchMessages,
			params: map[string]any{testParamQuery: testQueryFirewall, testParamRange: 14400},
			want:   []string{testWantUnknownRange, testWantMissingTimeRange},
		},
		{
			name:   "path param counts as required",
			tool:   "get_message",
			params: map[string]any{},
			want:   []string{`missing required parameter "id"`},
		},
		{
			name:   "composite rejects a missing required param",
			tool:   testCompositeSearchCompact,
			params: map[string]any{testParamQuery: testQueryFirewall},
			want:   []string{testWantMissingTimeRange},
		},
		{
			name:   "composite rejects an undeclared param",
			tool:   testCompositeSearchCompact,
			params: map[string]any{testParamQuery: testQueryFirewall, testParamTimeRange: map[string]any{}, testParamLimit: 5},
			want:   []string{`unknown parameter "limit"`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := adapter.Execute(context.Background(), tt.tool, tt.params)
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if !result.IsError {
				t.Fatalf("result.IsError = false, want the call rejected")
			}
			text := resultText(t, result)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Errorf("content = %q, want substring %q", text, want)
				}
			}
		})
	}
}

// TestBuildInputSchema_ClosedToExtras keeps the advertised schema honest about
// what the runtime accepts. An open object next to a runtime that rejects
// undeclared arguments is the discrepancy that lets a caller believe an extra
// argument was taken.
func TestBuildInputSchema_ClosedToExtras(t *testing.T) {
	adapter := newParamCheckAdapter(t)

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	if len(tools) == 0 {
		t.Fatal("no tools listed")
	}
	for _, tool := range tools {
		if got, ok := tool.InputSchema[schemaKeyAdditionalProperties]; !ok || got != false {
			t.Errorf("%s: additionalProperties = %v (present=%v), want false", tool.Name, got, ok)
		}
	}
}

// TestExecute_ParamValidation_SemanticError pins the §8.2 metadata on a
// rejection: composite code and Code Mode branch on e.code / e.http_status,
// so a validation failure has to look like the 400 it is rather than an
// untyped error.
func TestExecute_ParamValidation_SemanticError(t *testing.T) {
	adapter := newParamCheckAdapter(t)

	result, err := adapter.Execute(context.Background(), testToolSearchMessages, map[string]any{"nope": 1})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := result.Metadata[metadataKeyErrorCode]; got != dadl.ErrCodeInvalidInput {
		t.Errorf("error_code = %v, want %q", got, dadl.ErrCodeInvalidInput)
	}
	if got := result.Metadata[metadataKeyStatusCode]; got != http.StatusBadRequest {
		t.Errorf("statusCode = %v, want %d", got, http.StatusBadRequest)
	}
	if apiErr := apiErrorFromMetadata(result); apiErr == nil {
		t.Fatal("apiErrorFromMetadata = nil, want the structured form a composite catch reads")
	}
}

// TestExecute_ParamValidation_ChildCall covers the composite path the original
// report singled out: a child api.* call with a mistyped parameter name has to
// abort the composite instead of running with the argument dropped.
func TestExecute_ParamValidation_ChildCall(t *testing.T) {
	adapter := newParamCheckAdapter(t)

	result, err := adapter.Execute(context.Background(), "passthrough", map[string]any{"id": "42"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !result.IsError {
		t.Fatalf("result.IsError = false, want the composite to fail on its child call")
	}
	text := resultText(t, result)
	for _, want := range []string{`unknown parameter "identifier"`, `missing required parameter "id"`} {
		if !strings.Contains(text, want) {
			t.Errorf("content = %q, want substring %q", text, want)
		}
	}
}

// TestExecute_ParamValidation_Accepts guards the cases that must keep working:
// a declared default stands in for a required value, an explicit body null is
// a value rather than an omission, and an optional parameter may be left out.
func TestExecute_ParamValidation_Accepts(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = map[string]any{"query": r.URL.RawQuery}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
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
					Method: testMethodPOST,
					Path:   testPathItems,
					Params: map[string]dadl.ParamDef{
						"version":  {Type: schemaTypeString, In: paramInQuery, Required: true, Default: "2.0"},
						"nullable": {Type: schemaTypeString, In: paramInBody, Required: true},
						"optional": {Type: schemaTypeString, In: paramInQuery},
					},
				},
			},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "t", map[string]any{"nullable": nil})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("call rejected, want accepted: %s", resultText(t, result))
	}
	if !strings.Contains(got["query"].(string), "version=2.0") {
		t.Errorf("query = %v, want the declared default to have been sent", got["query"])
	}
}
