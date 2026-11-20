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
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_PlaceholderInQueryOfPath pins that a tool whose path
// template carries a path parameter after "?" is refused when the backend
// is built, also for a spec that never went through the parser. Such a
// value is escaped as a path segment, so "x&admin=true" would reach the API
// as two query parameters. The same parameter declared with in: query is
// escaped as one value.
func TestRESTAdapter_PlaceholderInQueryOfPath(t *testing.T) {
	var query atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.RawQuery
		query.Store(&q)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	const tool = "find"
	spec := func(path, in string) *dadl.Spec {
		return &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name:    testBackendNameAPI,
				Type:    transportTypeREST,
				BaseURL: srv.URL,
				Tools: map[string]dadl.ToolDef{
					tool: {Method: testMethodGET, Path: path, Params: map[string]dadl.ParamDef{
						"q": {Type: schemaTypeString, In: in, Required: true},
					}},
				},
			},
		}
	}

	_, err := NewRESTAdapter(spec("/search?q={q}", paramInPath), &testCredStore{}, slog.Default(), testRESTOpts)
	if err == nil || !strings.Contains(err.Error(), "placeholder in its query") {
		t.Fatalf("a placeholder in the query part of a path was accepted: %v", err)
	}

	a, err := NewRESTAdapter(spec("/search", paramInQuery), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), tool, map[string]any{"q": "x&admin=true"})
	if err != nil || result.IsError {
		t.Fatalf("Execute: %v %v", err, result)
	}
	if got := query.Load(); got == nil || *got != "q=x%26admin%3Dtrue" {
		t.Errorf("query = %v, want the value as one escaped parameter", got)
	}
}
