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
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_PathParamSegmentSeparators pins that a path parameter
// value with ";" or "\" is refused before any request is sent. Servers that
// cut a ";..." suffix off a path segment would read "..;" as "..", and
// servers that read "\" as "/" would read "..\" the same way: the dot
// segments that are refused as plain values would arrive after all. Other
// punctuation stays allowed and reaches the API as one segment.
func TestRESTAdapter_PathParamSegmentSeparators(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	const tool = "issues"
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL + "/api/v4",
			Tools: map[string]dadl.ToolDef{
				tool: {Method: testMethodGET, Path: "/projects/{id}/issues", Params: map[string]dadl.ParamDef{
					"id": {Type: schemaTypeString, In: paramInPath, Required: true},
				}},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}

	refused := []string{"..;", "..;x=1", ".;", ";", "42;x", `..\`, `..\..\admin`, `a\b`, `\`}
	for _, v := range refused {
		result, err := a.Execute(context.Background(), tool, map[string]any{"id": v})
		if err == nil && (result == nil || !result.IsError) {
			t.Errorf("id %q: expected rejection", v)
		}
	}
	mu.Lock()
	if len(paths) != 0 {
		t.Errorf("backend received requests for refused values: %v", paths)
	}
	mu.Unlock()

	allowed := map[string]string{
		"group/project": "/api/v4/projects/group%2Fproject/issues",
		"a:b,c=d":       "/api/v4/projects/a:b%2Cc=d/issues",
		"v1.2..3":       "/api/v4/projects/v1.2..3/issues",
	}
	for v, want := range allowed {
		mu.Lock()
		paths = nil
		mu.Unlock()
		result, err := a.Execute(context.Background(), tool, map[string]any{"id": v})
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Errorf("id %q was refused: %v", v, result.Content)
			continue
		}
		mu.Lock()
		if len(paths) != 1 || paths[0] != want {
			t.Errorf("id %q: backend saw %v, want %q", v, paths, want)
		}
		mu.Unlock()
	}
}
