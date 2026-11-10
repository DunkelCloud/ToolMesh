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
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

const (
	testCompositeCountItems = "count_items"
	testCompositeTouch      = "touch"
	testParamProjectID      = "project_id"
	testParamMode           = "mode"
	testParamNote           = "note"
)

// recordingChildGuard is a test ChildGuard that records the canonical tool
// names it is asked to authorize, and the arguments its gate would see, and
// returns a fixed error (nil = allow).
type recordingChildGuard struct {
	seen   []string
	params []map[string]any
	err    error
}

func (g *recordingChildGuard) CheckChild(_ context.Context, toolName string, params map[string]any) error {
	g.seen = append(g.seen, toolName)
	g.params = append(g.params, params)
	return g.err
}

func TestRESTAdapter_CompositeChildGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == testPathItems {
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	newAdapter := func(t *testing.T) *RESTAdapter {
		t.Helper()
		spec := &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name:    testBackendNameAPI,
				Type:    transportTypeREST,
				BaseURL: srv.URL,
				Tools: map[string]dadl.ToolDef{
					testToolListItems: {Method: testMethodGET, Path: testPathItems},
				},
				Composites: map[string]dadl.CompositeDef{
					testCompositeCountItems: {
						Description: "Count items",
						Code:        "const items = await api.list_items(); return items.length;",
						Timeout:     "5s",
					},
				},
			},
		}
		a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	t.Run("guard authorizes each child with its canonical name", func(t *testing.T) {
		adapter := newAdapter(t)
		guard := &recordingChildGuard{}
		adapter.SetChildGuard(guard)

		result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatalf("composite returned error: %v", result.Content)
		}
		if len(guard.seen) != 1 || guard.seen[0] != testBackendNameAPI+"_"+testToolListItems {
			t.Errorf("guard saw %v, want [%s_%s]", guard.seen, testBackendNameAPI, testToolListItems)
		}
	})

	t.Run("guard denial aborts the composite (fail closed)", func(t *testing.T) {
		adapter := newAdapter(t)
		adapter.SetChildGuard(&recordingChildGuard{err: errors.New("not authorized")})

		result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Error("expected composite to fail closed when the child guard denies the child call")
		}
	})

	t.Run("arguments are checked before the guard", func(t *testing.T) {
		adapter := newAdapter(t)
		adapter.spec.Backend.Tools[testToolListItems] = dadl.ToolDef{
			Method: testMethodGET, Path: testPathItems,
			Params: map[string]dadl.ParamDef{"flag": {Type: schemaTypeBoolean, In: testParamQuery}},
		}
		adapter.spec.Backend.Composites[testCompositeCountItems] = dadl.CompositeDef{
			Code:    `const items = await api.list_items({flag: "false"}); return items.length;`,
			Timeout: "5s",
		}
		guard := &recordingChildGuard{}
		adapter.SetChildGuard(guard)

		result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError || !strings.Contains(redactResultText(t, result), "must be boolean") {
			t.Fatalf("expected a type error from the child call, got %v", result.Content)
		}
		if len(guard.seen) != 0 {
			t.Errorf("guard (and its gate) saw the badly typed child call: %v", guard.seen)
		}
	})

	t.Run("composite SetChildGuard(nil) removes the guard", func(t *testing.T) {
		adapter := newAdapter(t)
		comp := NewCompositeBackend(map[string]ToolBackend{testBackendNameAPI: adapter})
		comp.SetChildGuard(AllowAllChildGuard{})
		comp.SetChildGuard(nil)
		result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Error("after SetChildGuard(nil) the old guard still allowed the child call")
		}
	})

	t.Run("no guard refuses child calls (fail closed)", func(t *testing.T) {
		adapter := newAdapter(t)

		result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected composite to fail closed when no child guard is installed")
		}
		if text := redactResultText(t, result); !strings.Contains(text, "no authorization guard") {
			t.Errorf("error = %q, want it to name the missing guard", text)
		}
	})

	// The composite remembers the guard and installs it on every backend that
	// reaches it later. A hot reload of backends.yaml swaps in fresh adapters;
	// their composites must still be checked.
	installPaths := []struct {
		name    string
		install func(c *CompositeBackend, a *RESTAdapter)
	}{
		{"Swap", func(c *CompositeBackend, a *RESTAdapter) {
			c.Swap(map[string]ToolBackend{testBackendNameAPI: a}, nil)
		}},
		{"AddNamed", func(c *CompositeBackend, a *RESTAdapter) {
			c.AddNamed(testBackendNameAPI, a)
		}},
		{"AddPassthrough", func(c *CompositeBackend, a *RESTAdapter) {
			c.AddPassthrough(a)
		}},
	}
	for _, p := range installPaths {
		t.Run("guard survives "+p.name, func(t *testing.T) {
			comp := NewCompositeBackend(map[string]ToolBackend{testBackendNameAPI: newAdapter(t)})
			guard := &recordingChildGuard{err: errors.New("not authorized")}
			comp.SetChildGuard(guard)

			fresh := newAdapter(t)
			p.install(comp, fresh)

			result, err := fresh.Execute(context.Background(), testCompositeCountItems, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Error("a backend installed after SetChildGuard ran its composite without the guard")
			}
			if len(guard.seen) != 1 {
				t.Errorf("guard saw %v, want exactly one child check", guard.seen)
			}
		})
	}
}

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
				testCompositeCountItems: {
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
	adapter.SetChildGuard(AllowAllChildGuard{})

	// Composite must appear in ListTools.
	tools, _ := adapter.ListTools(context.Background())
	found := false
	for _, tool := range tools {
		if tool.Name == testCompositeCountItems {
			found = true
		}
	}
	if !found {
		t.Error("composite not in tool list")
	}

	// Execute the composite.
	result, err := adapter.Execute(context.Background(), testCompositeCountItems, nil)
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

// TestRESTAdapter_CompositeChildStringParamsAsText pins that an api.* child
// call hands the guard (and so the pre-execution gate) a number or boolean
// for a string parameter as the text the request carries, as a direct call
// does. A value with no text form, such as a BigInt, is refused.
func TestRESTAdapter_CompositeChildStringParamsAsText(t *testing.T) {
	var (
		mu               sync.Mutex
		gotPath, gotMode string
		gotBody          map[string]any
		hits             int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		mu.Lock()
		hits++
		gotPath, gotMode, gotBody = r.URL.Path, r.URL.Query().Get(testParamMode), body
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	newAdapter := func(t *testing.T, code string) (*RESTAdapter, *recordingChildGuard) {
		t.Helper()
		spec := &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
				Tools: map[string]dadl.ToolDef{
					"update_project": {Method: http.MethodPut, Path: "/projects/{project_id}", Params: map[string]dadl.ParamDef{
						testParamProjectID: {Type: schemaTypeString, In: paramInPath},
						testParamMode:      {Type: schemaTypeString, In: paramInQuery},
						testParamNote:      {Type: schemaTypeString, In: paramInBody},
					}},
				},
				Composites: map[string]dadl.CompositeDef{
					testCompositeTouch: {Code: code, Timeout: "5s"},
				},
			},
		}
		a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
		if err != nil {
			t.Fatal(err)
		}
		guard := &recordingChildGuard{}
		a.SetChildGuard(guard)
		return a, guard
	}

	t.Run("numbers and booleans become text", func(t *testing.T) {
		adapter, guard := newAdapter(t, `return await api.update_project({project_id: 42, mode: true, note: 4.5});`)
		result, err := adapter.Execute(context.Background(), testCompositeTouch, nil)
		if err != nil {
			t.Fatal(err)
		}
		if result.IsError {
			t.Fatalf("composite returned error: %v", result.Content)
		}
		if len(guard.params) != 1 {
			t.Fatalf("guard saw %d child calls, want 1", len(guard.params))
		}
		mu.Lock()
		defer mu.Unlock()
		want := map[string]string{testParamProjectID: "42", testParamMode: "true", testParamNote: "4.5"}
		for name, text := range want {
			if got, ok := guard.params[0][name].(string); !ok || got != text {
				t.Errorf("guard saw %s = %#v, want %q", name, guard.params[0][name], text)
			}
		}
		if gotPath != "/projects/42" || gotMode != "true" {
			t.Errorf("request %s?mode=%s, want /projects/42?mode=true", gotPath, gotMode)
		}
		if note, ok := gotBody[testParamNote].(string); !ok || note != "4.5" {
			t.Errorf("body note = %#v, want the string \"4.5\"", gotBody[testParamNote])
		}
	})

	t.Run("a BigInt is refused before the guard", func(t *testing.T) {
		mu.Lock()
		before := hits
		mu.Unlock()
		adapter, guard := newAdapter(t, `return await api.update_project({project_id: 42n});`)
		result, err := adapter.Execute(context.Background(), testCompositeTouch, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError || !strings.Contains(redactResultText(t, result), `parameter "project_id" must be string`) {
			t.Fatalf("expected a type error from the child call, got %v", result.Content)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(guard.seen) != 0 || hits != before {
			t.Errorf("the BigInt call got past the check: guard %v, requests %d", guard.seen, hits-before)
		}
	})
}
