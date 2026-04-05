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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestFlattenFormValues(t *testing.T) {
	vals := url.Values{}
	flattenFormValues(vals, "", map[string]any{
		"str":  "hello",
		"num":  float64(3.14),
		"int":  42,
		"i64":  int64(100),
		"bool": true,
		"null": nil,
		"arr":  []any{"a", "b"},
		"obj":  map[string]any{"nested": "value"},
	})

	if vals.Get("str") != "hello" {
		t.Errorf("str = %q", vals.Get("str"))
	}
	if vals.Get("num") != "3.14" {
		t.Errorf("num = %q", vals.Get("num"))
	}
	if vals.Get("int") != "42" {
		t.Errorf("int = %q", vals.Get("int"))
	}
	if vals.Get("i64") != "100" {
		t.Errorf("i64 = %q", vals.Get("i64"))
	}
	if vals.Get("bool") != "true" {
		t.Errorf("bool = %q", vals.Get("bool"))
	}
	if vals.Get("arr[0]") != "a" || vals.Get("arr[1]") != "b" {
		t.Errorf("arr = %v", vals)
	}
	if vals.Get("obj[nested]") != "value" {
		t.Errorf("obj = %v", vals)
	}
}

func TestFlattenFormValues_BoolFalse(t *testing.T) {
	vals := url.Values{}
	flattenFormValues(vals, "flag", false)
	if vals.Get("flag") != "false" {
		t.Errorf("got %q", vals.Get("flag"))
	}
}

func TestFlattenFormValues_Default(t *testing.T) {
	vals := url.Values{}
	flattenFormValues(vals, "obj", struct{ X int }{X: 1})
	if vals.Get("obj") == "" {
		t.Error("fallback should set value")
	}
}

func TestRESTAdapter_BinaryResponse(t *testing.T) {
	binaryData := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(binaryData)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name: "api", Type: "rest", BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"get_image": {
					Method: "GET", Path: "/image",
					Response: &dadl.ResponseConfig{
						Binary:      true,
						ContentType: "image/png",
					},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	// Attach a blob store so binary responses can be served.
	bs, _ := blob.NewStore(t.TempDir(), "http://localhost:8080", slog.Default())
	a.SetBlobStore(bs)
	result, err := a.Execute(context.Background(), "get_image", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("error result: %v", result.Content)
	}
	// Content should include the binary data (base64 or similar).
	if len(result.Content) == 0 {
		t.Error("no content")
	}
}

func TestRESTAdapter_QueryParams(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name: "api", Type: "rest", BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"search": {
					Method: "GET", Path: "/search",
					Params: map[string]dadl.ParamDef{
						"q":     {Type: "string", In: "query", Required: true},
						"limit": {Type: "integer", In: "query"},
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default())
	_, err := a.Execute(context.Background(), "search", map[string]any{"q": "hello", "limit": 10})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "q=hello") {
		t.Errorf("query = %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "limit=10") {
		t.Errorf("limit missing: %q", gotQuery)
	}
}

func TestReadCloser_ByteCounter(t *testing.T) {
	r := &byteCounter{Reader: strings.NewReader("hello world")}
	buf := make([]byte, 100)
	n, err := r.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if n != 11 {
		t.Errorf("read n = %d, want 11", n)
	}
	if r.N != 11 {
		t.Errorf("counter = %d", r.N)
	}
}
