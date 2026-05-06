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
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_HeaderParam_Forwarded verifies that a tool parameter
// declared with `in: header` reaches the upstream as an HTTP header with the
// caller-supplied value. Regression test for the Google Places API
// X-Goog-FieldMask drop where header params were silently ignored, producing
// HTTP 400 "FieldMask is a required parameter" against the real API.
func TestRESTAdapter_HeaderParam_Forwarded(t *testing.T) {
	var (
		mu      sync.Mutex
		gotMask string
		gotCT   string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotMask = r.Header.Get(testHeaderFieldMask)
		gotCT = r.Header.Get(testHeaderContentType)
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"places":[]}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "places",
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					testHeaderContentType: testContentTypeJSON,
					testHeaderAccept:      testContentTypeJSON,
				},
			},
			Tools: map[string]dadl.ToolDef{
				"search_text": {
					Method: testMethodPOST,
					Path:   "/v1/places:searchText",
					Params: map[string]dadl.ParamDef{
						testHeaderFieldMask: {Type: schemaTypeString, In: paramInHeader, Required: true},
						testParamTextQuery:  {Type: schemaTypeString, In: paramInBody, Required: true},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	_, err = adapter.Execute(context.Background(), "search_text", map[string]any{
		testHeaderFieldMask: "places.id,places.displayName",
		testParamTextQuery:  "Bahnhof Hofheim",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMask != "places.id,places.displayName" {
		t.Errorf("X-Goog-FieldMask header = %q, want %q", gotMask, "places.id,places.displayName")
	}
	if gotCT != testContentTypeJSON {
		t.Errorf("Content-Type header = %q, want application/json (auth/content-type must not be clobbered)", gotCT)
	}
}

// TestRESTAdapter_HeaderParam_RequiredMissing verifies that a missing
// required header param produces a clear error BEFORE the HTTP request,
// rather than letting the upstream return an opaque 400.
func TestRESTAdapter_HeaderParam_RequiredMissing(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "places",
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"search_text": {
					Method: testMethodPOST,
					Path:   "/v1/places:searchText",
					Params: map[string]dadl.ParamDef{
						testHeaderFieldMask: {Type: schemaTypeString, In: paramInHeader, Required: true},
						testParamTextQuery:  {Type: schemaTypeString, In: paramInBody, Required: true},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	result, err := adapter.Execute(context.Background(), "search_text", map[string]any{
		testParamTextQuery: "x",
	})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatalf("expected error for missing required header param, got nil (called=%v)", called)
	}
	if called {
		t.Error("upstream was called despite missing required header — should fail fast")
	}
}

// TestRESTAdapter_HeaderParam_Default verifies that a param default is used
// when the caller does not supply a value, matching buildQuery's semantics.
func TestRESTAdapter_HeaderParam_Default(t *testing.T) {
	var gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept = r.Header.Get(testHeaderAccept)
		w.Header().Set(testHeaderContentType, "text/tab-separated-values")
		_, _ = w.Write([]byte("a\tb\n1\t2\n"))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "deepl",
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					testHeaderAccept: testContentTypeJSON,
				},
			},
			Tools: map[string]dadl.ToolDef{
				"export_glossary_as_tsv": {
					Method: testMethodGET,
					Path:   "/glossaries/{glossary_id}/entries",
					Params: map[string]dadl.ParamDef{
						"glossary_id":    {Type: schemaTypeString, In: paramInPath, Required: true},
						testHeaderAccept: {Type: schemaTypeString, In: paramInHeader, Default: "text/tab-separated-values"},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	_, err = adapter.Execute(context.Background(), "export_glossary_as_tsv", map[string]any{
		"glossary_id": "abc",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if gotAccept != "text/tab-separated-values" {
		t.Errorf("Accept header = %q, want text/tab-separated-values (per-tool default must override backend default)", gotAccept)
	}
}

// TestRESTAdapter_HeaderParam_ContentTypeAndAuthProtected verifies that a
// DADL `in: header` param cannot clobber Content-Type (owned by
// tool.ContentType / multipart) or Authorization (owned by auth.InjectAuth).
func TestRESTAdapter_HeaderParam_ContentTypeAndAuthProtected(t *testing.T) {
	var gotCT, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT = r.Header.Get(testHeaderContentType)
		gotAuth = r.Header.Get(testHeaderAuth)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "evil",
			Type:    transportTypeREST,
			BaseURL: srv.URL,
			Auth: dadl.AuthConfig{
				Type:       testTokenBearer,
				Credential: testTokenValue,
				InjectInto: paramInHeader,
				HeaderName: testHeaderAuth,
				Prefix:     "Bearer ",
			},
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					testHeaderContentType: testContentTypeJSON,
				},
			},
			Tools: map[string]dadl.ToolDef{
				"malicious": {
					Method: testMethodPOST,
					Path:   "/x",
					Params: map[string]dadl.ParamDef{
						// Attempt to clobber Content-Type and Authorization via
						// `in: header` params — must not succeed.
						testHeaderContentType: {Type: schemaTypeString, In: paramInHeader},
						testHeaderAuth:        {Type: schemaTypeString, In: paramInHeader},
						"payload":             {Type: schemaTypeString, In: paramInBody},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{testTokenValue: "sk_secret"}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	_, err = adapter.Execute(context.Background(), "malicious", map[string]any{
		testHeaderContentType: "text/evil",
		testHeaderAuth:        "Bearer attacker",
		"payload":             "hi",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if gotCT != testContentTypeJSON {
		t.Errorf("Content-Type = %q, want application/json (must be protected from header-param clobber)", gotCT)
	}
	if !strings.HasPrefix(gotAuth, "Bearer sk_secret") {
		t.Errorf("Authorization = %q, want Bearer sk_secret… (auth must not be clobbered by header-param)", gotAuth)
	}
}
