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
		gotMask = r.Header.Get("X-Goog-FieldMask")
		gotCT = r.Header.Get("Content-Type")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"places":[]}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "places",
			Type:    "rest",
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					"Content-Type": "application/json",
					"Accept":       "application/json",
				},
			},
			Tools: map[string]dadl.ToolDef{
				"search_text": {
					Method: "POST",
					Path:   "/v1/places:searchText",
					Params: map[string]dadl.ParamDef{
						"X-Goog-FieldMask": {Type: "string", In: "header", Required: true},
						"textQuery":        {Type: "string", In: "body", Required: true},
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
		"X-Goog-FieldMask": "places.id,places.displayName",
		"textQuery":        "Bahnhof Hofheim",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotMask != "places.id,places.displayName" {
		t.Errorf("X-Goog-FieldMask header = %q, want %q", gotMask, "places.id,places.displayName")
	}
	if gotCT != "application/json" {
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
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "places",
			Type:    "rest",
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"search_text": {
					Method: "POST",
					Path:   "/v1/places:searchText",
					Params: map[string]dadl.ParamDef{
						"X-Goog-FieldMask": {Type: "string", In: "header", Required: true},
						"textQuery":        {Type: "string", In: "body", Required: true},
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
		"textQuery": "x",
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
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "text/tab-separated-values")
		_, _ = w.Write([]byte("a\tb\n1\t2\n"))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "deepl",
			Type:    "rest",
			BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					"Accept": "application/json",
				},
			},
			Tools: map[string]dadl.ToolDef{
				"export_glossary_as_tsv": {
					Method: "GET",
					Path:   "/glossaries/{glossary_id}/entries",
					Params: map[string]dadl.ParamDef{
						"glossary_id": {Type: "string", In: "path", Required: true},
						"Accept":      {Type: "string", In: "header", Default: "text/tab-separated-values"},
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
		gotCT = r.Header.Get("Content-Type")
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: dadl.BackendDef{
			Name:    "evil",
			Type:    "rest",
			BaseURL: srv.URL,
			Auth: dadl.AuthConfig{
				Type:       "bearer",
				Credential: "tok",
				InjectInto: "header",
				HeaderName: "Authorization",
				Prefix:     "Bearer ",
			},
			Defaults: dadl.DefaultsConfig{
				Headers: map[string]string{
					"Content-Type": "application/json",
				},
			},
			Tools: map[string]dadl.ToolDef{
				"malicious": {
					Method: "POST",
					Path:   "/x",
					Params: map[string]dadl.ParamDef{
						// Attempt to clobber Content-Type and Authorization via
						// `in: header` params — must not succeed.
						"Content-Type":  {Type: "string", In: "header"},
						"Authorization": {Type: "string", In: "header"},
						"payload":       {Type: "string", In: "body"},
					},
				},
			},
		},
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{"tok": "sk_secret"}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	_, err = adapter.Execute(context.Background(), "malicious", map[string]any{
		"Content-Type":  "text/evil",
		"Authorization": "Bearer attacker",
		"payload":       "hi",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}

	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (must be protected from header-param clobber)", gotCT)
	}
	if !strings.HasPrefix(gotAuth, "Bearer sk_secret") {
		t.Errorf("Authorization = %q, want Bearer sk_secret… (auth must not be clobbered by header-param)", gotAuth)
	}
}
