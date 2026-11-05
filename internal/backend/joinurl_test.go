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
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestJoinURL(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "host-only base with absolute path",
			base: testBaseURLExample,
			path: "/v2/items",
			want: "https://api.example.com/v2/items",
		},
		{
			name: "host-only base with trailing slash and absolute path",
			base: "https://api.example.com/",
			path: "/v2/items",
			want: "https://api.example.com/v2/items",
		},
		{
			name: "base with path prefix is preserved (GitLab)",
			base: testBaseURLGitLab,
			path: "/projects",
			want: "https://gitlab.example.com/api/v4/projects",
		},
		{
			name: "base with path prefix and trailing slash",
			base: "https://gitlab.example.com/api/v4/",
			path: "/projects",
			want: "https://gitlab.example.com/api/v4/projects",
		},
		{
			name: "base with deep path prefix (DeepL)",
			base: "https://api.deepl.com/v2",
			path: "/translate",
			want: "https://api.deepl.com/v2/translate",
		},
		{
			name: "absolute tool URL on different host overrides base",
			base: "https://maps.googleapis.com",
			path: "https://places.googleapis.com/v1/places:searchText",
			want: "https://places.googleapis.com/v1/places:searchText",
		},
		{
			name: "absolute tool URL with base that has path prefix",
			base: testBaseURLGitLab,
			path: "https://other.example.com/foo",
			want: "https://other.example.com/foo",
		},
		{
			name: "tool path without leading slash",
			base: "https://api.example.com/v2",
			path: "translate",
			want: "https://api.example.com/v2/translate",
		},
		{
			name: "percent-encoded path segment is preserved",
			base: testBaseURLExample,
			path: "/repos/owner/some%20repo",
			want: "https://api.example.com/repos/owner/some%20repo",
		},
		{
			name: "percent-encoded segment with base path prefix",
			base: testBaseURLGitLab,
			path: "/projects/group%2Fproject",
			want: "https://gitlab.example.com/api/v4/projects/group%2Fproject",
		},
		{
			name:    "invalid base URL",
			base:    "://not-a-url",
			path:    "/foo",
			wantErr: true,
		},
		{
			name: "colon in the first segment is not a scheme",
			base: testBaseURLGitLab,
			path: "evil.example:443/issues",
			want: "https://gitlab.example.com/api/v4/evil.example:443/issues",
		},
		{
			name: "escaped scheme in the first segment stays relative",
			base: testBaseURLGitLab,
			path: "https:%2F%2Fevil.example/issues",
			want: "https://gitlab.example.com/api/v4/https:%2F%2Fevil.example/issues",
		},
		{
			name: "network-path reference stays under the base",
			base: testBaseURLGitLab,
			path: "//evil.example/x",
			want: "https://gitlab.example.com/api/v4//evil.example/x",
		},
		{
			name:    "dot segments leaving the base path are rejected",
			base:    testBaseURLGitLab,
			path:    "/projects/../../issues",
			wantErr: true,
		},
		{
			name:    "dot segment at the start is rejected",
			base:    testBaseURLGitLab,
			path:    "/../issues",
			wantErr: true,
		},
		{
			name: "dot segments that stay inside the base path are resolved",
			base: testBaseURLGitLab,
			path: "/projects/x/../issues",
			want: "https://gitlab.example.com/api/v4/projects/issues",
		},
		{
			name: "colon in a later segment of a relative path",
			base: "https://places.googleapis.com/v1",
			path: "/places:autocomplete",
			want: "https://places.googleapis.com/v1/places:autocomplete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := joinURL(tt.base, tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("joinURL(%q, %q) = %q, want error", tt.base, tt.path, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("joinURL(%q, %q) returned error: %v", tt.base, tt.path, err)
			}
			if got != tt.want {
				t.Errorf("joinURL(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.want)
			}
		})
	}
}

// TestRESTAdapter_PathParamDotSegments pins that "." and ".." path parameter
// values are rejected before any request is sent: url.PathEscape keeps them,
// and URL resolution would turn /projects/{id}/issues with id ".." into
// /issues, or /{id}/issues into a path outside the base URL prefix.
func TestRESTAdapter_PathParamDotSegments(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: srv.URL + "/api/v4",
			Tools: map[string]dadl.ToolDef{
				"under_prefix": {Method: testMethodGET, Path: "/projects/{id}/issues", Params: map[string]dadl.ParamDef{
					"id": {Type: schemaTypeString, In: paramInPath, Required: true},
				}},
				"at_root": {Method: testMethodGET, Path: "/{id}/issues", Params: map[string]dadl.ParamDef{
					"id": {Type: schemaTypeString, In: paramInPath, Required: true},
				}},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"under_prefix", "at_root"} {
		for _, v := range []string{".", ".."} {
			result, err := a.Execute(context.Background(), tool, map[string]any{"id": v})
			if err == nil && (result == nil || !result.IsError) {
				t.Errorf("%s with id %q: expected rejection", tool, v)
			}
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("backend received %d requests for dot-segment values, want 0", n)
	}

	// A first segment with a colon must stay on the backend host.
	result, err := a.Execute(context.Background(), "at_root", map[string]any{"id": "evil.example:443"})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("colon value should reach the backend as a path segment: %v", result.Content)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("backend hits = %d, want 1", n)
	}
}
