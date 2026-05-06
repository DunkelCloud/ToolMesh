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

import "testing"

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
