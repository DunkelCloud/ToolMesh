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
	"log/slog"
	"os"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_LookupTool_Access verifies that the access classification
// from a parsed DADL spec reaches the descriptor returned by LookupTool —
// for both regular tools and composites.
func TestRESTAdapter_LookupTool_Access(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: github
  type: rest
  base_url: https://api.github.com
  tools:
    list_repos:
      method: GET
      path: /user/repos
      access: read
      description: "List repos"
    create_repo:
      method: POST
      path: /user/repos
      access: write
      description: "Create repo"
    no_access_tag:
      method: GET
      path: /things
      description: "Unclassified"
  composites:
    refresh_all:
      description: "Compound write"
      access: admin
      code: "return api.list_repos({});"
`
	spec, err := dadl.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseBytes: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	adapter, err := NewRESTAdapter(spec, credentials.NewEmbeddedStore(), logger, RESTAdapterOptions{})
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}

	cases := []struct {
		toolName string
		want     string
		wantOK   bool
	}{
		{toolName: "list_repos", want: accessRead, wantOK: true},
		{toolName: "create_repo", want: "write", wantOK: true},
		{toolName: "no_access_tag", want: "", wantOK: true},
		{toolName: "refresh_all", want: "admin", wantOK: true},
		{toolName: "unknown_tool", want: "", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.toolName, func(t *testing.T) {
			got, ok := adapter.LookupTool(tc.toolName)
			if ok != tc.wantOK {
				t.Fatalf("LookupTool(%q) ok = %v, want %v", tc.toolName, ok, tc.wantOK)
			}
			if got.Access != tc.want {
				t.Errorf("LookupTool(%q).Access = %q, want %q", tc.toolName, got.Access, tc.want)
			}
		})
	}
}

// TestCompositeBackend_LookupTool_RoutesByPrefix verifies the composite
// backend forwards LookupTool to the named backend whose prefix matches —
// and that the access classification survives the prefix re-application.
func TestCompositeBackend_LookupTool_RoutesByPrefix(t *testing.T) {
	echo := NewEchoBackend()
	c := NewCompositeBackend(map[string]ToolBackend{
		"builtin": echo,
	})

	got, ok := c.LookupTool("builtin_echo")
	if !ok {
		t.Fatal("LookupTool(builtin_echo) returned !ok")
	}
	if got.Name != "builtin_echo" {
		t.Errorf("Name = %q, want %q (public prefix should be re-applied)", got.Name, "builtin_echo")
	}
	if got.Access != accessRead {
		t.Errorf("Access = %q, want %q", got.Access, accessRead)
	}

	if _, ok := c.LookupTool("nonexistent_tool"); ok {
		t.Error("LookupTool(nonexistent_tool) should return false")
	}
}
