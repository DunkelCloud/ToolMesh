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
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func includeTestSpec() *dadl.Spec {
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameTestAPI,
			Type:    transportTypeREST,
			BaseURL: testBaseURLExample,
			Tools: map[string]dadl.ToolDef{
				testToolGetItem: {
					Method:      testMethodGET,
					Path:        testPathItemsByID,
					Description: testDescGetItem,
				},
				testToolListItems: {
					Method:      testMethodGET,
					Path:        testPathItems,
					Description: testDescListItems,
				},
			},
		},
	}
}

// include_tools restricts ListTools to exactly the named subset.
func TestRESTAdapter_IncludeTools_FiltersListTools(t *testing.T) {
	opts := testRESTOpts
	opts.IncludeTools = []string{testToolGetItem}

	adapter, err := NewRESTAdapter(includeTestSpec(), &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != testToolGetItem {
		t.Fatalf("ListTools = %+v, want only %q", tools, testToolGetItem)
	}
}

// A tool excluded by include_tools cannot be invoked even by guessing its name.
func TestRESTAdapter_IncludeTools_BlocksExecute(t *testing.T) {
	opts := testRESTOpts
	opts.IncludeTools = []string{testToolGetItem}

	adapter, err := NewRESTAdapter(includeTestSpec(), &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := adapter.Execute(context.Background(), testToolListItems, map[string]any{}); err == nil {
		t.Fatalf("Execute(%q) succeeded, want not-found error", testToolListItems)
	}
}

// No include_tools restriction exposes the full tool set (default behavior).
func TestRESTAdapter_IncludeTools_NilExposesAll(t *testing.T) {
	adapter, err := NewRESTAdapter(includeTestSpec(), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 2 {
		t.Fatalf("ListTools returned %d tools, want 2 (no restriction)", len(tools))
	}
}

// Unknown include_tools names are dropped; a list of only-unknowns yields an
// empty (non-nil) allow-set that hides everything rather than silently
// exposing the whole API.
func TestRESTAdapter_IncludeTools_UnknownHidesAll(t *testing.T) {
	opts := testRESTOpts
	opts.IncludeTools = []string{"does_not_exist"}

	adapter, err := NewRESTAdapter(includeTestSpec(), &testCredStore{}, slog.Default(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 0 {
		t.Fatalf("ListTools returned %d tools, want 0 (all unknown names dropped)", len(tools))
	}
}
