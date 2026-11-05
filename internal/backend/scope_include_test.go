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
	"fmt"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// includeSpec has a tool on the backend's host ("near"), one on a foreign
// host ("far"), and a composite ("wrap") that calls "far".
func includeSpec(baseURL string) *dadl.Spec {
	s := bindingSpec(scopeEntryName, baseURL, "/ping", "mine_token")
	s.Backend.Tools = map[string]dadl.ToolDef{
		"near": {Method: testMethodGET, Path: bindingPath},
		"far":  {Method: testMethodGET, Path: "https://far.elsewhere.example/x"},
	}
	s.Backend.Composites = map[string]dadl.CompositeDef{
		"wrap": {Description: "Wrap", Code: "return await api.far();"},
	}
	return s
}

// TestRESTAdapter_IncludeToolsScope pins that a tool outside include_tools
// needs no binding, because no request for it can leave: Execute refuses
// it, also as an api.* call of an included composite. The health check
// tool runs without Execute and stays checked.
func TestRESTAdapter_IncludeToolsScope(t *testing.T) {
	srv, got := bindingServer(t)
	store := &testCredStore{creds: map[string]string{"mine_token": "SECRET"}}
	scope := &BackendScope{EntryName: scopeEntryName, Owners: dadl.NewCredentialOwners(scopeEntryName)}

	opts := testRESTOpts
	opts.Scope = scope
	if _, err := NewRESTAdapter(includeSpec(srv.URL), store, quietLogger(), opts); err == nil {
		t.Fatal("without include_tools the foreign tool must be refused")
	}

	opts.IncludeTools = []string{"near", "wrap"}
	a, err := NewRESTAdapter(includeSpec(srv.URL), store, quietLogger(), opts)
	if err != nil {
		t.Fatalf("with include_tools [near, wrap]: %v", err)
	}
	// Let child calls through the guard, as the authorization of a
	// permitted caller does, so the call meets Execute.
	a.SetChildGuard(AllowAllChildGuard{})
	if _, err := a.Execute(context.Background(), "far", map[string]any{}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("the excluded tool was not refused as unknown: %v", err)
	}
	res, err := a.Execute(context.Background(), "wrap", map[string]any{})
	if err == nil && (!res.IsError || !strings.Contains(fmt.Sprint(res.Content), "not found")) {
		t.Errorf("the composite's call of the excluded tool was not refused as unknown: %v", res.Content)
	}
	if v := got.Load(); v != nil {
		t.Errorf("a request reached the backend's host with %q", *v)
	}

	health := includeSpec(srv.URL)
	health.Backend.Health = &dadl.HealthConfig{Tool: "far"}
	_, err = NewRESTAdapter(health, store, quietLogger(), opts)
	var se *dadl.ScopeError
	if !errors.As(err, &se) {
		t.Errorf("an excluded health check tool on a foreign host was not checked: %v", err)
	}
}
