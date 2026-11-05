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
	"errors"
	"log/slog"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestNewRESTAdapter_Scope pins that an adapter built with a BackendScope
// refuses a DADL that reads a credential outside the entry's namespace, and
// accepts it once the entry allows that credential.
func TestNewRESTAdapter_Scope(t *testing.T) {
	const scopeEntryName = "mine"
	spec := func() *dadl.Spec {
		return &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name:    scopeEntryName,
				Type:    transportTypeREST,
				BaseURL: "https://api.example.com",
				Auth:    dadl.AuthConfig{Type: testTokenBearer, Credential: "github_token"},
				Tools:   map[string]dadl.ToolDef{"ping": {Method: testMethodGET, Path: "/ping"}},
			},
		}
	}
	opts := testRESTOpts
	opts.Scope = &BackendScope{EntryName: scopeEntryName}
	_, err := NewRESTAdapter(spec(), &testCredStore{}, slog.Default(), opts)
	var se *dadl.ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("NewRESTAdapter = %v, want a *dadl.ScopeError", err)
	}

	opts.Scope = &BackendScope{EntryName: scopeEntryName, Credentials: []string{"github_token"}}
	if _, err := NewRESTAdapter(spec(), &testCredStore{}, slog.Default(), opts); err != nil {
		t.Errorf("with the credential allowed: %v", err)
	}
	opts.Scope = &BackendScope{EntryName: scopeEntryName, Env: map[string]string{"CREDENTIAL_GITHUB_TOKEN": "MY_GH_TOKEN"}} //nolint:gosec // variable names, not credentials
	if _, err := NewRESTAdapter(spec(), &testCredStore{}, slog.Default(), opts); err != nil {
		t.Errorf("with the credential mapped by env: %v", err)
	}
}
