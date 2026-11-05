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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// bindingTool is the one tool of a bindingSpec.
const bindingTool = "ping"

// bindingSpec is a bearer-auth spec with one tool bindingTool at toolPath.
func bindingSpec(name, baseURL, toolPath, credential string) *dadl.Spec {
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    name,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Auth:    dadl.AuthConfig{Type: testTokenBearer, Credential: credential},
			Tools:   map[string]dadl.ToolDef{bindingTool: {Method: testMethodGET, Path: toolPath}},
		},
	}
}

// bindingServer records the Authorization header of the last request.
func bindingServer(t *testing.T) (*httptest.Server, *atomic.Pointer[string]) {
	t.Helper()
	var got atomic.Pointer[string]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("Authorization")
		got.Store(&v)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestRESTAdapter_EnvKeyCaseRemaps pins that an env: key in another case
// both widens the binding and remaps the read: the backend reads the mapped
// variable, never the real CREDENTIAL_<NAME>, which may belong to another
// backend.
func TestRESTAdapter_EnvKeyCaseRemaps(t *testing.T) {
	t.Setenv("CREDENTIAL_GITHUB_TOKEN", "REAL-GITHUB") //nolint:gosec // test value
	t.Setenv("MINE_MAPPED_TOKEN", "MAPPED-FOR-MINE")   //nolint:gosec // test value
	srv, got := bindingServer(t)
	env := map[string]string{"credential_github_token": "MINE_MAPPED_TOKEN"} //nolint:gosec // variable names, not credentials
	store := credentials.NewRemappingStore(credentials.NewEmbeddedStore(), env)
	opts := testRESTOpts
	opts.Scope = &BackendScope{EntryName: "mine", Env: env}
	a, err := NewRESTAdapter(bindingSpec("mine", srv.URL, "/ping", "github_token"), store, quietLogger(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Execute(context.Background(), bindingTool, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if v := got.Load(); v == nil || *v != "Bearer MAPPED-FOR-MINE" {
		t.Errorf("Authorization = %v, want the mapped variable", v)
	}
}
