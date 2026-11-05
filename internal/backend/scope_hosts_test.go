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
	"net/url"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_SchemeDowngrade pins, end to end, that with the
// operator's url https://host a DADL cannot send the bearer token over
// plain http to the same host through an absolute tool path: the DADL is
// refused at load, and an adapter whose load check was bypassed refuses the
// request at run time without it leaving.
func TestRESTAdapter_SchemeDowngrade(t *testing.T) {
	srv, got := bindingServer(t)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	store := &testCredStore{creds: map[string]string{"mine_token": "SECRET"}}
	spec := bindingSpec(scopeEntryName, "https://"+u.Host+"/api", "http://"+u.Host+"/ping", "mine_token")

	opts := testRESTOpts
	opts.Scope = &BackendScope{EntryName: scopeEntryName, Owners: dadl.NewCredentialOwners(scopeEntryName)}
	_, err = NewRESTAdapter(spec, store, quietLogger(), opts)
	var se *dadl.ScopeError
	if !errors.As(err, &se) {
		t.Fatalf("NewRESTAdapter = %v, want a *dadl.ScopeError", err)
	}

	a, err := NewRESTAdapter(spec, store, quietLogger(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := dadl.NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := dadl.NewCredentialScope(scopeEntryName, nil, nil, dadl.NewCredentialOwners(scopeEntryName))
	if err != nil {
		t.Fatal(err)
	}
	a.auth.SetScope(creds, hosts)
	if _, err := a.Execute(context.Background(), bindingTool, map[string]any{}); err == nil {
		t.Error("the http request was not refused")
	}
	if v := got.Load(); v != nil {
		t.Errorf("a request left with Authorization %q", *v)
	}
}
