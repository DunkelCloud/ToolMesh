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
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_PrefixOverlap pins, end to end, that an entry "github"
// cannot read the token of an entry "github-enterprise": its DADL is
// refused at load, and an adapter loaded before github-enterprise was
// configured refuses the read once it is, without a request leaving.
func TestRESTAdapter_PrefixOverlap(t *testing.T) {
	srv, got := bindingServer(t)
	store := &testCredStore{creds: map[string]string{"github_enterprise_token": "GHE-SECRET"}}
	spec := func() *dadl.Spec {
		return bindingSpec(testBackendNameGitHub, srv.URL, "/ping", "github_enterprise_token")
	}

	owners := dadl.NewCredentialOwners(testBackendNameGitHub, "github-enterprise")
	opts := testRESTOpts
	opts.Scope = &BackendScope{EntryName: testBackendNameGitHub, Owners: owners}
	if _, err := NewRESTAdapter(spec(), store, quietLogger(), opts); err == nil {
		t.Fatal("the DADL of entry github reading github_enterprise_token was loaded")
	}

	owners = dadl.NewCredentialOwners(testBackendNameGitHub)
	opts.Scope = &BackendScope{EntryName: testBackendNameGitHub, Owners: owners}
	a, err := NewRESTAdapter(spec(), store, quietLogger(), opts)
	if err != nil {
		t.Fatalf("before github-enterprise is configured: %v", err)
	}
	owners.Set([]string{testBackendNameGitHub, "github-enterprise"})
	if _, err := a.Execute(context.Background(), bindingTool, map[string]any{}); err == nil {
		t.Error("the read was not refused after github-enterprise was configured")
	}
	if v := got.Load(); v != nil {
		t.Errorf("a request left with Authorization %q", *v)
	}
}
