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
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_LogsSiblingHosts pins that a backend says at load which
// other hosts of its base_url's domain its DADL sends credentials to: a
// tool on another customer's subdomain of a shared domain loads, because
// the binding allows the domain, and the operator must be able to see it.
// A host the entry lists in allowed_hosts is confirmed and not reported.
func TestRESTAdapter_LogsSiblingHosts(t *testing.T) {
	const (
		otherTenant = "theirs.tenants.example"
		siblingCred = "mine_sibling_token" //nolint:gosec // credential name, not a credential
	)
	spec := func() *dadl.Spec {
		s := bindingSpec(scopeEntryName, "https://mine.tenants.example/api", bindingPath, siblingCred)
		s.Backend.Tools["export"] = dadl.ToolDef{Method: testMethodGET, Path: "https://" + otherTenant + "/export"}
		return s
	}
	store := &testCredStore{creds: map[string]string{siblingCred: "sibling-secret"}}
	load := func(allowed []string) string {
		t.Helper()
		var buf bytes.Buffer
		opts := testRESTOpts
		opts.Unbound = false
		opts.Scope = &BackendScope{EntryName: scopeEntryName, AllowedHosts: allowed, Owners: dadl.NewCredentialOwners(scopeEntryName)}
		if _, err := NewRESTAdapter(spec(), store, slog.New(slog.NewTextHandler(&buf, nil)), opts); err != nil {
			t.Fatalf("the backend must load: %v", err)
		}
		return buf.String()
	}

	logs := load(nil)
	for _, want := range []string{"other hosts of its base_url's domain", otherTenant, "domain=tenants.example", "name=" + scopeEntryName} {
		if !strings.Contains(logs, want) {
			t.Errorf("load log lacks %q:\n%s", want, logs)
		}
	}
	if logs := load([]string{otherTenant}); strings.Contains(logs, "other hosts of its base_url's domain") {
		t.Errorf("a host listed in allowed_hosts is still reported:\n%s", logs)
	}
}
