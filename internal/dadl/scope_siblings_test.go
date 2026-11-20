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

package dadl

import (
	"slices"
	"testing"
)

// TestSiblingHosts pins which hosts a backend reports as reached through
// the same-domain rule alone: other hosts of the registrable domain of
// base_url that the DADL names and no allowed_hosts: entry confirms. The
// backend's own host, relative paths, tools that cannot be called and
// hosts the entry lists are not among them. On a domain whose customers
// each have a subdomain, another customer's host is one of them.
func TestSiblingHosts(t *testing.T) {
	const (
		tenantBase  = "https://mine.tenants.example"
		otherTenant = "theirs.tenants.example"
		authHost    = "auth.tenants.example"
		filesHost   = "files.tenants.example"
	)
	spec := &Spec{Backend: BackendDef{
		Name:    "tenant-api",
		BaseURL: tenantBase + "/api",
		Auth:    AuthConfig{Type: authTypeOAuth2, TokenURL: "https://" + authHost + "/token"},
		Tools: map[string]ToolDef{
			"relative": {Method: httpMethodGET, Path: "/records/{id}"},
			"own":      {Method: httpMethodGET, Path: tenantBase + "/other"},
			"tenant":   {Method: httpMethodGET, Path: "https://" + otherTenant + "/records/{id}"},
			"tenant2":  {Method: httpMethodGET, Path: "https://THEIRS.tenants.example./more"},
			"files":    {Method: httpMethodGET, Path: "https://" + filesHost + "/f"},
			"hidden":   {Method: httpMethodGET, Path: "https://hidden.tenants.example/x"},
		},
		Health: &HealthConfig{Path: "https://status.tenants.example/health"},
	}}
	reachable := func(tool string) bool { return tool != "hidden" }

	hosts, err := NewHostScope(spec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckScopeOf(spec, nil, hosts, reachable); err != nil {
		t.Fatalf("the DADL stays within the domain and must load: %v", err)
	}
	got := SiblingHosts(spec, hosts, reachable)
	want := []string{authHost, filesHost, "status.tenants.example", otherTenant}
	if !slices.Equal(got, want) {
		t.Errorf("SiblingHosts = %v, want %v", got, want)
	}
	if d := hosts.Domain(); d != "tenants.example" {
		t.Errorf("Domain = %q", d)
	}

	// An allowed_hosts: entry confirms a host; a wildcard confirms all.
	confirmed, err := NewHostScope(spec.Backend.BaseURL, []string{authHost, filesHost})
	if err != nil {
		t.Fatal(err)
	}
	if got := SiblingHosts(spec, confirmed, reachable); !slices.Equal(got, []string{"status.tenants.example", otherTenant}) {
		t.Errorf("with two hosts listed: SiblingHosts = %v", got)
	}
	all, err := NewHostScope(spec.Backend.BaseURL, []string{"*.tenants.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got := SiblingHosts(spec, all, reachable); len(got) != 0 {
		t.Errorf("with the wildcard listed: SiblingHosts = %v, want none", got)
	}

	// Without a registrable domain (an IP address) and without a scope
	// there are no siblings.
	ipSpec := &Spec{Backend: BackendDef{Name: "ip", BaseURL: "http://10.0.0.5:8080"}}
	ipHosts, err := NewHostScope(ipSpec.Backend.BaseURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := SiblingHosts(ipSpec, ipHosts, nil); len(got) != 0 || ipHosts.Domain() != "" {
		t.Errorf("IP base_url: SiblingHosts = %v, Domain = %q", got, ipHosts.Domain())
	}
	if got := SiblingHosts(spec, nil, nil); got != nil {
		t.Errorf("nil scope: SiblingHosts = %v", got)
	}
	var none *HostScope
	if none.Domain() != "" {
		t.Error("nil scope has a domain")
	}
}
