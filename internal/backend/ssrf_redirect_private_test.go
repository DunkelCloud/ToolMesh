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
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_RedirectToUndeclaredPrivateTarget pins that with
// allow_private_url a redirect cannot steer a tool call to a private
// destination the configuration does not name: base_url may be private, a
// Location header may not point at another private host or port.
func TestRESTAdapter_RedirectToUndeclaredPrivateTarget(t *testing.T) {
	inner := &headerRecorder{}
	innerSrv := httptest.NewServer(inner)
	defer innerSrv.Close()
	_, innerPort, _ := net.SplitHostPort(strings.TrimPrefix(innerSrv.URL, "http://"))

	for _, target := range []string{
		innerSrv.URL + "/latest/meta-data/",        // same host, another port
		"http://localhost:" + innerPort + "/admin", // another loopback name
	} {
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}))
		a := redirectTestAdapter(t, origin.URL, dadl.AuthConfig{})
		result, err := a.Execute(context.Background(), redirectTestTool, nil)
		if err == nil && (result == nil || !result.IsError) {
			t.Errorf("redirect to %s was followed", target)
		}
		origin.Close()
	}
	if hits, _ := inner.snapshot(); hits != 0 {
		t.Errorf("undeclared private target was reached %d times", hits)
	}

	// base_url itself stays reachable on a private address.
	direct := redirectTestAdapter(t, innerSrv.URL, dadl.AuthConfig{})
	if result, err := direct.Execute(context.Background(), redirectTestTool, nil); err != nil || result.IsError {
		t.Fatalf("private base_url must stay reachable: %v %v", err, result)
	}
}

func TestDeclaredDestinations(t *testing.T) {
	spec := &dadl.Spec{Backend: dadl.BackendDef{
		BaseURL: "http://10.0.0.5:8080/api",
		Auth:    dadl.AuthConfig{TokenURL: "https://auth.internal/token"}, //nolint:gosec // test URL, not a credential
		Tools: map[string]dadl.ToolDef{
			"abs":         {Path: "https://Files.Internal./v1/{id}"},
			"rel":         {Path: "/items/{id}"},
			"placeholder": {Path: "https://{region}.example.invalid/x"},
		},
	}}
	got := declaredDestinations(spec)
	for _, want := range []string{"10.0.0.5:8080", "auth.internal:443", "files.internal:443"} {
		if !got[want] {
			t.Errorf("declared destinations %v lack %s", got, want)
		}
	}
	if len(got) != 3 {
		t.Errorf("declared destinations = %v, want exactly 3", got)
	}
}
