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
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestBearerTransport_OnlyToEndpointOrigin pins that the MCP backend token
// is not sent to the target of a redirect to another host: the transport
// injects it below the redirect logic, so it must check the origin itself.
func TestBearerTransport_OnlyToEndpointOrigin(t *testing.T) {
	var mu sync.Mutex
	got := map[string]string{}
	record := func(name string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got[name] = r.Header.Get("Authorization")
			mu.Unlock()
			_, _ = w.Write([]byte("{}"))
		}
	}
	other := httptest.NewServer(record("other"))
	defer other.Close()
	_, otherPort, _ := net.SplitHostPort(strings.TrimPrefix(other.URL, "http://"))
	otherURL := "http://localhost:" + otherPort + "/landing"

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mcp" {
			http.Redirect(w, r, otherURL, http.StatusFound)
			return
		}
		record("origin")(w, r)
	}))
	defer origin.Close()

	endpoint, _ := url.Parse(origin.URL + "/mcp")
	// Go's default redirect policy on purpose: this test pins that the
	// transport itself withholds the token from another host, whatever the
	// redirect policy lets through (mcpRedirectPolicy refuses such hops).
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &bearerTransport{base: http.DefaultTransport, token: "mcp-backend-token", origin: endpoint}, //nolint:gosec // test fixture token
	}
	for _, path := range []string{"/mcp", "/other-path"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL+path, http.NoBody)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(got["other"], "mcp-backend-token") {
		t.Errorf("the redirect target on another host received %q", got["other"])
	}
	if got["origin"] != "Bearer mcp-backend-token" {
		t.Errorf("a request to the endpoint origin got Authorization %q, want the token", got["origin"])
	}
}

func TestMCPRedirectPolicy(t *testing.T) {
	const mcpTestEndpoint = "https://mcp.example.com/mcp"
	mk := func(raw string) *http.Request {
		r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, raw, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	via := []*http.Request{mk(mcpTestEndpoint)}
	if err := mcpRedirectPolicy(mk("http://mcp.example.com/mcp"), via); err == nil {
		t.Error("https to http redirect was allowed")
	}
	if err := mcpRedirectPolicy(mk("https://mcp.example.com/other"), via); err != nil {
		t.Errorf("same-origin redirect refused: %v", err)
	}
	if err := mcpRedirectPolicy(mk("https://other.example.com/mcp"), via); err == nil {
		t.Error("redirect to another host was allowed")
	}
	if err := mcpRedirectPolicy(mk("https://mcp.example.com/x"), []*http.Request{mk("http://mcp.example.com/mcp")}); err != nil {
		t.Errorf("http to https upgrade on the same host refused: %v", err)
	}
	for _, c := range []struct {
		endpoint, u string
		want        bool
	}{
		{mcpTestEndpoint, "https://MCP.example.com:443/x", true},
		{"http://mcp.example.com/mcp", "https://mcp.example.com/x", true},
		{mcpTestEndpoint, "https://mcp.example.com:8443/x", false},
		{mcpTestEndpoint, "https://other.example.com/x", false},
		{mcpTestEndpoint, "http://mcp.example.com/x", false},
	} {
		e, _ := url.Parse(c.endpoint)
		u, _ := url.Parse(c.u)
		if got := onEndpointOrigin(e, u); got != c.want {
			t.Errorf("onEndpointOrigin(%s, %s) = %v, want %v", c.endpoint, c.u, got, c.want)
		}
	}
}
