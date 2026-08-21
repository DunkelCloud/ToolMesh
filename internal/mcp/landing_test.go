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

package mcp

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/config"
)

const (
	acceptHTML     = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	acceptAny      = "*/*"
	acceptSSE      = "text/event-stream"
	testHost       = "demo.toolmesh.io"
	testHTTPScheme = "http"
	testTLSScheme  = "https"
)

// TestWantsHTML pins the branch condition: only an explicit text/html without a
// competing text/event-stream may divert a GET away from the 405.
func TestWantsHTML(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"browser", acceptHTML, true},
		{"bare html", "text/html", true},
		{"html with q", "text/html;q=0.9", true},
		{"uppercase", "TEXT/HTML", true},
		{"mcp sse client", acceptSSE, false},
		{"sse wins over html", "text/html, " + acceptSSE, false},
		{"html listed after sse", acceptSSE + ", text/html", false},
		{"curl", acceptAny, false},
		{"json client", "application/json", false},
		{"no accept header", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if got := wantsHTML(r); got != tt.want {
				t.Errorf("wantsHTML(%q) = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}

func TestEndpointURL(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		forwarded string
		tls       bool
		want      string
	}{
		{"plain http", "localhost:8080", "", false, "http://localhost:8080/mcp"},
		{"direct tls", testHost, "", true, testTLSScheme + "://" + testHost + "/mcp"},
		{"behind tls proxy", testHost, testTLSScheme, false, testTLSScheme + "://" + testHost + "/mcp"},
		{"proxy reports http", testHost, testHTTPScheme, false, testHTTPScheme + "://" + testHost + "/mcp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
			r.Host = tt.host
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}
			// httptest builds a plaintext request; TLS is opt-in per case.
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := endpointURL(r); got != tt.want {
				t.Errorf("endpointURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestServer_MCP_BrowserGetServesLandingPage covers the reported symptom: a
// visitor pastes the endpoint into the address bar and must not see
// "Method not allowed".
func TestServer_MCP_BrowserGetServesLandingPage(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Host = testHost
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, "This is an MCP endpoint") {
		t.Errorf("body is not the landing page:\n%s", body)
	}
	if !strings.Contains(body, testHTTPScheme+"://"+testHost+"/mcp") {
		t.Errorf("body does not offer the endpoint URL to copy:\n%s", body)
	}
}

// TestServer_MCP_SSEClientStillRejected guards the compatibility promise: an
// MCP client opening a server-initiated stream sees exactly what it saw before.
func TestServer_MCP_SSEClientStillRejected(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	for _, accept := range []string{acceptSSE, "text/html, " + acceptSSE, acceptAny, ""} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Accept %q: status = %d, want %d", accept, w.Code, http.StatusMethodNotAllowed)
		}
	}
}

// TestServer_MCP_LandingPageIsUnauthenticated: the page carries no secrets and
// must render before a visitor has any credentials, which is the whole point.
func TestServer_MCP_LandingPageIsUnauthenticated(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{AuthPassword: "secret"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	body := w.Body.String()
	if strings.Contains(body, "secret") {
		t.Error("landing page leaks the configured password")
	}
	if !strings.Contains(body, "Required.") {
		t.Errorf("body does not state that authentication is required:\n%s", body)
	}
}

func TestServer_MCP_LandingPageWithoutAuth(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if !strings.Contains(w.Body.String(), "None") {
		t.Errorf("body does not state that no auth is configured:\n%s", w.Body.String())
	}
}

// TestServer_MCP_HostHeaderIsEscaped: the host is attacker-controlled and lands
// in the page, so it must go through html/template escaping.
func TestServer_MCP_HostHeaderIsEscaped(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Host = "evil\"><script>alert(1)</script>"
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Error("host header rendered unescaped into the page")
	}
}

// TestServer_MCP_PostUnaffected: a client that sets Accept: text/html on a POST
// still speaks JSON-RPC. The branch is GET-only.
func TestServer_MCP_PostUnaffected(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

// TestServer_Root replaces the bare "404 page not found" a visitor got when
// they trimmed the URL down to the host.
func TestServer_Root(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.Host = testHost
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), testHTTPScheme+"://"+testHost+"/mcp") {
		t.Error("root page does not point at the MCP endpoint")
	}
}

// TestServer_Root_UnknownPathStill404 pins that the "/" catch-all did not turn
// the whole server into a landing page.
func TestServer_Root_UnknownPathStill404(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	for _, path := range []string{"/nope", "/mcp/", "/admin/secret"} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		req.Header.Set("Accept", acceptHTML)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("GET %s: status = %d, want %d", path, w.Code, http.StatusNotFound)
		}
	}
}

// TestServer_Root_Redirect: an operator with somewhere better to send visitors
// points TOOLMESH_ROOT_REDIRECT at it and the site root forwards there.
func TestServer_Root_Redirect(t *testing.T) {
	const target = "https://www.toolmesh.io/en/demo/"
	_, mux := newTestServer(t, &config.Config{RootRedirect: target})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusFound)
	}
	if loc := w.Header().Get("Location"); loc != target {
		t.Errorf("Location = %q, want %q", loc, target)
	}
}

// TestServer_MCP_RedirectDoesNotCoverEndpoint: /mcp keeps the page even when a
// root redirect is configured — a visitor who landed there needs the URL in
// front of them, not a trip to a docs site.
func TestServer_MCP_RedirectDoesNotCoverEndpoint(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{RootRedirect: "https://www.toolmesh.io/en/demo/"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/mcp", nil)
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if !strings.Contains(w.Body.String(), "This is an MCP endpoint") {
		t.Error("/mcp did not serve the landing page")
	}
}

// TestServer_Root_RedirectUnknownPathStill404: the redirect is bound to "/",
// not to the catch-all, so a wrong path must not be forwarded to the target.
func TestServer_Root_RedirectUnknownPathStill404(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{RootRedirect: "https://www.toolmesh.io/en/demo/"})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/nope", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestServer_Root_MethodNotAllowed(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestServer_Health_StillJSON: /health is registered before the catch-all and
// must keep answering JSON, not HTML — monitoring depends on it.
func TestServer_Health_StillJSON(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	req.Header.Set("Accept", acceptHTML)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := strings.TrimSpace(w.Body.String()); got != `{"status":"ok"}` {
		t.Errorf("body = %q, want the health JSON", got)
	}
}
