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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

const (
	redirectTestSecret     = "s3cr3t-redirect-key" //nolint:gosec // test fixture, not a credential
	redirectTestCredential = "redirect_key"
	redirectTestPath       = "/thing"
	redirectTestHeader     = "PRIVATE-TOKEN"
	redirectTestAuthType   = "apikey"
	redirectTestTool       = "get_thing"
)

// headerRecorder is an upstream that records the headers of the last request
// it received and answers with a small JSON document.
type headerRecorder struct {
	mu     sync.Mutex
	hits   int
	header http.Header
}

func (h *headerRecorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.hits++
	h.header = r.Header.Clone()
	h.mu.Unlock()
	w.Header().Set(testHeaderContentType, testContentTypeJSON)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (h *headerRecorder) snapshot() (int, http.Header) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits, h.header
}

// redirectTestAdapter builds an adapter for baseURL. alsoDeclared names
// further URLs the configuration declares (as absolute tool paths), so that a
// redirect to them may reach a private test server.
func redirectTestAdapter(t *testing.T, baseURL string, auth dadl.AuthConfig, alsoDeclared ...string) *RESTAdapter {
	t.Helper()
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Auth:    auth,
			Tools: map[string]dadl.ToolDef{
				redirectTestTool: {Method: testMethodGET, Path: redirectTestPath},
				"post_thing": {Method: "POST", Path: redirectTestPath, Params: map[string]dadl.ParamDef{
					"name": {Type: schemaTypeString, In: paramInBody},
				}},
			},
		},
	}
	for i, u := range alsoDeclared {
		spec.Backend.Tools[fmt.Sprintf("declared_%d", i)] = dadl.ToolDef{Method: testMethodGET, Path: u}
	}
	creds := &testCredStore{creds: map[string]string{redirectTestCredential: redirectTestSecret}}
	a, err := NewRESTAdapter(spec, creds, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRESTAdapter_RedirectDropsCredentialsAcrossOrigins pins that a backend
// redirect to another origin never carries the injected credential: not in
// the custom auth header, and not in the Referer, which Go fills with the
// previous URL including a query-injected key.
func TestRESTAdapter_RedirectDropsCredentialsAcrossOrigins(t *testing.T) {
	cases := []struct {
		name string
		auth dadl.AuthConfig
	}{
		{"custom header", dadl.AuthConfig{Type: redirectTestAuthType, Credential: redirectTestCredential, HeaderName: redirectTestHeader}},
		{"bearer with custom header", dadl.AuthConfig{Type: testTokenBearer, Credential: redirectTestCredential, HeaderName: "X-Auth"}},
		{"query parameter", dadl.AuthConfig{Type: redirectTestAuthType, Credential: redirectTestCredential, InjectInto: testParamQuery, QueryParam: "api_key"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			other := &headerRecorder{}
			otherSrv := httptest.NewServer(other)
			defer otherSrv.Close()

			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, otherSrv.URL+"/landing", http.StatusFound)
			}))
			defer origin.Close()

			a := redirectTestAdapter(t, origin.URL, tc.auth, otherSrv.URL)
			result, err := a.Execute(context.Background(), redirectTestTool, nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError {
				t.Fatalf("cross-origin GET redirect should still be followed, got error: %v", result.Content)
			}
			hits, h := other.snapshot()
			if hits != 1 {
				t.Fatalf("redirect target hits = %d, want 1", hits)
			}
			for name, values := range h {
				for _, v := range values {
					if strings.Contains(v, redirectTestSecret) {
						t.Errorf("redirect target received the credential in header %s: %q", name, v)
					}
				}
			}
		})
	}
}

func TestRESTAdapter_RedirectSameOriginKeepsCredential(t *testing.T) {
	var mu sync.Mutex
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == redirectTestPath {
			http.Redirect(w, r, "/moved", http.StatusMovedPermanently)
			return
		}
		mu.Lock()
		got = r.Header.Get(redirectTestHeader)
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	a := redirectTestAdapter(t, srv.URL, dadl.AuthConfig{Type: redirectTestAuthType, Credential: redirectTestCredential, HeaderName: redirectTestHeader})
	result, err := a.Execute(context.Background(), redirectTestTool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("same-origin redirect failed: %v", result.Content)
	}
	mu.Lock()
	defer mu.Unlock()
	if got != redirectTestSecret {
		t.Errorf("same-origin redirect target got PRIVATE-TOKEN %q, want the credential", got)
	}
}

func TestRESTAdapter_RedirectRefusesBodyToOtherOrigin(t *testing.T) {
	other := &headerRecorder{}
	otherSrv := httptest.NewServer(other)
	defer otherSrv.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherSrv.URL+"/landing", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()

	a := redirectTestAdapter(t, origin.URL, dadl.AuthConfig{Type: redirectTestAuthType, Credential: redirectTestCredential, HeaderName: redirectTestHeader}, otherSrv.URL)
	result, err := a.Execute(context.Background(), "post_thing", map[string]any{"name": "x"})
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("expected a 307 with body to another origin to be refused")
	}
	if hits, _ := other.snapshot(); hits != 0 {
		t.Errorf("redirect target was hit %d times, want 0", hits)
	}
}

func TestBackendRedirectChecker(t *testing.T) {
	mk := func(method, rawURL string) *http.Request {
		r, err := http.NewRequestWithContext(context.Background(), method, rawURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// allowPrivate=true keeps DNS out of the test; the origin rules apply anyway.
	check := newBackendRedirectChecker(true)

	t.Run("https to http is refused, same host", func(t *testing.T) {
		via := []*http.Request{mk(http.MethodGet, "https://api.example.com/a?key=1")}
		err := check(mk(http.MethodGet, "http://api.example.com/b"), via)
		if err == nil {
			t.Fatal("expected downgrade to be refused")
		}
		if strings.Contains(err.Error(), "key=1") {
			t.Errorf("error leaks the original query: %v", err)
		}
	})

	t.Run("http to https upgrade on the same host keeps headers", func(t *testing.T) {
		via := []*http.Request{mk(http.MethodGet, "http://api.example.com/a")}
		next := mk(http.MethodGet, "https://api.example.com/a")
		next.Header.Set("X-Api-Key", "k")
		if err := check(next, via); err != nil {
			t.Fatal(err)
		}
		if next.Header.Get("X-Api-Key") != "k" {
			t.Error("upgrade on the same host must keep the credential header")
		}
	})

	t.Run("other host strips all but safe headers", func(t *testing.T) {
		via := []*http.Request{mk(http.MethodGet, "https://api.example.com/a")}
		next := mk(http.MethodGet, "https://cdn.example.net/file")
		next.Header.Set("X-Api-Key", "k")
		next.Header.Set("Authorization", "Bearer k")
		next.Header.Set("Referer", "https://api.example.com/a?api_key=k")
		next.Header.Set("Accept", "application/json")
		if err := check(next, via); err != nil {
			t.Fatal(err)
		}
		for _, h := range []string{"X-Api-Key", "Authorization", "Referer"} {
			if next.Header.Get(h) != "" {
				t.Errorf("header %s survived a cross-origin redirect", h)
			}
		}
		if next.Header.Get("Accept") == "" {
			t.Error("Accept should survive a cross-origin redirect")
		}
	})

	t.Run("other port is another origin", func(t *testing.T) {
		via := []*http.Request{mk(http.MethodGet, "https://api.example.com/a")}
		next := mk(http.MethodGet, "https://api.example.com:8443/a")
		next.Header.Set("X-Api-Key", "k")
		if err := check(next, via); err != nil {
			t.Fatal(err)
		}
		if next.Header.Get("X-Api-Key") != "" {
			t.Error("credential header survived a redirect to another port")
		}
	})
}

// TestRESTAdapter_TokenRequestUsesSSRFTransport pins that OAuth2 token
// requests go through the adapter's SSRF-safe transport: with
// allow_private_url off, a token_url on a loopback address is not contacted.
func TestRESTAdapter_TokenRequestUsesSSRFTransport(t *testing.T) {
	var hits int32
	var mu sync.Mutex
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
	}))
	defer tokenSrv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI,
			Type: transportTypeREST,
			// A public IP literal passes base_url validation without DNS.
			BaseURL: "https://93.184.215.14",
			Auth: dadl.AuthConfig{
				Type:                   "oauth2",
				TokenURL:               tokenSrv.URL + "/token",
				ClientIDCredential:     "cid",
				ClientSecretCredential: redirectTestCredential,
			},
			Tools: map[string]dadl.ToolDef{
				redirectTestTool: {Method: testMethodGET, Path: redirectTestPath},
			},
		},
	}
	creds := &testCredStore{creds: map[string]string{"cid": "id", redirectTestCredential: redirectTestSecret}}
	a, err := NewRESTAdapter(spec, creds, slog.Default(), RESTAdapterOptions{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), redirectTestTool, nil)
	if err == nil && (result == nil || !result.IsError) {
		t.Fatal("expected the call to fail: the token endpoint is on a private address")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("token endpoint on a private address was contacted %d times", hits)
	}
}

// TestRESTAdapter_RedirectBackToOriginStaysStripped pins that a chain that
// leaves the origin and returns (A -> B -> A) does not get the credential
// back on the path the third party chose.
func TestRESTAdapter_RedirectBackToOriginStaysStripped(t *testing.T) {
	final := &headerRecorder{}
	var originSrv, otherSrv *httptest.Server
	originSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == redirectTestPath {
			http.Redirect(w, r, otherSrv.URL+"/hop", http.StatusFound)
			return
		}
		final.ServeHTTP(w, r)
	}))
	defer originSrv.Close()
	otherSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, originSrv.URL+"/chosen-by-third-party?op=delete", http.StatusFound)
	}))
	defer otherSrv.Close()

	a := redirectTestAdapter(t, originSrv.URL,
		dadl.AuthConfig{Type: redirectTestAuthType, Credential: redirectTestCredential, HeaderName: redirectTestHeader},
		otherSrv.URL)
	result, err := a.Execute(context.Background(), redirectTestTool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("chain refused: %v", result.Content)
	}
	hits, h := final.snapshot()
	if hits != 1 {
		t.Fatalf("return hop hits = %d, want 1", hits)
	}
	if got := h.Get(redirectTestHeader); got != "" {
		t.Errorf("credential re-attached on the return hop: %q", got)
	}
}
