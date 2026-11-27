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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// cimdTestClientID is the client_id of the test client. The certificate
	// of httptest is issued for example.com, so a document host can be
	// reached under that name with certificate verification on.
	cimdTestClientID = "https://example.com/oauth/client.json"
	cimdTestHostName = "example.com"
	cimdTestName     = "Example Client"
	cimdTestLoopback = "http://localhost/callback"

	// cimdTestOtherHost is a host no test document is on.
	cimdTestOtherHost = "other.example"
	// cimdTestKeyMethod is a client authentication method this server does
	// not offer.
	cimdTestKeyMethod = "private_key_jwt"

	// cimdTestMarker stands for content of a response that must never reach
	// the requester.
	cimdTestMarker = "MARKER-FROM-THE-RESPONSE"

	testHeaderContentType  = "Content-Type"
	testHeaderCacheControl = "Cache-Control"
)

// cimdTestDocument returns a valid metadata document for clientID with the
// given fields set, or removed when their value is nil.
func cimdTestDocument(clientID string, overrides map[string]any) []byte {
	doc := map[string]any{
		oauthClientID:           clientID,
		cimdFieldClientName:     cimdTestName,
		cimdFieldRedirectURIs:   []string{testLoginRedirect, cimdTestLoopback},
		cimdFieldGrantTypes:     []string{oauthGrantAuthCode, oauthRefreshToken},
		cimdFieldResponseTypes:  []string{oauthCode},
		cimdFieldAuthMethod:     tokenAuthMethodNone,
		"client_uri":            "https://example.com",
		"something_unknown_yet": cimdTestMarker,
	}
	for k, v := range overrides {
		if v == nil {
			delete(doc, k)
			continue
		}
		doc[k] = v
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return raw
}

// cimdTestHost is a server that publishes metadata documents, reached under
// any host name through the client it hands out.
type cimdTestHost struct {
	srv *httptest.Server

	mu      sync.Mutex
	hits    map[string]int
	handler http.HandlerFunc
}

// newCIMDTestHost starts a TLS server that answers every request with
// handler.
func newCIMDTestHost(t *testing.T, handler http.HandlerFunc) *cimdTestHost {
	t.Helper()
	h := &cimdTestHost{hits: map[string]int{}, handler: handler}
	h.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.hits[r.URL.Path]++
		serve := h.handler
		h.mu.Unlock()
		serve(w, r)
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// serveDocument answers every request with body as JSON.
func serveDocument(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, mimeJSON)
		_, _ = w.Write(body)
	}
}

// setHandler replaces what the host serves.
func (h *cimdTestHost) setHandler(handler http.HandlerFunc) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handler = handler
}

// requests returns how many requests the host received, for all paths or
// for the given one.
func (h *cimdTestHost) requests(path ...string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for p, c := range h.hits {
		if len(path) == 0 || p == path[0] {
			n += c
		}
	}
	return n
}

// client returns the fetch client of the server under test, with the one
// change that every connection goes to this host, whatever name the URL
// has. Redirects, timeout and certificate verification are as in production.
func (h *cimdTestHost) client() *http.Client {
	tr := h.srv.Client().Transport.(*http.Transport).Clone()
	addr := h.srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.DisableKeepAlives = true
	return cimdHTTPClient(tr)
}

func TestClientIDURLError(t *testing.T) {
	const issuer = "https://toolmesh.example.org/"
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"document url", "https://claude.ai/oauth/claude-code-client-metadata", true},
		{"with port", "https://client.example:8443/client.json", true},
		{"deep path", "https://client.example/a/b/c.json", true},
		{"percent-encoded path", "https://client.example/a%20b.json", true},
		{"no path", "https://client.example", false},
		{"root path", "https://client.example/", false},
		{"dot segment", "https://client.example/a/./client.json", false},
		{"dot-dot segment", "https://client.example/a/../client.json", false},
		{"encoded dot-dot segment", "https://client.example/a/%2e%2e/client.json", false},
		{"fragment", "https://client.example/client.json#x", false},
		{"empty fragment", "https://client.example/client.json#", false},
		{"query", "https://client.example/client.json?x=1", false},
		{"empty query", "https://client.example/client.json?", false},
		{"user information", "https://user@client.example/client.json", false},
		{"user and password", "https://user:pw@client.example/client.json", false},
		{"host behind user information", "https://claude.ai@client.example/client.json", false},
		{"no host", "https:///client.json", false},
		{"space", "https://client.example/a b.json", false},
		{"control character", "https://client.example/a\tb.json", false},
		{"backslash", `https://client.example\client.json`, false},
		{"non-ascii host", "https://cli\xc3\xa9nt.example/client.json", false},
		{"percent-encoded non-ascii host", "https://claude.ai%E3%80%82client.example/client.json", false},
		{"ipv6 zone", "https://[fe80::1%25eth0]/client.json", false},
		{"own host", "https://toolmesh.example.org/blobs/abc", false},
		{"own host, other case and port", "https://ToolMesh.Example.Org:8443/blobs/abc", false},
		{"own host, trailing dot", "https://toolmesh.example.org./blobs/abc", false},
		{"too long", "https://client.example/" + strings.Repeat("a", maxClientIDURLBytes), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := clientIDURLError(tc.raw, issuer)
			if tc.ok && msg != "" {
				t.Errorf("clientIDURLError(%q) = %q, want it accepted", tc.raw, msg)
			}
			if !tc.ok && msg == "" {
				t.Errorf("clientIDURLError(%q) accepted the URL", tc.raw)
			}
		})
	}
}

func TestIsClientIDURL(t *testing.T) {
	for id, want := range map[string]bool{
		"https://client.example/client.json": true,
		"http://client.example/client.json":  false, // never fetched: an unknown client
		"HTTPS://client.example/client.json": false,
		generateID():                         false, // what /register hands out
		"":                                   false,
	} {
		if got := isClientIDURL(id); got != want {
			t.Errorf("isClientIDURL(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestHostListed pins how the host allowlists match, the one of redirect
// URIs and the one of metadata documents alike: by the name as it is
// written, case aside.
func TestHostListed(t *testing.T) {
	allowed := []string{cimdTestHostName, "*.example.org"}
	for host, want := range map[string]bool{
		cimdTestHostName:           true,
		"EXAMPLE.com":              true,
		"sub.example.com":          false, // the entry names the host, not its subdomains
		"example.com.":             false, // another origin to a browser
		"notexample.com":           false,
		"example.com.evil.example": false,
		"a.example.org":            true,
		"a.b.example.org":          true,
		"example.org":              false, // the wildcard covers subdomains only
		"badexample.org":           false,
		"a.example.org.":           false,
		"":                         false,
	} {
		if got := hostListed(host, allowed); got != want {
			t.Errorf("hostListed(%q) = %v, want %v", host, got, want)
		}
	}
	// Through the two callers, with whole URLs.
	if redirectHostAllowed("https://example.com./cb", allowed) || !redirectHostAllowed("https://example.com:8443/cb", allowed) {
		t.Error("redirectHostAllowed: a trailing dot must not pass, a port must not matter")
	}
	if clientIDHostAllowed("https://example.com./client.json", allowed) || !clientIDHostAllowed("https://example.com:8443/client.json", allowed) {
		t.Error("clientIDHostAllowed: a trailing dot must not pass, a port must not matter")
	}
	if !clientIDHostAllowed(cimdTestClientID, nil) {
		t.Error("clientIDHostAllowed: without a list every host is allowed")
	}
}

func TestRedirectListed(t *testing.T) {
	listed := []string{
		"https://client.example/cb",
		"http://localhost/callback",
		"http://127.0.0.1:33418/",
		"http://[::1]/cb?x=1",
		"http://localhost/with#fragment",
	}
	cases := []struct {
		redirect string
		want     bool
	}{
		{"https://client.example/cb", true},
		{"https://client.example/cb/", false},
		{"https://client.example:443/cb", false}, // compared as strings
		{"https://client.example/CB", false},
		{"https://other.example/cb", false},
		// Loopback: any port, nothing else differs.
		{"http://localhost/callback", true},
		{"http://localhost:53124/callback", true},
		{"http://localhost:53124/other", false},
		{"http://localhost:53124/callback?x=1", false},
		{"http://127.0.0.1:53124/", true},
		{"http://127.0.0.1:53124", false},
		{"http://127.0.0.1:53124/callback", false}, // listed for localhost only
		{"http://[::1]:9000/cb?x=1", true},
		{"http://[::1]:9000/cb", false},
		{"http://user@localhost:53124/callback", false},
		{"http://localhost:53124/with", false}, // the entry with a fragment is no entry
		// Not loopback: the port is part of the string.
		{"http://localhost.client.example:53124/callback", false},
		{"https://localhost:53124/callback", false},
	}
	for _, tc := range cases {
		if got := redirectListed(listed, tc.redirect); got != tc.want {
			t.Errorf("redirectListed(%q) = %v, want %v", tc.redirect, got, tc.want)
		}
	}
}

func TestParseClientMetadata(t *testing.T) {
	cases := []struct {
		name string
		body []byte
		kind cimdErrorKind // of the error; -1 for a document that is accepted
	}{
		{"valid", cimdTestDocument(cimdTestClientID, nil), -1},
		{"only what is required", []byte(`{"client_id":"` + cimdTestClientID + `","client_name":"x","redirect_uris":["https://example.com/cb"]}`), -1},
		{"method list with none", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethod: nil, cimdFieldAuthMethods: []string{cimdTestKeyMethod, tokenAuthMethodNone}}), -1},
		{"null fields", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientSecret: json.RawMessage(jsonTypeNull), cimdFieldGrantTypes: json.RawMessage(jsonTypeNull)}), -1},
		{"jwks for a method this server does not use", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldJWKSURI: "https://example.com/jwks.json"}), -1},

		{"not json", []byte("<html>" + cimdTestMarker + "</html>"), cimdUnavailable},
		{"empty", nil, cimdUnavailable},
		{"json null", []byte(jsonTypeNull), cimdUnavailable},
		{"array", []byte(`[{"client_id":"` + cimdTestClientID + `"}]`), cimdUnavailable},
		{"trailing data", append(cimdTestDocument(cimdTestClientID, nil), []byte("{}")...), cimdUnavailable},
		{"no client_id", cimdTestDocument(cimdTestClientID, map[string]any{oauthClientID: nil}), cimdUnavailable},
		{"client_id of another url", cimdTestDocument("https://example.com/oauth/other.json", nil), cimdUnavailable},
		{"client_id differs in case", cimdTestDocument(strings.ToUpper(cimdTestClientID), nil), cimdUnavailable},
		{"client_id with a trailing slash", cimdTestDocument(cimdTestClientID+"/", nil), cimdUnavailable},
		{"client_id is no string", cimdTestDocument(cimdTestClientID, map[string]any{oauthClientID: 7}), cimdUnavailable},

		{"no client_name", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: nil}), cimdInvalid},
		{"blank client_name", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: "  "}), cimdInvalid},
		{"client_name is no string", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: []string{"x"}}), cimdInvalid},
		{"long client_name", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: strings.Repeat("n", maxClientNameBytes+1)}), cimdInvalid},
		{"no redirect_uris", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldRedirectURIs: nil}), cimdInvalid},
		{"empty redirect_uris", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldRedirectURIs: []string{}}), cimdInvalid},
		{"redirect_uris is a string", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldRedirectURIs: testLoginRedirect}), cimdInvalid},
		{"client_secret", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientSecret: "s"}), cimdInvalid},
		{"client_secret_expires_at", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldSecretExpiresAt: 0}), cimdInvalid},
		{"jwks and jwks_uri", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldJWKS: map[string]any{"keys": []any{}}, cimdFieldJWKSURI: "https://example.com/jwks.json"}), cimdInvalid},
		{"a key method only", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethod: cimdTestKeyMethod}), cimdInvalid},
		{"shared secret method", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethod: "client_secret_basic"}), cimdInvalid},
		{"shared secret method in the list", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethods: []string{tokenAuthMethodNone, "client_secret_post"}}), cimdInvalid},
		{"method is no string", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethod: 1}), cimdInvalid},
		{"grant_types without authorization_code", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldGrantTypes: []string{"client_credentials"}}), cimdInvalid},
		{"response_types without code", cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldResponseTypes: []string{"token"}}), cimdInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := parseClientMetadata(cimdTestClientID, tc.body)
			if tc.kind < 0 {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if metadata.clientName == "" || len(metadata.redirectURIs) == 0 {
					t.Errorf("metadata = %+v, want name and redirect URIs", metadata)
				}
				return
			}
			var ce *cimdError
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want a cimdError", err)
			}
			if ce.kind != tc.kind {
				t.Errorf("kind = %d (%s), want %d", ce.kind, ce.reason, tc.kind)
			}
			if strings.Contains(ce.Error(), cimdTestMarker) {
				t.Errorf("the error repeats content of the response: %s", ce.Error())
			}
		})
	}
}

func TestCIMDLifetime(t *testing.T) {
	cases := []struct {
		name         string
		cacheControl []string
		age          string
		want         time.Duration
	}{
		{"no header", nil, "", cimdCacheMin},
		{"max-age within the bounds", []string{"public, max-age=3600"}, "", time.Hour},
		{"max-age below the minimum", []string{"max-age=30"}, "", cimdCacheMin},
		{"max-age above the maximum", []string{"max-age=31536000"}, "", cimdCacheMax},
		{"max-age beyond int range of durations", []string{"max-age=9223372036854775807"}, "", cimdCacheMax},
		{"age is subtracted", []string{"max-age=3600"}, "1800", 30 * time.Minute},
		{"age beyond max-age", []string{"max-age=3600"}, "7200", cimdCacheMin},
		{"not to be stored", []string{cacheDirectiveNoStore}, "", cimdCacheMin},
		{"no-store wins over max-age", []string{"max-age=3600, no-store"}, "", cimdCacheMin},
		{"no-cache, as one real client sends it", []string{"no-store,no-cache,max-age=0"}, "", cimdCacheMin},
		{"upper case and a second header line", []string{"Public", "MAX-AGE=7200"}, "", 2 * time.Hour},
		{"quoted value", []string{`max-age="7200"`}, "", 2 * time.Hour},
		{"negative max-age", []string{"max-age=-5"}, "", cimdCacheMin},
		{"garbage", []string{"max-age=soon"}, "", cimdCacheMin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tc.cacheControl {
				h.Add(testHeaderCacheControl, v)
			}
			if tc.age != "" {
				h.Set("Age", tc.age)
			}
			if got := cimdLifetime(h); got != tc.want {
				t.Errorf("cimdLifetime = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCIMDFetcher_RequestIsPlain pins what a fetch sends: a GET that asks
// for JSON, names the fetcher without a version, and carries nothing else of
// the request that caused it.
func TestCIMDFetcher_RequestIsPlain(t *testing.T) {
	var got *http.Request
	host := newCIMDTestHost(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(context.Background())
		serveDocument(cimdTestDocument(cimdTestClientID, nil))(w, r)
	})
	f := newCIMDFetcher(host.client())
	if _, err := f.fetch(context.Background(), cimdTestClientID); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Method != http.MethodGet || got.URL.Path != "/oauth/client.json" || got.Host != cimdTestHostName {
		t.Errorf("request = %s %s on host %q", got.Method, got.URL.Path, got.Host)
	}
	if got.Header.Get("Accept") != mimeJSON || got.Header.Get("User-Agent") != cimdUserAgent {
		t.Errorf("Accept %q, User-Agent %q", got.Header.Get("Accept"), got.Header.Get("User-Agent"))
	}
	for _, name := range []string{"Cookie", "Authorization", "Referer", "Origin"} {
		if v := got.Header.Get(name); v != "" {
			t.Errorf("the fetch sent %s: %q", name, v)
		}
	}
}

// TestCIMDFetcher_CachesForTheLifetime pins that a document is fetched once
// for its lifetime, that the response's max-age sets the lifetime, and that
// a response asking not to be cached is still used for the minimum.
func TestCIMDFetcher_CachesForTheLifetime(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cacheControl string
		lifetime     time.Duration
	}{
		{"max-age", "public, max-age=3600", time.Hour},
		{"not to be stored", "no-store,no-cache,max-age=0", cimdCacheMin},
		{"nothing said", "", cimdCacheMin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := newCIMDTestHost(t, func(w http.ResponseWriter, r *http.Request) {
				if tc.cacheControl != "" {
					w.Header().Set(testHeaderCacheControl, tc.cacheControl)
				}
				serveDocument(cimdTestDocument(cimdTestClientID, nil))(w, r)
			})
			f := newCIMDFetcher(host.client())
			now := time.Now()
			f.now = func() time.Time { return now }

			fetch := func() {
				t.Helper()
				if _, err := f.fetch(context.Background(), cimdTestClientID); err != nil {
					t.Fatalf("fetch: %v", err)
				}
			}
			fetch()
			fetch()
			if _, ok := f.cached(cimdTestClientID); !ok {
				t.Error("cached() does not see the document")
			}
			now = now.Add(tc.lifetime - time.Second)
			fetch()
			if n := host.requests(); n != 1 {
				t.Fatalf("%d requests within the lifetime, want 1", n)
			}
			now = now.Add(2 * time.Second)
			if _, ok := f.cached(cimdTestClientID); ok {
				t.Error("cached() returns a document that has run out")
			}
			fetch()
			if n := host.requests(); n != 2 {
				t.Errorf("%d requests after the lifetime, want 2", n)
			}
		})
	}
}

// TestCIMDFetcher_FailuresAreNotRemembered pins that neither a failed fetch
// nor a refused document is cached: the next request fetches again.
func TestCIMDFetcher_FailuresAreNotRemembered(t *testing.T) {
	host := newCIMDTestHost(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	})
	f := newCIMDFetcher(host.client())
	if _, err := f.fetch(context.Background(), cimdTestClientID); err == nil {
		t.Fatal("a 404 was accepted")
	}
	host.setHandler(serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: nil})))
	if _, err := f.fetch(context.Background(), cimdTestClientID); err == nil {
		t.Fatal("a document without client_name was accepted")
	}
	host.setHandler(serveDocument(cimdTestDocument(cimdTestClientID, nil)))
	if _, err := f.fetch(context.Background(), cimdTestClientID); err != nil {
		t.Fatalf("the document was refused after it became valid: %v", err)
	}
	if n := host.requests(); n != 3 {
		t.Errorf("%d requests, want 3", n)
	}
}

// TestCIMDFetcher_ResponsesThatAreNoDocument covers what a host can answer
// instead of a document. None of it is used, and nothing of it is repeated.
func TestCIMDFetcher_ResponsesThatAreNoDocument(t *testing.T) {
	valid := cimdTestDocument(cimdTestClientID, nil)
	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"status 404 with a valid body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, mimeJSON)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write(valid)
		}},
		{"status 203", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, mimeJSON)
			w.WriteHeader(http.StatusNonAuthoritativeInfo)
			_, _ = w.Write(valid)
		}},
		{"redirect to a valid document", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/elsewhere.json" {
				serveDocument(valid)(w, r)
				return
			}
			http.Redirect(w, r, "/elsewhere.json", http.StatusFound)
		}},
		{"redirect to http", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://example.com/elsewhere.json", http.StatusMovedPermanently)
		}},
		{"served as text", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, "text/plain; charset=utf-8")
			_, _ = w.Write(valid)
		}},
		{"served as html", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, "text/html")
			_, _ = w.Write(valid)
		}},
		{"no content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header()[testHeaderContentType] = nil
			_, _ = w.Write(valid)
		}},
		{"longer than the limit, length stated", serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{"padding": strings.Repeat("p", maxCIMDDocumentBytes)}))},
		{"longer than the limit, length not stated", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, mimeJSON)
			w.(http.Flusher).Flush() // chunked: no Content-Length
			_, _ = w.Write(cimdTestDocument(cimdTestClientID, map[string]any{"padding": strings.Repeat("p", maxCIMDDocumentBytes)}))
		}},
		{"valid document with white space beyond the limit, length not stated", func(w http.ResponseWriter, _ *http.Request) {
			// What is read up to the limit is a complete document; only
			// the count of bytes says that there is more.
			w.Header().Set(testHeaderContentType, mimeJSON)
			w.(http.Flusher).Flush()
			_, _ = w.Write(valid)
			_, _ = w.Write([]byte(strings.Repeat(" ", maxCIMDDocumentBytes)))
		}},
		{"a page instead of a document", serveDocument([]byte("<html>" + cimdTestMarker + "</html>"))},
		{"document of another client", serveDocument(cimdTestDocument("https://example.com/oauth/other.json", nil))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := newCIMDTestHost(t, tc.handler)
			f := newCIMDFetcher(host.client())
			_, err := f.fetch(context.Background(), cimdTestClientID)
			var ce *cimdError
			if !errors.As(err, &ce) || ce.kind != cimdUnavailable {
				t.Fatalf("err = %v, want a cimdError of kind unavailable", err)
			}
			if strings.Contains(ce.Error(), cimdTestMarker) {
				t.Errorf("the error repeats content of the response: %s", ce.Error())
			}
			if n := host.requests("/elsewhere.json"); n != 0 {
				t.Errorf("a redirect was followed (%d requests)", n)
			}
			if _, ok := f.cached(cimdTestClientID); ok {
				t.Error("the response was cached")
			}
		})
	}
}

// TestCIMDFetcher_AcceptsJSONSubtypes pins the media types a document may
// be served with.
func TestCIMDFetcher_AcceptsJSONSubtypes(t *testing.T) {
	for _, ct := range []string{mimeJSON, "application/json; charset=utf-8", "Application/JSON", "application/cimd+json"} {
		host := newCIMDTestHost(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(testHeaderContentType, ct)
			_, _ = w.Write(cimdTestDocument(cimdTestClientID, nil))
		})
		if _, err := newCIMDFetcher(host.client()).fetch(context.Background(), cimdTestClientID); err != nil {
			t.Errorf("Content-Type %q: %v", ct, err)
		}
	}
}

// TestCIMDFetcher_DocumentAtTheLimit pins that the limit itself is allowed.
func TestCIMDFetcher_DocumentAtTheLimit(t *testing.T) {
	doc := cimdTestDocument(cimdTestClientID, nil)
	doc = append(doc, []byte(strings.Repeat(" ", maxCIMDDocumentBytes-len(doc)))...)
	host := newCIMDTestHost(t, serveDocument(doc))
	if _, err := newCIMDFetcher(host.client()).fetch(context.Background(), cimdTestClientID); err != nil {
		t.Errorf("a document of exactly %d bytes was refused: %v", maxCIMDDocumentBytes, err)
	}
}

// TestCIMDFetcher_StopsReadingAtTheLimit pins that a host cannot make the
// server take in more than the limit: the fetch ends once the limit is
// passed, long before the host is done sending.
func TestCIMDFetcher_StopsReadingAtTheLimit(t *testing.T) {
	const total = 64 << 20
	var sent atomic.Int64
	done := make(chan struct{})
	host := newCIMDTestHost(t, func(w http.ResponseWriter, _ *http.Request) {
		defer close(done)
		w.Header().Set(testHeaderContentType, mimeJSON)
		chunk := []byte(strings.Repeat(" ", 64<<10))
		for sent.Load() < total {
			n, err := w.Write(chunk)
			sent.Add(int64(n))
			if err != nil {
				return
			}
		}
	})
	f := newCIMDFetcher(host.client())
	_, err := f.fetch(context.Background(), cimdTestClientID)
	var ce *cimdError
	if !errors.As(err, &ce) || ce.kind != cimdUnavailable {
		t.Fatalf("err = %v, want a cimdError of kind unavailable", err)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the host is still sending")
	}
	// What the host got rid of went into buffers of the connection, not
	// into the fetcher.
	if got := sent.Load(); got > total/8 {
		t.Errorf("the host sent %d bytes before the fetch ended, want far less than %d", got, total)
	}
}

// TestCIMDFetcher_Timeout pins that a host that does not answer costs the
// timeout and no more.
func TestCIMDFetcher_Timeout(t *testing.T) {
	release := make(chan struct{})
	host := newCIMDTestHost(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)

	client := host.client()
	client.Timeout = 100 * time.Millisecond
	f := newCIMDFetcher(client)

	start := time.Now()
	_, err := f.fetch(context.Background(), cimdTestClientID)
	var ce *cimdError
	if !errors.As(err, &ce) || ce.kind != cimdUnavailable {
		t.Fatalf("err = %v, want a cimdError of kind unavailable", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("the fetch took %s", elapsed)
	}
	if strings.Contains(ce.Error(), cimdTestClientID) {
		t.Errorf("the error repeats the URL: %s", ce.Error())
	}
}

// blockingTransport holds every request until it is released and counts
// them.
type blockingTransport struct {
	started atomic.Int32
	release chan struct{}
	body    func(*http.Request) []byte
}

func (b *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b.started.Add(1)
	select {
	case <-b.release:
	case <-req.Context().Done():
		return nil, req.Context().Err()
	}
	rec := httptest.NewRecorder()
	rec.Header().Set(testHeaderContentType, mimeJSON)
	_, _ = rec.Write(b.body(req))
	return rec.Result(), nil
}

// waitFor polls until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestCIMDFetcher_OneFetchPerURL pins that requests for a URL that is being
// fetched wait for that fetch instead of starting their own.
func TestCIMDFetcher_OneFetchPerURL(t *testing.T) {
	tr := &blockingTransport{release: make(chan struct{}), body: func(*http.Request) []byte {
		return cimdTestDocument(cimdTestClientID, nil)
	}}
	f := newCIMDFetcher(cimdHTTPClient(tr))

	const callers = 20
	errs := make(chan error, callers)
	for range callers {
		go func() {
			_, err := f.fetch(context.Background(), cimdTestClientID)
			errs <- err
		}()
	}
	waitFor(t, "the fetch to start", func() bool { return tr.started.Load() >= 1 })
	// Give the other callers time to arrive; none may start a second fetch.
	time.Sleep(50 * time.Millisecond)
	close(tr.release)
	for range callers {
		if err := <-errs; err != nil {
			t.Errorf("fetch: %v", err)
		}
	}
	if n := tr.started.Load(); n != 1 {
		t.Errorf("%d fetches for one URL, want 1", n)
	}
}

// TestCIMDFetcher_FetchOutlivesTheRequestThatStartedIt pins that a fetch
// others wait for does not end when the request that started it goes away.
func TestCIMDFetcher_FetchOutlivesTheRequestThatStartedIt(t *testing.T) {
	tr := &blockingTransport{release: make(chan struct{}), body: func(*http.Request) []byte {
		return cimdTestDocument(cimdTestClientID, nil)
	}}
	f := newCIMDFetcher(cimdHTTPClient(tr))

	ctx, cancel := context.WithCancel(context.Background())
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := f.fetch(ctx, cimdTestClientID)
		first <- err
	}()
	waitFor(t, "the fetch to start", func() bool { return tr.started.Load() == 1 })
	go func() {
		_, err := f.fetch(context.Background(), cimdTestClientID)
		second <- err
	}()
	time.Sleep(50 * time.Millisecond) // the second request joins the fetch
	cancel()
	time.Sleep(50 * time.Millisecond)
	close(tr.release)

	if err := <-second; err != nil {
		t.Errorf("the request that waited got no document: %v", err)
	}
	<-first
	if _, ok := f.cached(cimdTestClientID); !ok {
		t.Error("the document was not kept")
	}
}

// TestCIMDFetcher_BoundsFetchesInFlight pins that no more than
// maxCIMDFetches run at once and that a request beyond them is turned away
// at once instead of queueing.
func TestCIMDFetcher_BoundsFetchesInFlight(t *testing.T) {
	tr := &blockingTransport{release: make(chan struct{}), body: func(r *http.Request) []byte {
		return cimdTestDocument(r.URL.String(), nil)
	}}
	f := newCIMDFetcher(cimdHTTPClient(tr))
	clientID := func(i int) string { return fmt.Sprintf("https://example.com/clients/%d.json", i) }

	errs := make(chan error, maxCIMDFetches)
	for i := range maxCIMDFetches {
		go func() {
			_, err := f.fetch(context.Background(), clientID(i))
			errs <- err
		}()
	}
	waitFor(t, "every slot to be taken", func() bool { return int(tr.started.Load()) == maxCIMDFetches })

	start := time.Now()
	_, err := f.fetch(context.Background(), clientID(maxCIMDFetches))
	var ce *cimdError
	if !errors.As(err, &ce) || ce.kind != cimdBusy {
		t.Fatalf("err = %v, want a cimdError of kind busy", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("the refusal took %s", elapsed)
	}

	close(tr.release)
	for range maxCIMDFetches {
		if err := <-errs; err != nil {
			t.Errorf("fetch: %v", err)
		}
	}
	if _, err := f.fetch(context.Background(), clientID(maxCIMDFetches)); err != nil {
		t.Errorf("fetch after the slots were free again: %v", err)
	}
}

// TestCIMDFetcher_CacheIsBounded pins that the cache does not grow beyond
// maxCIMDCacheEntries, and that what is given up is what runs out first.
func TestCIMDFetcher_CacheIsBounded(t *testing.T) {
	f := newCIMDFetcher(nil)
	now := time.Now()
	f.now = func() time.Time { return now }
	clientID := func(i int) string { return fmt.Sprintf("https://example.com/clients/%d.json", i) }

	f.mu.Lock()
	for i := range maxCIMDCacheEntries {
		// Entry 0 runs out first, entry 1 has run out already.
		lifetime := time.Duration(i+1) * time.Hour
		if i == 1 {
			lifetime = -time.Minute
		}
		f.storeLocked(clientID(i), &clientMetadata{}, lifetime)
	}
	// Two more than fit, both outliving everything else: the first takes
	// the place of the entry that has run out, the second that of entry 0.
	late := time.Duration(maxCIMDCacheEntries+10) * time.Hour
	f.storeLocked(clientID(maxCIMDCacheEntries), &clientMetadata{}, late)
	f.storeLocked(clientID(maxCIMDCacheEntries+1), &clientMetadata{}, late)
	size := len(f.cache)
	f.mu.Unlock()

	if size > maxCIMDCacheEntries {
		t.Errorf("cache holds %d entries, want at most %d", size, maxCIMDCacheEntries)
	}
	for _, i := range []int{0, 1} {
		if _, ok := f.cached(clientID(i)); ok {
			t.Errorf("entry %d is still cached", i)
		}
	}
	for _, i := range []int{2, maxCIMDCacheEntries - 1, maxCIMDCacheEntries, maxCIMDCacheEntries + 1} {
		if _, ok := f.cached(clientID(i)); !ok {
			t.Errorf("entry %d was given up", i)
		}
	}
}

// TestCIMDTransport_RefusesAddressesThatAreNotPublic runs the fetcher as the
// server builds it against a document host that listens on loopback. The
// connection must not be made: the host sees no request, whatever name or
// notation the URL uses for the address.
func TestCIMDTransport_RefusesAddressesThatAreNotPublic(t *testing.T) {
	host := newCIMDTestHost(t, func(w http.ResponseWriter, r *http.Request) {
		serveDocument(cimdTestDocument("https://"+r.Host+r.URL.Path, nil))(w, r)
	})
	_, port, err := net.SplitHostPort(host.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	f := newCIMDFetcher(cimdHTTPClient(cimdTransport()))
	for _, authority := range []string{
		"127.0.0.1:" + port,
		"localhost:" + port,
		"LOCALHOST:" + port,
		"localhost.:" + port,
		"[::1]:" + port,
		"[::ffff:127.0.0.1]:" + port,
		"127.1:" + port,
		"2130706433:" + port, // 127.0.0.1 as one number
		"0x7f000001:" + port,
		"0.0.0.0:" + port,
		"169.254.169.254",
		"10.1.2.3",
		"192.168.1.1",
		"[fd00::1]",
		"metadata.google.internal",
	} {
		clientID := "https://" + authority + "/oauth/client.json"
		_, err := f.fetch(context.Background(), clientID)
		var ce *cimdError
		if !errors.As(err, &ce) || ce.kind != cimdUnavailable {
			t.Errorf("%s: err = %v, want a cimdError of kind unavailable", authority, err)
		}
	}
	if n := host.requests(); n != 0 {
		t.Errorf("the loopback host received %d requests, want none", n)
	}
}

// TestCIMDTransport_Settings pins the bounds on the transport that are not
// visible in a response: no proxy, no connection kept, a bounded header.
func TestCIMDTransport_Settings(t *testing.T) {
	tr := cimdTransport()
	if tr.Proxy != nil {
		t.Error("the transport uses a proxy")
	}
	if !tr.DisableKeepAlives {
		t.Error("the transport keeps connections open")
	}
	if tr.MaxResponseHeaderBytes != maxCIMDHeaderBytes {
		t.Errorf("MaxResponseHeaderBytes = %d, want %d", tr.MaxResponseHeaderBytes, maxCIMDHeaderBytes)
	}
	if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("the transport does not verify certificates")
	}
	c := cimdHTTPClient(tr)
	if c.Timeout != cimdFetchTimeout || c.Jar != nil {
		t.Errorf("client timeout %s, jar %v", c.Timeout, c.Jar)
	}
}
