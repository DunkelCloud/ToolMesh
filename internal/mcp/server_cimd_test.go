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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	cimdTestVerifier = "cimd-test-verifier-with-enough-entropy-0123456789"

	testMsgMetadataNotUsable = "client metadata document not usable"
	testMetadataPath         = "/.well-known/oauth-authorization-server"
	testHeaderLocation       = "Location"
)

// newCIMDTestServer returns a server that accepts clients with a metadata
// document on cimdTestHostName, and the host its fetches go to. A cfg that
// is given is used as it is.
func newCIMDTestServer(t *testing.T, cfg *config.Config, handler http.HandlerFunc) (*loginTestServer, *cimdTestHost) {
	t.Helper()
	if cfg == nil {
		cfg = loginTestConfig()
		cfg.CIMDHosts = []string{cimdTestHostName}
	}
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	host := newCIMDTestHost(t, handler)
	ts.srv.cimd = newCIMDFetcher(host.client())
	return ts, host
}

// authorizePage requests the login page.
func (ts *loginTestServer) authorizePage(clientID, redirectURI, remoteAddr string) *httptest.ResponseRecorder {
	q := url.Values{
		oauthClientID:      {clientID},
		oauthRedirectURI:   {redirectURI},
		oauthCodeChallenge: {testLoginChallenge},
		oauthState:         {"s1"},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+q.Encode(), nil)
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// loginForCode logs the owner in for clientID, redirected to
// testLoginRedirect, with a code challenge whose verifier is
// cimdTestVerifier, and returns the response.
func (ts *loginTestServer) loginForCode(clientID, state string) *httptest.ResponseRecorder {
	sum := sha256.Sum256([]byte(cimdTestVerifier))
	form := url.Values{
		testFormUsername:   {testLoginOwner},
		testFormPassword:   {testLoginSecret},
		oauthClientID:      {clientID},
		oauthRedirectURI:   {testLoginRedirect},
		oauthConfirmHost:   {confirmHostOf(testLoginRedirect)},
		oauthState:         {state},
		oauthCodeChallenge: {base64.RawURLEncoding.EncodeToString(sum[:])},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set(testHeaderContentType, "application/x-www-form-urlencoded")
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// exchangeCode takes the code of a login response to the token endpoint.
func (ts *loginTestServer) exchangeCode(t *testing.T, login *httptest.ResponseRecorder, clientID string) *httptest.ResponseRecorder {
	t.Helper()
	loc, err := url.Parse(login.Header().Get(testHeaderLocation))
	if err != nil || loc.Query().Get(argNameCode) == "" {
		t.Fatalf("login: status %d, Location %q, body %s", login.Code, login.Header().Get(testHeaderLocation), login.Body.String())
	}
	return ts.token(url.Values{
		oauthGrantType:    {oauthGrantAuthCode},
		argNameCode:       {loc.Query().Get(argNameCode)},
		oauthCodeVerifier: {cimdTestVerifier},
		oauthClientID:     {clientID},
	})
}

// issuedToken returns the stored record of the access token in a token
// response, and the refresh token of the response.
func (ts *loginTestServer) issuedToken(t *testing.T, w *httptest.ResponseRecorder) (ti *auth.TokenInfo, refresh string) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("token request: status %d, body %s", w.Code, w.Body.String())
	}
	var tokens map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	access, _ := tokens["access_token"].(string)
	refresh, _ = tokens[oauthRefreshToken].(string)
	ti, err := ts.srv.tokenStore.GetToken(context.Background(), access)
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	return ti, refresh
}

// oauthError decodes the error and its description from a JSON answer.
func oauthError(t *testing.T, w *httptest.ResponseRecorder) (code, description string) {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("answer is not JSON (status %d): %s", w.Code, w.Body.String())
	}
	return body[outcomeError], body[oauthErrorDescription]
}

// TestCIMD_AuthorizationCodeFlow walks a client that never registered
// through the whole flow: login page, login, code, tokens, a call, a refresh.
func TestCIMD_AuthorizationCodeFlow(t *testing.T) {
	ts, host := newCIMDTestServer(t, nil, serveDocument(cimdTestDocument(cimdTestClientID, nil)))

	page := ts.authorizePage(cimdTestClientID, testLoginRedirect, testLoginAddr)
	if page.Code != http.StatusOK {
		t.Fatalf("login page: status %d, body %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		"ToolMesh read from:", `<p class="host">example.com</p>`,
		"<bdi>" + cimdTestName + "</bdi>", "has not verified",
		`name="client_id" value="` + cimdTestClientID + `"`,
		`name="confirm_host" value="example.com" required`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %q", want)
		}
	}
	if strings.Contains(body, cimdTestMarker) {
		t.Error("the login page shows a field of the document it has no use for")
	}
	if strings.Contains(body, "program on the device") {
		t.Error("the login page warns about a loopback redirect that is none")
	}

	login := ts.loginForCode(cimdTestClientID, "state with spaces & more")
	if login.Code != http.StatusFound {
		t.Fatalf("login: status %d, body %s", login.Code, login.Body.String())
	}
	loc, err := url.Parse(login.Header().Get(testHeaderLocation))
	if err != nil {
		t.Fatal(err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != testLoginRedirect {
		t.Errorf("redirect goes to %q, want %q", got, testLoginRedirect)
	}
	if loc.Query().Get(argNameCode) == "" || loc.Query().Get(oauthState) != "state with spaces & more" {
		t.Errorf("redirect query = %q", loc.RawQuery)
	}
	if iss := loc.Query().Get("iss"); iss != testIssuerToolmesh {
		t.Errorf("iss = %q, want %q", iss, testIssuerToolmesh)
	}
	// The login page and its submission used one fetch.
	if n := host.requests(); n != 1 {
		t.Errorf("%d fetches for page and login, want 1", n)
	}

	ti, refresh := ts.issuedToken(t, ts.exchangeCode(t, login, cimdTestClientID))
	access := ti.AccessToken
	if ti.ClientID != cimdTestClientID || ti.CallerID != cimdTestClientID || ti.CallerName != cimdTestName {
		t.Errorf("token: client %q, caller %q, caller name %q", ti.ClientID, ti.CallerID, ti.CallerName)
	}
	if w := ts.mcpCall("Bearer " + access); strings.Contains(w.Body.String(), "Unauthorized") {
		t.Errorf("the access token was not accepted: %s", w.Body.String())
	}

	// Nothing was stored for the client, and nothing complains about that.
	if _, err := ts.srv.tokenStore.GetClient(context.Background(), cimdTestClientID); !errors.Is(err, auth.ErrNotFound) {
		t.Errorf("GetClient err = %v, want ErrNotFound", err)
	}
	if recs := ts.logs.lines(t, "could not extend oauth client lifetime"); len(recs) != 0 {
		t.Errorf("the token endpoint tried to extend a client that is not stored: %v", recs)
	}

	// Grants of kits are bound to this sign-in, not to the client_id that
	// every installation of the client shares: the token names the sign-in,
	// the caller of a request carries it, and a refresh keeps it.
	if !strings.HasPrefix(ti.GrantKey, userctx.GrantKeyLoginPrefix) || len(ti.GrantKey) != len(userctx.GrantKeyLoginPrefix)+loginGrantKeyLen {
		t.Errorf("grant key = %q, want %s and %d characters", ti.GrantKey, userctx.GrantKeyLoginPrefix, loginGrantKeyLen)
	}
	call := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	call.Header.Set("Authorization", "Bearer "+access)
	caller, err := ts.srv.authenticate(call)
	if err != nil || caller.CallerID != cimdTestClientID || caller.GrantKey != ti.GrantKey || caller.GrantBinding() == cimdTestClientID {
		t.Errorf("caller = %+v, %v; want the client_id as caller id and the sign-in as grant binding", caller, err)
	}
	renewed, _ := ts.issuedToken(t, ts.token(url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {refresh}, oauthClientID: {cimdTestClientID}}))
	if renewed.GrantKey != ti.GrantKey || renewed.CallerID != cimdTestClientID || renewed.CallerName != cimdTestName {
		t.Errorf("after the refresh: grant key %q (was %q), caller %q, caller name %q", renewed.GrantKey, ti.GrantKey, renewed.CallerID, renewed.CallerName)
	}
	// Another sign-in through the same client is another holder of grants.
	other, _ := ts.issuedToken(t, ts.exchangeCode(t, ts.loginForCode(cimdTestClientID, "s2"), cimdTestClientID))
	if other.GrantKey == ti.GrantKey || other.GrantKey == "" {
		t.Errorf("second sign-in has grant key %q, the first %q", other.GrantKey, ti.GrantKey)
	}
	// A registered client has a client_id of its own and needs no such key.
	registered, _ := ts.issuedToken(t, ts.exchangeCode(t, ts.loginForCode(ts.clientID, "s3"), ts.clientID))
	if registered.GrantKey != "" || registered.CallerID != ts.clientID {
		t.Errorf("registered client: grant key %q, caller %q", registered.GrantKey, registered.CallerID)
	}
	// Neither token request needed the document.
	if n := host.requests(); n != 1 {
		t.Errorf("%d fetches after the token requests, want 1", n)
	}

	// A code of this client is not exchanged for another client_id.
	stolen := ts.exchangeCode(t, ts.loginForCode(cimdTestClientID, "s4"), "https://example.com/oauth/other.json")
	if stolen.Code != http.StatusBadRequest {
		t.Errorf("code exchange under another client_id: status %d, want 400", stolen.Code)
	}
}

// TestCIMD_InvalidDocument pins how the authorization endpoint answers when
// the document cannot be used: never with a redirect, and with a reason only
// when the URL serves a document of this client.
func TestCIMD_InvalidDocument(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		// reason is what the description must name; "" for the one answer
		// that says no more than that there is no usable document.
		reason string
	}{
		{"a page instead of a document", serveDocument([]byte("<html>" + cimdTestMarker + "</html>")), ""},
		{"status 404", func(w http.ResponseWriter, _ *http.Request) { http.Error(w, cimdTestMarker, http.StatusNotFound) }, ""},
		{"document of another client", serveDocument(cimdTestDocument("https://example.com/oauth/other.json", nil)), ""},
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/elsewhere.json", http.StatusFound)
		}, ""},
		{"no client_name", serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: nil})), "client_name is missing"},
		{"no redirect_uris", serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldRedirectURIs: nil})), "redirect_uris is missing"},
		{"client secret", serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientSecret: cimdTestMarker})), "client secret"},
		{"confidential client", serveDocument(cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldAuthMethod: cimdTestKeyMethod})), "public clients only"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ts, host := newCIMDTestServer(t, nil, tc.handler)
			remote := fmt.Sprintf("203.0.113.%d:40000", 10+i)

			check := func(what string, w *httptest.ResponseRecorder) {
				t.Helper()
				if w.Code != http.StatusBadRequest || w.Header().Get(testHeaderLocation) != "" {
					t.Fatalf("%s: status %d, Location %q; want 400 without a redirect", what, w.Code, w.Header().Get(testHeaderLocation))
				}
				code, description := oauthError(t, w)
				if code != oauthErrInvalidClient {
					t.Errorf("%s: error = %q, want %q", what, code, oauthErrInvalidClient)
				}
				if tc.reason == "" && description != descClientMetadataUnavailable {
					t.Errorf("%s: description = %q, want only %q", what, description, descClientMetadataUnavailable)
				}
				if tc.reason != "" && !strings.Contains(description, tc.reason) {
					t.Errorf("%s: description = %q, want it to name %q", what, description, tc.reason)
				}
				if strings.Contains(w.Body.String(), cimdTestMarker) {
					t.Errorf("%s: the answer repeats content of the response: %s", what, w.Body.String())
				}
			}
			check("login page", ts.authorizePage(cimdTestClientID, testLoginRedirect, remote))
			check("login", ts.loginTo(cimdTestClientID, testLoginRedirect, testLoginOwner, testLoginSecret, remote))

			// A failure is not remembered: each request fetched.
			if n := host.requests("/oauth/client.json"); n != 2 {
				t.Errorf("%d fetches, want 2", n)
			}
			if n := host.requests("/elsewhere.json"); n != 0 {
				t.Errorf("a redirect was followed")
			}
			recs := ts.logs.lines(t, testMsgMetadataNotUsable)
			if len(recs) != 2 {
				t.Fatalf("got %d %q lines, want 2", len(recs), testMsgMetadataNotUsable)
			}
			for _, rec := range recs {
				reason, _ := rec[logKeyReason].(string)
				if rec["level"] != testLogLevelWarn || rec[logKeyClientID] != cimdTestClientID || reason == "" || strings.Contains(reason, cimdTestMarker) {
					t.Errorf("record = %v, want WARN with the client_id and a reason that repeats nothing of the response", rec)
				}
			}
			// The login was turned away before the password was looked at.
			if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
				t.Errorf("password failures = %v, want 0", got)
			}
		})
	}
}

// TestCIMD_RedirectURIMismatch pins that the redirect_uri of the request
// must be listed in the document, and that only https and loopback http are
// redirected to, whatever a document lists.
func TestCIMD_RedirectURIMismatch(t *testing.T) {
	doc := cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldRedirectURIs: []string{
		testLoginRedirect, cimdTestLoopback, "http://example.com/plain", "cursor://callback/cb", "javascript:alert(1)",
	}})
	ts, _ := newCIMDTestServer(t, nil, serveDocument(doc))

	cases := []struct {
		redirect string
		ok       bool
	}{
		{testLoginRedirect, true},
		{"http://localhost:53124/callback", true},
		{testLoginRedirect + "/", false},
		{"https://example.com/other", false},
		{"https://evil.example/cb", false},
		{"http://localhost:53124/other", false},
		{"http://127.0.0.1:53124/callback", false},
		{"http://example.com/plain", false},   // listed, but neither https nor loopback
		{"cursor://callback/cb", false},       // listed, but no https
		{"javascript:alert(1)", false},        // listed, and no URL to redirect to
		{testLoginRedirect + "#frag", false},  // a fragment is never accepted
		{"https://example.com%2Fcb", false},   // not the listed string
		{"https://example.com/cb?x=1", false}, // not the listed string
	}
	for _, tc := range cases {
		for what, w := range map[string]*httptest.ResponseRecorder{
			"login page": ts.authorizePage(cimdTestClientID, tc.redirect, testLoginAddr),
			"login":      ts.loginTo(cimdTestClientID, tc.redirect, testLoginOwner, testLoginSecret, testLoginAddr),
		} {
			if w.Header().Get(testHeaderLocation) != "" && !tc.ok {
				t.Errorf("%s with redirect_uri %q: redirected to %q", what, tc.redirect, w.Header().Get(testHeaderLocation))
			}
			accepted := w.Code == http.StatusOK || w.Code == http.StatusFound
			if accepted != tc.ok {
				t.Errorf("%s with redirect_uri %q: status %d, body %s", what, tc.redirect, w.Code, w.Body.String())
				continue
			}
			if !tc.ok {
				if code, _ := oauthError(t, w); code != oauthErrInvalidRedURI {
					t.Errorf("%s with redirect_uri %q: error = %q, want %q", what, tc.redirect, code, oauthErrInvalidRedURI)
				}
			}
		}
	}
}

// TestCIMD_LoopbackRedirect pins what the login page says when a client with
// a metadata document is redirected to on the loopback interface, and that
// the person confirms the loopback address, not the host of the document.
func TestCIMD_LoopbackRedirect(t *testing.T) {
	ts, _ := newCIMDTestServer(t, nil, serveDocument(cimdTestDocument(cimdTestClientID, nil)))
	const redirect = "http://localhost:53124/callback"

	page := ts.authorizePage(cimdTestClientID, redirect, testLoginAddr)
	if page.Code != http.StatusOK {
		t.Fatalf("login page: status %d, body %s", page.Code, page.Body.String())
	}
	body := page.Body.String()
	for _, want := range []string{
		`<p class="host">example.com</p>`, `<p class="host">localhost:53124</p>`,
		"program on the device", `name="confirm_host" value="localhost:53124" required`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("login page lacks %q", want)
		}
	}

	form := url.Values{
		testFormUsername: {testLoginOwner}, testFormPassword: {testLoginSecret},
		oauthClientID: {cimdTestClientID}, oauthRedirectURI: {redirect},
		oauthState: {"s1"}, oauthCodeChallenge: {testLoginChallenge},
	}
	post := func(confirm string) *httptest.ResponseRecorder {
		form.Set(oauthConfirmHost, confirm)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
		req.Header.Set(testHeaderContentType, "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		return w
	}
	if w := post("example.com"); w.Code != http.StatusBadRequest || w.Header().Get(testHeaderLocation) != "" {
		t.Errorf("confirming the document host: status %d, Location %q; want 400", w.Code, w.Header().Get(testHeaderLocation))
	}
	w := post("localhost:53124")
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get(testHeaderLocation), redirect+"?code=") {
		t.Errorf("confirmed login: status %d, Location %q", w.Code, w.Header().Get(testHeaderLocation))
	}
}

// TestCIMD_LoginPageEscapesTheDocument pins that what a document says
// reaches the page as text.
func TestCIMD_LoginPageEscapesTheDocument(t *testing.T) {
	doc := cimdTestDocument(cimdTestClientID, map[string]any{cimdFieldClientName: `<script>alert(1)</script>"Claude"`})
	ts, _ := newCIMDTestServer(t, nil, serveDocument(doc))
	page := ts.authorizePage(cimdTestClientID, testLoginRedirect, testLoginAddr)
	if page.Code != http.StatusOK {
		t.Fatalf("login page: status %d", page.Code)
	}
	if body := page.Body.String(); strings.Contains(body, "<script>alert") || !strings.Contains(body, "<bdi>scriptalert(1)/scriptClaude</bdi>") {
		t.Errorf("the client name is not shown as plain text: %s", body)
	}
}

// TestAuthorize_ResponseCarriesIss pins RFC 9207 for every client: the
// redirect back carries iss, it is the issuer of the metadata to the
// character, and the metadata says that it is sent.
func TestAuthorize_ResponseCarriesIss(t *testing.T) {
	for _, issuer := range []string{testIssuerToolmesh, "https://toolmesh.io", "https://mesh.example.org:8443/"} {
		cfg := loginTestConfig()
		cfg.Issuer = issuer
		ts := newLoginTestServer(t, cfg, loginTestOptions{})

		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, testMetadataPath, nil)
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		var metadata map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata["authorization_response_iss_parameter_supported"] != true {
			t.Errorf("issuer %q: metadata does not announce iss: %v", issuer, metadata)
		}
		want, _ := metadata["issuer"].(string)

		login := ts.login(testLoginOwner, testLoginSecret, testLoginAddr)
		if login.Code != http.StatusFound {
			t.Fatalf("issuer %q: login status %d", issuer, login.Code)
		}
		location := login.Header().Get(testHeaderLocation)
		loc, err := url.Parse(location)
		if err != nil {
			t.Fatal(err)
		}
		if got := loc.Query().Get("iss"); got == "" || got != want {
			t.Errorf("issuer %q: iss = %q, metadata issuer = %q", issuer, got, want)
		}
		if !strings.HasSuffix(location, "&iss="+url.QueryEscape(want)) {
			t.Errorf("issuer %q: Location = %q, want iss percent-encoded at the end", issuer, location)
		}
		if loc.Query().Get(argNameCode) == "" || loc.Query().Get(oauthState) != "s1" {
			t.Errorf("issuer %q: code or state missing in %q", issuer, location)
		}
	}
}

// TestAuthorize_IssWithQueryInRedirectURI pins that iss joins a redirect URI
// that has a query of its own.
func TestAuthorize_IssWithQueryInRedirectURI(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	const redirect = "https://example.com/cb?tenant=a"
	clientID := registeredClientID(t, registerClient(t, ts.mux, "x", redirect))
	login := ts.loginTo(clientID, redirect, testLoginOwner, testLoginSecret, testLoginAddr)
	loc, err := url.Parse(login.Header().Get(testHeaderLocation))
	if err != nil || login.Code != http.StatusFound {
		t.Fatalf("login: status %d, err %v", login.Code, err)
	}
	q := loc.Query()
	if q.Get("tenant") != "a" || q.Get(argNameCode) == "" || q.Get("iss") != testIssuerToolmesh {
		t.Errorf("Location = %q", login.Header().Get(testHeaderLocation))
	}
}

// TestOAuthMetadata_AnnouncesClientMetadataDocuments pins that the metadata
// says whether a client may name itself by a URL, and that registration is
// offered either way.
func TestOAuthMetadata_AnnouncesClientMetadataDocuments(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		cfg := &config.Config{Issuer: testIssuerToolmesh}
		if enabled {
			cfg.CIMDHosts = []string{cimdTestHostName}
		}
		_, mux := newTestServer(t, cfg)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, testMetadataPath, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var metadata map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
			t.Fatal(err)
		}
		if metadata["client_id_metadata_document_supported"] != enabled {
			t.Errorf("enabled %v: client_id_metadata_document_supported = %v", enabled, metadata["client_id_metadata_document_supported"])
		}
		if metadata["registration_endpoint"] != "https://toolmesh.io/register" {
			t.Errorf("enabled %v: registration_endpoint = %v", enabled, metadata["registration_endpoint"])
		}
	}
}

// TestCIMD_SwitchedOff pins that with metadata documents off a URL is a
// client_id nobody registered: the answer is that of an unknown client and
// nothing is fetched.
func TestCIMD_SwitchedOff(t *testing.T) {
	cfg := loginTestConfig() // lists no host for metadata documents
	ts, host := newCIMDTestServer(t, cfg, serveDocument(cimdTestDocument(cimdTestClientID, nil)))

	page := ts.authorizePage(cimdTestClientID, testLoginRedirect, testLoginAddr)
	if _, description := oauthError(t, page); page.Code != http.StatusBadRequest || description != descUnknownClient {
		t.Errorf("login page: status %d, description %q; want 400 %q", page.Code, description, descUnknownClient)
	}
	login := ts.loginTo(cimdTestClientID, testLoginRedirect, testLoginOwner, testLoginSecret, testLoginAddr)
	if _, description := oauthError(t, login); login.Code != http.StatusBadRequest || description != descUnknownClient {
		t.Errorf("login: status %d, description %q; want 400 %q", login.Code, description, descUnknownClient)
	}
	if n := host.requests(); n != 0 {
		t.Errorf("%d fetches with metadata documents switched off", n)
	}
	// Registered clients are served as before.
	if w := ts.login(testLoginOwner, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("login of a registered client: status %d", w.Code)
	}
}

// TestCIMD_NothingIsFetchedThatCannotLeadToALogin pins the order of the
// checks: whatever can turn a request away without a fetch does.
func TestCIMD_NothingIsFetchedThatCannotLeadToALogin(t *testing.T) {
	cases := []struct {
		name     string
		prepare  func(cfg *config.Config)
		clientID string
		redirect string
		status   int
		code     string
	}{
		{name: "client_id with a query", clientID: cimdTestClientID + "?x=1", status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "client_id without a path", clientID: "https://example.com/", status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "client_id with user information", clientID: "https://claude.ai@example.com/client.json", status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "client_id on this server", clientID: "https://toolmesh.io/blobs/abc", status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "client_id host not allowed", prepare: func(cfg *config.Config) { cfg.CIMDHosts = []string{cimdTestOtherHost, "*.example.net"} },
			clientID: cimdTestClientID, status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "subdomain where only the domain is allowed", prepare: func(cfg *config.Config) { cfg.CIMDHosts = []string{cimdTestHostName} },
			clientID: "https://sub.example.com/client.json", status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "domain where only subdomains are allowed", prepare: func(cfg *config.Config) { cfg.CIMDHosts = []string{"*." + cimdTestHostName} },
			clientID: cimdTestClientID, status: http.StatusBadRequest, code: oauthErrInvalidClient},
		{name: "redirect host not allowed", prepare: func(cfg *config.Config) { cfg.OAuthRedirectHosts = []string{cimdTestOtherHost} },
			clientID: cimdTestClientID, status: http.StatusBadRequest, code: oauthErrInvalidRedURI},
		{name: "redirect_uri that is no https", clientID: cimdTestClientID, redirect: "http://example.com/cb", status: http.StatusBadRequest, code: oauthErrInvalidRedURI},
		{name: "redirect_uri with a fragment", clientID: cimdTestClientID, redirect: testLoginRedirect + "#x", status: http.StatusBadRequest, code: oauthErrInvalidRedURI},
		{name: "no password login", prepare: func(cfg *config.Config) { cfg.AuthPassword = ""; cfg.APIKey = testLoginAPIKey },
			clientID: cimdTestClientID, status: http.StatusForbidden, code: oauthErrAccessDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loginTestConfig()
			cfg.CIMDHosts = []string{cimdTestHostName}
			ts, host := newCIMDTestServer(t, cfg, func(w http.ResponseWriter, r *http.Request) {
				serveDocument(cimdTestDocument("https://"+r.Host+r.URL.Path, nil))(w, r)
			})
			// The settings take effect after the registration the helper
			// makes for its own client.
			if tc.prepare != nil {
				tc.prepare(ts.srv.cfg)
			}
			redirect := tc.redirect
			if redirect == "" {
				redirect = testLoginRedirect
			}
			for what, w := range map[string]*httptest.ResponseRecorder{
				"login page": ts.authorizePage(tc.clientID, redirect, testLoginAddr),
				"login":      ts.loginTo(tc.clientID, redirect, testLoginOwner, testLoginSecret, testLoginAddr),
			} {
				code, _ := oauthError(t, w)
				if w.Code != tc.status || code != tc.code {
					t.Errorf("%s: status %d, error %q; want %d %q (body %s)", what, w.Code, code, tc.status, tc.code, w.Body.String())
				}
			}
			if n := host.requests(); n != 0 {
				t.Errorf("%d fetches, want none", n)
			}
		})
	}
}

// TestCIMD_HostAllowlist pins that a listed host is fetched from.
func TestCIMD_HostAllowlist(t *testing.T) {
	for _, hosts := range [][]string{{cimdTestHostName}, {cimdTestOtherHost, cimdTestHostName}} {
		cfg := loginTestConfig()
		cfg.CIMDHosts = hosts
		ts, _ := newCIMDTestServer(t, cfg, serveDocument(cimdTestDocument(cimdTestClientID, nil)))
		if w := ts.authorizePage(cimdTestClientID, testLoginRedirect, testLoginAddr); w.Code != http.StatusOK {
			t.Errorf("hosts %v: status %d, body %s", hosts, w.Code, w.Body.String())
		}
	}
	cfg := loginTestConfig()
	cfg.CIMDHosts = []string{"*." + cimdTestHostName}
	const clientID = "https://clients.example.com/app.json"
	ts, _ := newCIMDTestServer(t, cfg, serveDocument(cimdTestDocument(clientID, nil)))
	if w := ts.authorizePage(clientID, testLoginRedirect, testLoginAddr); w.Code != http.StatusOK {
		t.Errorf("subdomain of a listed domain: status %d, body %s", w.Code, w.Body.String())
	}
}

// TestCIMD_FetchesAreLimitedPerAddress pins that one address cannot make
// the server fetch without end, that the limit does not touch documents
// that are cached, and that other addresses are not affected.
func TestCIMD_FetchesAreLimitedPerAddress(t *testing.T) {
	ts, host := newCIMDTestServer(t, nil, func(w http.ResponseWriter, r *http.Request) {
		serveDocument(cimdTestDocument("https://"+r.Host+r.URL.Path, nil))(w, r)
	})
	clientID := func(i int) string { return fmt.Sprintf("https://example.com/clients/%d.json", i) }

	const limit = 10 // fetches per address and minute
	for i := range limit {
		if w := ts.authorizePage(clientID(i), testLoginRedirect, testLoginAddr); w.Code != http.StatusOK {
			t.Fatalf("fetch %d: status %d, body %s", i+1, w.Code, w.Body.String())
		}
	}
	refused := ts.authorizePage(clientID(limit), testLoginRedirect, testLoginAddr)
	if code, _ := oauthError(t, refused); refused.Code != http.StatusTooManyRequests || code != oauthErrTooManyRequests {
		t.Errorf("fetch beyond the limit: status %d, error %q; want 429 %q", refused.Code, code, oauthErrTooManyRequests)
	}
	if refused.Header().Get(testHeaderRetryAfter) != "60" {
		t.Errorf("Retry-After = %q, want 60", refused.Header().Get(testHeaderRetryAfter))
	}
	if n := host.requests(); n != limit {
		t.Errorf("%d fetches, want %d", n, limit)
	}
	// A cached document needs no fetch, so the address still gets it.
	if w := ts.authorizePage(clientID(0), testLoginRedirect, testLoginAddr); w.Code != http.StatusOK {
		t.Errorf("cached document from the limited address: status %d", w.Code)
	}
	// Another address is not limited.
	if w := ts.authorizePage(clientID(limit), testLoginRedirect, testLoginOtherAddr); w.Code != http.StatusOK {
		t.Errorf("fetch from another address: status %d, body %s", w.Code, w.Body.String())
	}
	// Requests that are turned away before a fetch do not count.
	for range 2 * limit {
		ts.authorizePage(clientID(99)+"?x=1", testLoginRedirect, "198.51.100.77:40000")
	}
	if w := ts.authorizePage(clientID(98), testLoginRedirect, "198.51.100.77:40000"); w.Code != http.StatusOK {
		t.Errorf("fetch after refused requests that fetched nothing: status %d", w.Code)
	}
}

// TestCIMD_BusyAnswer pins the answer while every fetch slot is taken.
func TestCIMD_BusyAnswer(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	ts.srv.cfg.CIMDHosts = []string{cimdTestHostName}
	tr := &blockingTransport{release: make(chan struct{}), body: func(r *http.Request) []byte {
		return cimdTestDocument(r.URL.String(), nil)
	}}
	ts.srv.cimd = newCIMDFetcher(cimdHTTPClient(tr))

	done := make(chan struct{}, maxCIMDFetches)
	for i := range maxCIMDFetches {
		go func() {
			_, _ = ts.srv.cimd.fetch(context.Background(), fmt.Sprintf("https://example.com/clients/%d.json", i))
			done <- struct{}{}
		}()
	}
	waitFor(t, "every slot to be taken", func() bool { return int(tr.started.Load()) == maxCIMDFetches })

	w := ts.authorizePage(cimdTestClientID, testLoginRedirect, testLoginAddr)
	if code, _ := oauthError(t, w); w.Code != http.StatusServiceUnavailable || code != oauthErrTemporarilyUnavailable {
		t.Errorf("status %d, error %q; want 503 %q", w.Code, code, oauthErrTemporarilyUnavailable)
	}
	if w.Header().Get(testHeaderRetryAfter) != "1" {
		t.Errorf("Retry-After = %q, want 1", w.Header().Get(testHeaderRetryAfter))
	}
	close(tr.release)
	for range maxCIMDFetches {
		<-done
	}
}

// TestCIMD_PrivateAddressIsNotReached runs the server as it is built, with
// its own fetch client, against a document host on loopback. The host must
// see no request, and the answer must not say why: that a name leads to a
// private address is something only this server can know.
func TestCIMD_PrivateAddressIsNotReached(t *testing.T) {
	host := newCIMDTestHost(t, func(w http.ResponseWriter, r *http.Request) {
		serveDocument(cimdTestDocument("https://"+r.Host+r.URL.Path, nil))(w, r)
	})
	authority := host.srv.Listener.Addr().String() // 127.0.0.1:port
	_, port, _ := strings.Cut(authority, ":")
	clientIDs := []string{
		"https://" + authority + "/oauth/client.json",
		"https://localhost:" + port + "/oauth/client.json",
		"https://[::1]:" + port + "/oauth/client.json",
	}
	cfg := loginTestConfig()
	// The hosts are listed: what keeps the fetch away is where they resolve.
	for _, clientID := range clientIDs {
		u, err := url.Parse(clientID)
		if err != nil {
			t.Fatal(err)
		}
		cfg.CIMDHosts = append(cfg.CIMDHosts, u.Hostname())
	}
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	for i, clientID := range clientIDs {
		w := ts.authorizePage(clientID, testLoginRedirect, fmt.Sprintf("203.0.113.%d:40000", 50+i))
		code, description := oauthError(t, w)
		if w.Code != http.StatusBadRequest || code != oauthErrInvalidClient || description != descClientMetadataUnavailable {
			t.Errorf("%s: status %d, error %q, description %q", clientID, w.Code, code, description)
		}
	}
	if n := host.requests(); n != 0 {
		t.Errorf("the loopback host received %d requests, want none", n)
	}
	recs := ts.logs.lines(t, testMsgMetadataNotUsable)
	if len(recs) != 3 {
		t.Fatalf("got %d %q lines, want 3", len(recs), testMsgMetadataNotUsable)
	}
	if reason, _ := recs[0][logKeyReason].(string); !strings.Contains(reason, "private") {
		t.Errorf("log reason = %q, want it to say that the address is private", reason)
	}
}

// TestCIMD_SessionsEndWhenTheClientIsNoLongerAccepted pins that switching
// metadata documents off, or taking a host off the allowlist, also ends what
// such a client obtained before: its code, its access token, its refresh
// token. Tokens of registered clients are not touched.
func TestCIMD_SessionsEndWhenTheClientIsNoLongerAccepted(t *testing.T) {
	for name, revoke := range map[string]func(cfg *config.Config){
		"switched off":      func(cfg *config.Config) { cfg.CIMDHosts = nil },
		"host not listed":   func(cfg *config.Config) { cfg.CIMDHosts = []string{cimdTestOtherHost} },
		"issuer is the url": func(cfg *config.Config) { cfg.Issuer = "https://example.com/" },
	} {
		t.Run(name, func(t *testing.T) {
			ts, _ := newCIMDTestServer(t, nil, serveDocument(cimdTestDocument(cimdTestClientID, nil)))
			ctx := context.Background()

			pair := func(clientID string) (access, refresh string) {
				access, refresh = generateID(), generateID()
				ti := &auth.TokenInfo{
					AccessToken: access, RefreshToken: refresh, ClientID: clientID, CallerID: clientID,
					UserID: testLoginOwner, ExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(time.Hour),
				}
				if isClientIDURL(clientID) {
					ti.GrantKey = userctx.GrantKeyLoginPrefix + generateID()[:loginGrantKeyLen]
				}
				if err := ts.srv.tokenStore.SaveToken(ctx, ti); err != nil {
					t.Fatal(err)
				}
				if err := ts.srv.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
					t.Fatal(err)
				}
				return access, refresh
			}
			access, refresh := pair(cimdTestClientID)
			_, refreshOnly := pair(cimdTestClientID)
			registeredAccess, registeredRefresh := pair(ts.clientID)

			// Two codes: one is exchanged while the client is accepted, to
			// show that nothing but the client stands in the way later.
			good := ts.loginForCode(cimdTestClientID, "s1")
			login := ts.loginForCode(cimdTestClientID, "s2")
			if w := ts.exchangeCode(t, good, cimdTestClientID); w.Code != http.StatusOK {
				t.Fatalf("code exchange while the client is accepted: status %d, body %s", w.Code, w.Body.String())
			}
			if w := ts.mcpCall("Bearer " + access); strings.Contains(w.Body.String(), "Unauthorized") {
				t.Fatal("the access token must be accepted while the client is")
			}

			revoke(ts.srv.cfg)

			if w := ts.mcpCall("Bearer " + access); !strings.Contains(w.Body.String(), "Unauthorized") {
				t.Error("the access token was still accepted")
			}
			// The pair ended as a whole.
			if w := ts.token(url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {refresh}, oauthClientID: {cimdTestClientID}}); w.Code != http.StatusBadRequest {
				t.Errorf("refresh with the token of the refused access token: status %d, want 400", w.Code)
			}
			if w := ts.token(url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {refreshOnly}, oauthClientID: {cimdTestClientID}}); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "access_token") {
				t.Errorf("refresh: status %d, body %s; want 400 without a token", w.Code, w.Body.String())
			}
			if w := ts.exchangeCode(t, login, cimdTestClientID); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "access_token") {
				t.Errorf("code exchange: status %d, body %s; want 400 without a token", w.Code, w.Body.String())
			}
			if recs := ts.logs.lines(t, "refresh refused: the client is no longer accepted"); len(recs) != 1 {
				t.Errorf("got %d refresh refusal lines, want 1", len(recs))
			}

			if w := ts.mcpCall("Bearer " + registeredAccess); strings.Contains(w.Body.String(), "Unauthorized") {
				t.Error("the access token of a registered client was refused")
			}
			if w := ts.token(url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {registeredRefresh}, oauthClientID: {ts.clientID}}); w.Code != http.StatusOK {
				t.Errorf("refresh of a registered client: status %d, body %s", w.Code, w.Body.String())
			}
		})
	}
}

// TestCIMD_TokenWithoutSignInIsNotHonored pins that the token of a client
// with a metadata URL is worth nothing without the key of its sign-in. No
// code exchange of this version issues such a token. One of the version
// before can, when it shares the token store during an upgrade, and grants
// of kits requested with it would be bound to the URL that every
// installation of the client shares.
func TestCIMD_TokenWithoutSignInIsNotHonored(t *testing.T) {
	ts, _ := newCIMDTestServer(t, nil, serveDocument(cimdTestDocument(cimdTestClientID, nil)))
	ctx := context.Background()

	pair := func(clientID, grantKey string) (access, refresh string) {
		access, refresh = generateID(), generateID()
		ti := &auth.TokenInfo{
			AccessToken: access, RefreshToken: refresh, ClientID: clientID, CallerID: clientID, GrantKey: grantKey,
			UserID: testLoginOwner, ExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(time.Hour),
		}
		if err := ts.srv.tokenStore.SaveToken(ctx, ti); err != nil {
			t.Fatal(err)
		}
		if err := ts.srv.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
			t.Fatal(err)
		}
		return access, refresh
	}
	refreshForm := func(refresh, clientID string) url.Values {
		return url.Values{oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {refresh}, oauthClientID: {clientID}}
	}

	for _, grantKey := range []string{"", "key-0123456789abcdef"} {
		access, _ := pair(cimdTestClientID, grantKey)
		if w := ts.mcpCall("Bearer " + access); !strings.Contains(w.Body.String(), "Unauthorized") {
			t.Errorf("grant key %q: the access token was accepted", grantKey)
		}
		_, refresh := pair(cimdTestClientID, grantKey)
		if w := ts.token(refreshForm(refresh, cimdTestClientID)); w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "access_token") {
			t.Errorf("grant key %q: refresh status %d, body %s; want 400 without a token", grantKey, w.Code, w.Body.String())
		}
	}

	// With the key of a sign-in the same tokens are good, and a registered
	// client needs none.
	for _, tc := range []struct{ clientID, grantKey string }{
		{cimdTestClientID, userctx.GrantKeyLoginPrefix + "0123456789abcdef"},
		{ts.clientID, ""},
	} {
		access, refresh := pair(tc.clientID, tc.grantKey)
		if w := ts.mcpCall("Bearer " + access); strings.Contains(w.Body.String(), "Unauthorized") {
			t.Errorf("client %q: the access token was refused", tc.clientID)
		}
		if w := ts.token(refreshForm(refresh, tc.clientID)); w.Code != http.StatusOK {
			t.Errorf("client %q: refresh status %d, body %s", tc.clientID, w.Code, w.Body.String())
		}
	}
}

// TestRegister_StillWorksNextToMetadataDocuments pins that registration is
// untouched: a client that registers gets an identifier that is no URL, and
// logs in with it while metadata documents are on.
func TestRegister_StillWorksNextToMetadataDocuments(t *testing.T) {
	ts, host := newCIMDTestServer(t, nil, serveDocument(cimdTestDocument(cimdTestClientID, nil)))
	if isClientIDURL(ts.clientID) {
		t.Fatalf("registration handed out a URL as client_id: %q", ts.clientID)
	}
	page := ts.authorizePage(ts.clientID, testLoginRedirect, testLoginAddr)
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(), "ToolMesh read from") {
		t.Errorf("login page of a registered client: status %d", page.Code)
	}
	if w := ts.login(testLoginOwner, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("login of a registered client: status %d", w.Code)
	}
	if n := host.requests(); n != 0 {
		t.Errorf("%d fetches for a registered client", n)
	}
}
