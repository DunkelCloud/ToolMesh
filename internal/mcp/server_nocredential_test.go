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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mcpRequest sends an MCP request with the given JSON-RPC body and
// Authorization header value.
func (ts *loginTestServer) mcpRequest(body, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pathMCP, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// A server without any credential configured (no TOOLMESH_AUTH_PASSWORD,
// TOOLMESH_API_KEY, users.yaml or apikeys.yaml) turns every request away. It
// answers like a server that has a credential and does not know the one
// presented: 401, the same challenge, the same body.
func TestMCP_ServerWithoutCredentialRejectsEveryRequest(t *testing.T) {
	cfg := loginTestConfig()
	cfg.AuthPassword = ""
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	reference := newLoginTestServer(t, loginTestConfig(), loginTestOptions{apiKeys: []string{testLoginAPIKey}})

	bodies := map[string]string{
		"ping":         `{"jsonrpc":"2.0","id":1,"method":"ping"}`,
		"tools/list":   `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		"execute_code": `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_code","arguments":{"code":"return 1"}}}`,
	}
	authorizations := []struct {
		name          string
		authorization string
		wantChallenge string
	}{
		{"no Authorization header", "", testChallengeNoToken},
		{"not a bearer credential", "Basic dXNlcjpwYXNzd29yZA", testChallengeNoToken},
		{"empty bearer", authSchemeBearer + " ", testChallengeNoToken},
		{"unknown bearer", "Bearer not-a-credential", testChallengeInvalid},
		{"token-shaped bearer", authSchemeBearer + " " + generateID(), testChallengeInvalid},
	}

	var withoutBearer int
	for method, body := range bodies {
		for _, a := range authorizations {
			if extractBearer(&http.Request{Header: http.Header{"Authorization": {a.authorization}}}) == "" {
				withoutBearer++
			}
			t.Run(method+"/"+a.name, func(t *testing.T) {
				w := ts.mcpRequest(body, a.authorization)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("status = %d, want 401; body %s", w.Code, w.Body.String())
				}
				if got := w.Header().Get(testHeaderChallenge); got != a.wantChallenge {
					t.Errorf("WWW-Authenticate = %q\n                    want %q", got, a.wantChallenge)
				}
				want := reference.mcpRequest(body, a.authorization)
				if w.Code != want.Code || w.Header().Get(testHeaderChallenge) != want.Header().Get(testHeaderChallenge) ||
					w.Header().Get("Content-Type") != want.Header().Get("Content-Type") || w.Body.String() != want.Body.String() {
					t.Errorf("answer differs from a server with a credential:\n got %d %q %q %s\nwant %d %q %q %s",
						w.Code, w.Header().Get(testHeaderChallenge), w.Header().Get("Content-Type"), w.Body.String(),
						want.Code, want.Header().Get(testHeaderChallenge), want.Header().Get("Content-Type"), want.Body.String())
				}
			})
		}
	}

	// The other authenticated endpoints (file upload, blob deletion) as well.
	for _, a := range authorizations {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", http.NoBody)
		if a.authorization != "" {
			req.Header.Set("Authorization", a.authorization)
		}
		rec := httptest.NewRecorder()
		if ts.srv.requireAuth(rec, req) || rec.Code != http.StatusUnauthorized {
			t.Errorf("requireAuth, %s: status = %d, want 401", a.name, rec.Code)
		}
		if extractBearer(req) == "" {
			withoutBearer++
		}
	}

	// A request without a credential is counted and logged as on any other
	// server. A bearer is no failed login of a method: there is none that
	// could have accepted it.
	if got := ts.loginCount(t, loginMethodAnonymous, "failure"); got != float64(withoutBearer) {
		t.Errorf("anonymous failures = %v, want %d", got, withoutBearer)
	}
	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 0 {
		t.Errorf("failed logins: api_key=%v oauth_bearer=%v, want 0 and 0", apiKey, oauth)
	}
	if n, want := len(ts.logs.lines(t, testMsgMCPRejected)), len(bodies)*len(authorizations); n != want {
		t.Errorf("%d %q lines, want %d", n, testMsgMCPRejected, want)
	}
}

// An API key configured as the empty string can never be presented: an empty
// bearer credential is no credential at all. The file still counts as
// configured authentication, so such a server rejects every request. This
// pins the behavior as it is; it is not changed.
func TestMCP_EmptyAPIKeyIsNeverAccepted(t *testing.T) {
	for name, digests := range map[string]bool{"bcrypt hash": false, "SHA-256 digest": true} {
		t.Run(name, func(t *testing.T) {
			cfg := loginTestConfig()
			cfg.AuthPassword = ""
			ts := newLoginTestServer(t, cfg, loginTestOptions{apiKeys: []string{""}, apiKeyDigests: digests})

			for _, authorization := range []string{"", authSchemeBearer + " ", authSchemeBearer} {
				w := ts.mcpCall(authorization)
				if w.Code != http.StatusUnauthorized || w.Header().Get(testHeaderChallenge) != testChallengeNoToken {
					t.Errorf("authorization %q: status = %d, WWW-Authenticate = %q; want 401 with %q",
						authorization, w.Code, w.Header().Get(testHeaderChallenge), testChallengeNoToken)
				}
			}
		})
	}
}
