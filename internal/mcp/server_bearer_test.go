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
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
)

const (
	testMetadataURLOfMCP = "https://toolmesh.io/.well-known/oauth-protected-resource/mcp"
	testChallengeNoToken = `Bearer realm="toolmesh", resource_metadata="` + testMetadataURLOfMCP + `"`
	testChallengeInvalid = `Bearer realm="toolmesh", error="invalid_token", resource_metadata="` + testMetadataURLOfMCP + `"`

	testMsgMCPRejected  = "mcp request rejected: unauthorized"
	testMsgAuthDeferred = "authentication deferred: no password hash comparison could be started"

	testHeaderChallenge  = "WWW-Authenticate"
	testHeaderRetryAfter = "Retry-After"

	// testNoWait is the deadline of a request that is expected to wait for a
	// bcrypt comparison slot it cannot get. Everything the request does before
	// it starts waiting has to fit in, on a busy machine as well.
	testNoWait = 150 * time.Millisecond
	// testNoNeedToWait is the deadline of a request that must be answered
	// without any bcrypt comparison. It is generous: nothing waits for it
	// unless the request does ask for a comparison, which is the failure.
	testNoNeedToWait = 4 * time.Second
)

// mcpCallCtx is mcpCall with a request context.
func (ts *loginTestServer) mcpCallCtx(ctx context.Context, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, pathMCP, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// mcpCallWithin sends an MCP request that gives up after d.
func (ts *loginTestServer) mcpCallWithin(d time.Duration, authorization string) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return ts.mcpCallCtx(ctx, authorization)
}

// mcpCallNoComparison sends an MCP request while no bcrypt comparison can
// start, and fails the test if the request asked for one. A request that
// does waits for a slot until its deadline, whatever it answers afterwards,
// so the time it took tells: without a comparison the answer is there in
// well under a millisecond.
func (ts *loginTestServer) mcpCallNoComparison(t *testing.T, authorization string) *httptest.ResponseRecorder {
	t.Helper()
	start := time.Now()
	w := ts.mcpCallWithin(testNoNeedToWait, authorization)
	if took := time.Since(start); took > testNoNeedToWait/2 {
		t.Errorf("the answer took %v: the request waited for a bcrypt comparison", took)
	}
	return w
}

// loginWithin posts the login form with a request that gives up after d.
func (ts *loginTestServer) loginWithin(d time.Duration, username, password string) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	form := url.Values{
		"username":         {username},
		testFormPassword:   {password},
		oauthClientID:      {ts.clientID},
		oauthRedirectURI:   {testLoginRedirect},
		oauthState:         {"s1"},
		oauthCodeChallenge: {testLoginChallenge},
	}
	req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// holdCompareSlots takes every slot of the limiter, so that no bcrypt
// comparison can start until the returned function is called.
func holdCompareSlots(t *testing.T, l *auth.CompareLimiter) (release func()) {
	t.Helper()
	done := make(chan struct{})
	var wg sync.WaitGroup
	for range l.Capacity() {
		started := make(chan struct{})
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Do(context.Background(), func() {
				close(started)
				<-done
			})
		}()
		<-started
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
	t.Cleanup(release)
	return release
}

// jsonRPCError decodes the JSON-RPC error of a response body.
func jsonRPCError(t *testing.T, w *httptest.ResponseRecorder) (code float64, message string) {
	t.Helper()
	var resp struct {
		Error struct {
			Code    float64 `json:"code"`
			Message string  `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body is not JSON: %q", w.Body.String())
	}
	return resp.Error.Code, resp.Error.Message
}

// Without a valid credential /mcp answers 401 with a Bearer challenge that
// names the protected resource metadata of the endpoint. Clients start or
// refresh an authorization on that status, not on the JSON-RPC error.
func TestMCP_UnauthorizedIs401WithBearerChallenge(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{apiKeys: []string{testLoginAPIKey}})

	rejected := []struct {
		name          string
		authorization string
		wantChallenge string
	}{
		{"no credential", "", testChallengeNoToken},
		{"not a bearer credential", "Basic dXNlcjpwYXNzd29yZA", testChallengeNoToken},
		{"empty bearer", "Bearer ", testChallengeNoToken},
		{"unknown bearer", "Bearer not-a-credential", testChallengeInvalid},
		{"unknown token", "Bearer " + generateID(), testChallengeInvalid},
		{"expired token", "Bearer " + ts.issueToken(t, time.Now().Add(-time.Minute)), testChallengeInvalid},
	}
	for _, tt := range rejected {
		t.Run(tt.name, func(t *testing.T) {
			w := ts.mcpCall(tt.authorization)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", w.Code)
			}
			if got := w.Header().Get(testHeaderChallenge); got != tt.wantChallenge {
				t.Errorf("WWW-Authenticate = %q\n                    want %q", got, tt.wantChallenge)
			}
			if got := w.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			// The body is what it was before the status changed.
			if code, message := jsonRPCError(t, w); code != -32001 || message != "Unauthorized" {
				t.Errorf("JSON-RPC error = %v %q, want -32001 \"Unauthorized\"", code, message)
			}
		})
	}

	accepted := map[string]string{
		"API key":      "Bearer " + testLoginAPIKey,
		"access token": "Bearer " + ts.issueToken(t, time.Now().Add(time.Hour)),
	}
	for name, authorization := range accepted {
		t.Run(name, func(t *testing.T) {
			w := ts.mcpCall(authorization)
			if w.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", w.Code)
			}
			if got := w.Header().Get(testHeaderChallenge); got != "" {
				t.Errorf("WWW-Authenticate = %q on an accepted request", got)
			}
		})
	}
}

// The challenge has to lead a client to metadata it accepts: the document at
// the URL in resource_metadata must name the MCP endpoint as its resource,
// because clients compare that value with the URL they connect to.
func TestMCP_ChallengeLeadsToMetadataOfTheEndpoint(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	challenge := ts.mcpCall("").Header().Get(testHeaderChallenge)
	// The pattern MCP clients use to read the parameter.
	m := regexp.MustCompile(`resource_metadata=(?:"([^"]+)"|([^\s,]+))`).FindStringSubmatch(challenge)
	if m == nil {
		t.Fatalf("no resource_metadata in %q", challenge)
	}
	metadataURL, err := url.Parse(m[1])
	if err != nil {
		t.Fatalf("resource_metadata %q is not a URL: %v", m[1], err)
	}
	issuer := strings.TrimRight(testIssuerToolmesh, "/")
	if got := metadataURL.Scheme + "://" + metadataURL.Host; got != issuer {
		t.Errorf("resource_metadata points to %s, want the issuer %s", got, issuer)
	}
	// RFC 9728, section 3.1: the well-known part goes in front of the path
	// of the resource.
	if want := "/.well-known/oauth-protected-resource" + pathMCP; metadataURL.Path != want {
		t.Errorf("resource_metadata path = %s, want %s", metadataURL.Path, want)
	}

	get := func(path string) map[string]any {
		t.Helper()
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200", path, w.Code)
		}
		var doc map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("GET %s: body is not JSON: %q", path, w.Body.String())
		}
		return doc
	}

	doc := get(metadataURL.Path)
	if got, want := doc["resource"], issuer+pathMCP; got != want {
		t.Errorf("resource = %v, want %s (the URL of the MCP endpoint)", got, want)
	}
	if got := fmt.Sprint(doc["authorization_servers"]); got != "["+testIssuerToolmesh+"]" {
		t.Errorf("authorization_servers = %s, want [%s]", got, testIssuerToolmesh)
	}

	// The document at the root is the one clients have always been served.
	if got := get("/.well-known/oauth-protected-resource")["resource"]; got != testIssuerToolmesh {
		t.Errorf("root document: resource = %v, want %s as before", got, testIssuerToolmesh)
	}
}

// A request without any credential is visible: one INFO line and one count,
// under a method of its own so that it is not mistaken for a failed login.
func TestMCP_AnonymousRequestIsLoggedAndCounted(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	anonymous := func() float64 { return ts.loginCount(t, loginMethodAnonymous, "failure") }

	ts.mcpCall("")
	ts.mcpCall("Basic dXNlcjpwYXNzd29yZA")
	if got := anonymous(); got != 2 {
		t.Errorf("anonymous failures = %v, want 2", got)
	}
	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 0 {
		t.Errorf("a request without a credential was counted as a failed login: api_key=%v oauth_bearer=%v", apiKey, oauth)
	}
	recs := ts.logs.lines(t, testMsgMCPRejected)
	if len(recs) != 2 {
		t.Fatalf("got %d %q lines at INFO or above, want 2", len(recs), testMsgMCPRejected)
	}
	for _, rec := range recs {
		if rec["level"] != testLogLevelInfo || rec[logKeyRemote] != testLoginRemote || rec[logKeyCredential] != credentialNone {
			t.Errorf("record = %v, want INFO with remote %s and credential %s", rec, testLoginRemote, credentialNone)
		}
	}

	// A rejected bearer is a failed login of its method, not an anonymous
	// request; its line says so.
	ts.mcpCall("Bearer not-the-api-key")
	if got := anonymous(); got != 2 {
		t.Errorf("anonymous failures = %v after a rejected bearer, want still 2", got)
	}
	if apiKey, _ := ts.bearerFailures(t); apiKey != 1 {
		t.Errorf("api_key failures = %v, want 1", apiKey)
	}
	recs = ts.logs.lines(t, testMsgMCPRejected)
	if last := recs[len(recs)-1]; len(recs) != 3 || last[logKeyCredential] != credentialRejected || last[logKeyRemote] != testLoginRemote {
		t.Errorf("rejected bearer: want a third line with credential %s, got %v", credentialRejected, recs)
	}
	if strings.Contains(ts.logs.String(), "not-the-api-key") {
		t.Error("the rejected credential must never be logged")
	}

	// An accepted request leaves neither.
	ts.mcpCall("Bearer " + testLoginAPIKey)
	if got, n := anonymous(), len(ts.logs.lines(t, testMsgMCPRejected)); got != 2 || n != 3 {
		t.Errorf("after an accepted request: anonymous failures = %v, lines = %d; want 2 and 3", got, n)
	}

	// The other authenticated endpoints count the same way.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/files/upload", http.NoBody)
	rec := httptest.NewRecorder()
	if ts.srv.requireAuth(rec, req) || rec.Code != http.StatusUnauthorized {
		t.Errorf("requireAuth without a credential: status = %d, want 401", rec.Code)
	}
	if got := anonymous(); got != 3 {
		t.Errorf("anonymous failures = %v after an upload without a credential, want 3", got)
	}
	// Only rejections are counted under this method.
	if got := ts.loginCount(t, loginMethodAnonymous, "success"); got != 0 {
		t.Errorf("anonymous successes = %v, want 0", got)
	}
}

// The count is of requests that were turned away. A server without any
// authentication configured turns nobody away, so it counts and logs nothing
// here, whatever the request carries.
func TestMCP_ServerWithoutAuthenticationCountsNoAnonymousFailure(t *testing.T) {
	cfg := loginTestConfig()
	cfg.AuthPassword = ""
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	for _, authorization := range []string{"", "Bearer " + generateID()} {
		w := ts.mcpCall(authorization)
		if w.Code != http.StatusOK || w.Header().Get(testHeaderChallenge) != "" {
			t.Errorf("authorization %q: status = %d, WWW-Authenticate = %q; want 200 and no challenge", authorization, w.Code, w.Header().Get(testHeaderChallenge))
		}
	}
	for _, result := range []string{"success", "failure"} {
		if got := ts.loginCount(t, loginMethodAnonymous, result); got != 0 {
			t.Errorf("anonymous %s = %v, want 0", result, got)
		}
	}
	if n := len(ts.logs.lines(t, testMsgMCPRejected)); n != 0 {
		t.Errorf("%d rejection lines on a server that turns nobody away", n)
	}
}

// A request must not be able to make the server run
// bcrypt unless a comparison is the only way left to tell. With every
// comparison slot taken, nothing that needs bcrypt can be answered, so
// whatever is answered here was decided without it.
func TestAuthenticate_BcryptOnlyWhereNothingElseDecides(t *testing.T) {
	limiter := auth.NewCompareLimiter(1)
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{
		apiKeys: []string{"bcrypt-key-a", "bcrypt-key-b"}, // as in a file written for earlier versions
		limiter: limiter,
	})

	// First use of one key: found by comparison, and remembered.
	if w := ts.mcpCall("Bearer bcrypt-key-a"); w.Code != http.StatusOK {
		t.Fatalf("first use of an API key: status = %d, want 200", w.Code)
	}
	token := ts.issueToken(t, time.Now().Add(time.Hour))

	release := holdCompareSlots(t, limiter)

	// An access token is looked up before anything is compared, and a key
	// that was seen before is found in the index.
	for name, bearer := range map[string]string{"access token": token, "API key seen before": "bcrypt-key-a"} {
		if w := ts.mcpCallNoComparison(t, "Bearer "+bearer); w.Code != http.StatusOK {
			t.Errorf("%s with no comparison possible: status = %d, want 200", name, w.Code)
		}
	}
	// So is a token the store knows to be expired: it is not a key.
	if w := ts.mcpCallNoComparison(t, "Bearer "+ts.issueToken(t, time.Now().Add(-time.Minute))); w.Code != http.StatusUnauthorized {
		t.Errorf("expired token with no comparison possible: status = %d, want 401", w.Code)
	}

	// One entry has not been seen yet, so a bearer nothing else knows has to
	// be compared against it. That cannot start: the answer is "not now",
	// which is not a verdict on the credential.
	apiKeyBefore, oauthBefore := ts.bearerFailures(t)
	w := ts.mcpCallWithin(testNoWait, "Bearer not-a-credential")
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("comparison that cannot start: status = %d, want 503", w.Code)
	}
	if got := w.Header().Get(testHeaderRetryAfter); got != authUnavailableRetryAfter {
		t.Errorf("Retry-After = %q, want %q", got, authUnavailableRetryAfter)
	}
	if got := w.Header().Get(testHeaderChallenge); got != "" {
		t.Errorf("WWW-Authenticate = %q on a 503; a challenge would make the client drop its credential", got)
	}
	if _, message := jsonRPCError(t, w); message != msgAuthUnavailable {
		t.Errorf("JSON-RPC error message = %q, want %q", message, msgAuthUnavailable)
	}
	if apiKey, oauth := ts.bearerFailures(t); apiKey != apiKeyBefore || oauth != oauthBefore {
		t.Error("a credential that was never checked was counted as a failed login")
	}
	recs := ts.logs.lines(t, testMsgAuthDeferred)
	if len(recs) != 1 || recs[0]["level"] != testLogLevelWarn || recs[0]["method"] != loginMethodAPIKey || recs[0][logKeyRemote] != testLoginRemote {
		t.Errorf("want one WARN line %q with method %s and the remote address, got %v", testMsgAuthDeferred, loginMethodAPIKey, recs)
	}

	// With a slot free the same bearer is checked and rejected, and the key
	// that had not been seen is accepted.
	release()
	if w := ts.mcpCall("Bearer not-a-credential"); w.Code != http.StatusUnauthorized {
		t.Errorf("unknown bearer with a slot free: status = %d, want 401", w.Code)
	}
	if apiKey, _ := ts.bearerFailures(t); apiKey != apiKeyBefore+1 {
		t.Errorf("api_key failures = %v, want %v", apiKey, apiKeyBefore+1)
	}
	if w := ts.mcpCall("Bearer bcrypt-key-b"); w.Code != http.StatusOK {
		t.Errorf("first use of the second key: status = %d, want 200", w.Code)
	}

	// Now every key has been seen. An unknown bearer is rejected without a
	// comparison, like on a file with key_sha256 entries.
	holdCompareSlots(t, limiter)
	for _, bearer := range []string{"not-a-credential", generateID(), strings.Repeat("x", 4096)} {
		if w := ts.mcpCallNoComparison(t, "Bearer "+bearer); w.Code != http.StatusUnauthorized {
			t.Errorf("unknown bearer after every key was seen: status = %d, want 401 without waiting for a comparison", w.Code)
		}
	}
}

// With key_sha256 entries no bearer costs a comparison, from the first request
// on: neither a key nor a value that is none.
func TestAuthenticate_KeySHA256EntriesNeedNoComparison(t *testing.T) {
	limiter := auth.NewCompareLimiter(1)
	keys := []string{"digest-key-a", "digest-key-b", "digest-key-c"}
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{apiKeys: keys, apiKeyDigests: true, limiter: limiter})
	holdCompareSlots(t, limiter)

	for _, bearer := range []string{"not-a-credential", generateID(), "digest-key-d", strings.Repeat("x", 4096)} {
		if w := ts.mcpCallNoComparison(t, "Bearer "+bearer); w.Code != http.StatusUnauthorized {
			t.Errorf("unknown bearer: status = %d, want 401 without waiting for a comparison", w.Code)
		}
	}
	for _, key := range keys {
		if w := ts.mcpCallNoComparison(t, "Bearer "+key); w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", key, w.Code)
		}
	}
	if got := ts.loginCount(t, loginMethodAPIKey, "success"); got != float64(len(keys)) {
		t.Errorf("api_key successes = %v, want %d", got, len(keys))
	}
	if n := len(ts.logs.lines(t, testMsgAuthDeferred)); n != 0 {
		t.Errorf("%d requests waited for a comparison", n)
	}
}

// The bound on bcrypt comparisons covers the password login as well, for a
// known and an unknown username alike. A login that cannot be checked is
// answered "try again": it is not a failed login, is not counted as one, and
// does not use up the attempts the failed-login limits allow.
func TestLogin_ComparisonThatCannotStartIsNotAFailedLogin(t *testing.T) {
	limiter := auth.NewCompareLimiter(1)
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}, limiter: limiter})
	release := holdCompareSlots(t, limiter)

	// For the known user, more attempts than the limit for one account from
	// one address would allow if they were charged; and the unknown user,
	// whose comparison against the dummy hash is bounded all the same.
	const unknownUser = "nobody"
	usernames := make([]string, 0, cfg.LoginMaxFailuresPerUserIP+4)
	usernames = append(usernames, unknownUser, unknownUser)
	for range cfg.LoginMaxFailuresPerUserIP + 2 {
		usernames = append(usernames, testLoginUserAlice)
	}
	attempts := len(usernames)
	for i, username := range usernames {
		w := ts.loginWithin(testNoWait, username, testLoginSecret)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("attempt %d (%s): status = %d, want 503", i+1, username, w.Code)
		}
		if got := w.Header().Get(testHeaderRetryAfter); got != authUnavailableRetryAfter {
			t.Errorf("Retry-After = %q, want %q", got, authUnavailableRetryAfter)
		}
		if body := w.Body.String(); !strings.Contains(body, "<form") || !strings.Contains(body, "busy") {
			t.Errorf("body should be the login form with a note that the server is busy: %q", body)
		}
	}
	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
		t.Errorf("password failures = %v, want 0: no password was checked", got)
	}
	if n := len(ts.logs.lines(t, testMsgLoginFailed)); n != 0 {
		t.Errorf("%d 'login failed' lines although no password was checked", n)
	}
	recs := ts.logs.lines(t, testMsgAuthDeferred)
	if len(recs) != attempts {
		t.Fatalf("got %d %q lines, want %d", len(recs), testMsgAuthDeferred, attempts)
	}
	for _, rec := range recs {
		if rec["level"] != testLogLevelWarn || rec["method"] != loginMethodPassword || rec[logKeyRemote] != testLoginRemote {
			t.Errorf("record = %v, want WARN with method %s and the remote address", rec, loginMethodPassword)
		}
	}
	if strings.Contains(ts.logs.String(), testLoginSecret) {
		t.Error("the submitted password must never be logged")
	}

	// Nothing was charged: the same address still has its full allowance of
	// failed attempts, and the right password still logs in.
	release()
	got := make([]int, 0, cfg.LoginMaxFailuresPerUserIP+1)
	for range cfg.LoginMaxFailuresPerUserIP + 1 {
		got = append(got, ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr).Code)
	}
	want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("wrong passwords after the busy period: statuses = %v, want %v", got, want)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginOtherAddr); !isRedirectWithCode(w) {
		t.Errorf("right password from another address: status = %d, want redirect", w.Code)
	}
}

// The single API key from the environment is accepted for exactly that value.
func TestAuthenticate_SingleAPIKey(t *testing.T) {
	const key = "tm-single-api-key-0123456789abcdef" //nolint:gosec // test fixture
	srv, _ := newTestServer(t, &config.Config{APIKey: key, AuthUser: testLoginOwner})

	tests := []struct {
		name   string
		bearer string
		want   bool
	}{
		{"the key", key, true},
		{"one character short", key[:len(key)-1], false},
		{"one character more", key + "0", false},
		{"same length, last character differs", key[:len(key)-1] + "x", false},
		{"same length, first character differs", "x" + key[1:], false},
		{"upper case", strings.ToUpper(key), false},
		{"a single character", "t", false},
		{"much longer", strings.Repeat(key, 300), false},
		{"with surrounding space", " " + key, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, pathMCP, nil)
			req.Header.Set("Authorization", "Bearer "+tt.bearer)
			uc, err := srv.authenticate(req)
			if err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if uc.Authenticated != tt.want {
				t.Errorf("Authenticated = %v, want %v", uc.Authenticated, tt.want)
			}
			if tt.want && uc.UserID != testLoginOwner {
				t.Errorf("UserID = %q, want %q", uc.UserID, testLoginOwner)
			}
		})
	}
}

// subtle.ConstantTimeCompare answers at once when its arguments differ in
// length, so handing it a configured secret tells a caller how long that
// secret is. Configured secrets are compared through secretsEqual, which
// hashes both sides to the same length first. How long a comparison takes
// cannot be asserted reliably in a test; that no configured value reaches the
// length-revealing comparison can.
func TestConfiguredSecretsAreNotComparedByLength(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	calls := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "ConstantTimeCompare" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "subtle" {
				return true
			}
			calls++
			for _, arg := range call.Args {
				var src strings.Builder
				if err := printer.Fprint(&src, fset, arg); err != nil {
					t.Fatalf("print argument: %v", err)
				}
				if strings.Contains(src.String(), "cfg.") {
					t.Errorf("%s: subtle.ConstantTimeCompare is given the configured value %s; compare it through secretsEqual",
						fset.Position(call.Pos()), src.String())
				}
			}
			return true
		})
	}
	if calls == 0 {
		t.Fatal("found no call to subtle.ConstantTimeCompare: this test no longer looks at anything")
	}
}
