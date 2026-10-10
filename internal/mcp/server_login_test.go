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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

const (
	testLoginRedirect    = "https://example.com/cb"
	testLoginChallenge   = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testLoginRemote      = "203.0.113.7"
	testLoginOtherRemote = "198.51.100.9"
	testLoginAddr        = testLoginRemote + ":40000"
	testLoginOtherAddr   = testLoginOtherRemote + ":40000"
	testLoginSecret      = "correct-horse-battery" //nolint:gosec // test fixture
	testLoginWrong       = "wrong-guess-0001"      //nolint:gosec // test fixture
	testLoginUserAlice   = "alice"
	testLoginOwner       = "owner"
	testLoginAPIKey      = "tm-test-api-key-value" //nolint:gosec // test fixture

	// Level names as slog's JSON handler writes them.
	testLogLevelWarn = "WARN"
	testLogLevelInfo = "INFO"

	testMsgLoginFailed  = "login failed"
	testMsgBearerFailed = "bearer authentication failed"
)

// loginLogBuffer collects log output written from request goroutines.
type loginLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *loginLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// lines returns the JSON log records whose msg equals the given message.
func (b *loginLogBuffer) lines(t *testing.T, msg string) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func (b *loginLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// loginTestServer is a Server with a Redis-backed token store and login
// throttle, metrics and a capturing logger, and one OAuth client already
// registered.
type loginTestServer struct {
	srv      *Server
	mux      *http.ServeMux
	redis    *miniredis.Miniredis
	logs     *loginLogBuffer
	metrics  *metrics.Registry
	clientID string
}

type loginTestOptions struct {
	users   map[string]string // username -> password; nil means single-password mode
	apiKeys []string          // plaintext keys for apikeys.yaml; nil means no file
	// localThrottle leaves the process-local login throttle from NewServer in
	// place, as on a deployment without Redis.
	localThrottle bool
}

// loginTestConfig returns limits small enough to exhaust in a test.
func loginTestConfig() *config.Config {
	return &config.Config{
		AuthPassword:              testLoginSecret,
		AuthUser:                  testLoginOwner,
		AuthPlan:                  "pro",
		AuthRoles:                 "admin",
		Issuer:                    testIssuerToolmesh,
		LoginMaxFailuresPerUserIP: 3,
		LoginMaxFailuresPerUser:   5,
		LoginMaxFailuresPerIP:     7,
		LoginFailureWindow:        900,
	}
}

func newLoginTestServer(t *testing.T, cfg *config.Config, opts loginTestOptions) *loginTestServer {
	t.Helper()

	logs := &loginLogBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo}))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	dir := t.TempDir()
	var userStore *auth.UserStore
	if opts.users != nil {
		content := "users:\n"
		for name, pw := range opts.users {
			hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			content += fmt.Sprintf("  - username: %s\n    password_hash: %q\n    company: example\n    plan: pro\n    roles: [admin]\n", name, hash)
		}
		path := filepath.Join(dir, "users.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		if userStore, err = auth.NewUserStore(path); err != nil {
			t.Fatalf("NewUserStore: %v", err)
		}
	}
	var apiKeys *auth.APIKeyStore
	if opts.apiKeys != nil {
		content := "keys:\n"
		for i, key := range opts.apiKeys {
			hash, err := bcrypt.GenerateFromPassword([]byte(key), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			content += fmt.Sprintf("  - key_hash: %q\n    user_id: key-user-%d\n    company_id: example\n    plan: pro\n    roles: [admin]\n", hash, i)
		}
		path := filepath.Join(dir, "apikeys.yaml")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		if apiKeys, err = auth.NewAPIKeyStore(path); err != nil {
			t.Fatalf("NewAPIKeyStore: %v", err)
		}
	}

	reg := metrics.New(metrics.Options{LabelTool: true})
	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, nil, 120*time.Second, logger, nil, nil)
	handler := NewHandler(exec, mb, nil, "", nil, logger, false)

	srv := NewServer(handler, cfg, logger, auth.NewRedisTokenStore(rdb), userStore, apiKeys, auth.NewDCRRateLimiter(rdb), nil, reg)
	if !opts.localThrottle {
		srv.UseRedisLoginThrottle(rdb)
	}
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	ts := &loginTestServer{srv: srv, mux: mux, redis: mr, logs: logs, metrics: reg}

	regReq := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/register", strings.NewReader(testRegisterBodyExampleCB))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)
	var regResp map[string]any
	if err := json.NewDecoder(regW.Body).Decode(&regResp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	ts.clientID, _ = regResp[oauthClientID].(string)
	if ts.clientID == "" {
		t.Fatalf("no client_id in register response (status %d)", regW.Code)
	}
	return ts
}

// login posts the login form from the given remote address.
func (ts *loginTestServer) login(username, password, remoteAddr string) *httptest.ResponseRecorder {
	return ts.loginAs(ts.clientID, username, password, remoteAddr)
}

func (ts *loginTestServer) loginAs(clientID, username, password, remoteAddr string) *httptest.ResponseRecorder {
	return ts.loginTo(clientID, testLoginRedirect, username, password, remoteAddr)
}

func (ts *loginTestServer) loginTo(clientID, redirectURI, username, password, remoteAddr string) *httptest.ResponseRecorder {
	form := url.Values{
		"username":         {username},
		testFormPassword:   {password},
		oauthClientID:      {clientID},
		oauthRedirectURI:   {redirectURI},
		oauthState:         {"s1"},
		oauthCodeChallenge: {testLoginChallenge},
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// loginCount reads toolmesh_logins_total for one label pair.
func (ts *loginTestServer) loginCount(t *testing.T, method, result string) float64 {
	t.Helper()
	families, err := ts.metrics.PrometheusRegistry().Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "toolmesh_logins_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, lp := range m.GetLabel() {
				labels[lp.GetName()] = lp.GetValue()
			}
			if labels["method"] == method && labels["result"] == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	t.Fatalf("no toolmesh_logins_total series for method=%s result=%s", method, result)
	return 0
}

func isRedirectWithCode(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusFound && strings.Contains(w.Header().Get("Location"), "code=")
}

func TestLogin_WrongPasswordIsLoggedCountedAndAnswered401(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	w := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, msgInvalidCredentials) {
		t.Error("login form should say why the attempt failed")
	}
	// The form must come back complete, so the user can simply try again.
	for _, want := range []string{`name="client_id" value="` + ts.clientID + `"`, `name="code_challenge" value="` + testLoginChallenge + `"`, `name="state" value="s1"`} {
		if !strings.Contains(body, want) {
			t.Errorf("re-rendered form is missing %s", want)
		}
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate = %q; a challenge would make browsers show their own password dialog", got)
	}

	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 1 {
		t.Errorf("password failures = %v, want 1", got)
	}
	if got := ts.loginCount(t, loginMethodPassword, "success"); got != 0 {
		t.Errorf("password successes = %v, want 0", got)
	}

	recs := ts.logs.lines(t, testMsgLoginFailed)
	if len(recs) != 1 {
		t.Fatalf("got %d 'login failed' lines, want 1\n%s", len(recs), ts.logs.String())
	}
	rec := recs[0]
	if rec["level"] != testLogLevelWarn {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["username"] != testLoginUserAlice {
		t.Errorf("username = %v, want %s", rec["username"], testLoginUserAlice)
	}
	if rec[logKeyRemote] != testLoginRemote {
		t.Errorf("remote = %v, want 203.0.113.7", rec[logKeyRemote])
	}
	if rec[logKeyReason] != loginReasonInvalidCredentials {
		t.Errorf("reason = %v, want %s", rec[logKeyReason], loginReasonInvalidCredentials)
	}
	if strings.Contains(ts.logs.String(), testLoginWrong) {
		t.Error("the submitted password must never be logged")
	}
}

func TestLogin_SuccessIsCountedAndNotLoggedAsFailure(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr)
	if !isRedirectWithCode(w) {
		t.Fatalf("status = %d, want a redirect carrying the auth code", w.Code)
	}
	if got := ts.loginCount(t, loginMethodPassword, "success"); got != 1 {
		t.Errorf("password successes = %v, want 1", got)
	}
	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
		t.Errorf("password failures = %v, want 0", got)
	}
	if n := len(ts.logs.lines(t, testMsgLoginFailed)); n != 0 {
		t.Errorf("a successful login wrote %d 'login failed' lines", n)
	}
	if strings.Contains(ts.logs.String(), testLoginSecret) {
		t.Error("the password must never be logged")
	}
}

// The client is checked before the credentials: with an unregistered client
// the password is never looked at, so the endpoint cannot be used to test
// passwords without registering first, and nothing is charged to the limits.
func TestLogin_ClientIsCheckedBeforePassword(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	for _, pw := range []string{testLoginWrong, testLoginSecret} {
		w := ts.loginAs("not-a-registered-client", testLoginUserAlice, pw, testLoginAddr)
		if w.Code != http.StatusBadRequest {
			t.Errorf("unknown client: status = %d, want 400 whatever the password", w.Code)
		}
		if strings.Contains(w.Body.String(), "<form") {
			t.Error("unknown client: must not get the login form back")
		}
	}

	// Far more of these than any limit allows must not lock the login.
	for range 20 {
		ts.loginAs("not-a-registered-client", testLoginUserAlice, testLoginWrong, testLoginAddr)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("valid login after unknown-client requests: status = %d, want redirect", w.Code)
	}

	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
		t.Errorf("password failures = %v, want 0: no credential was checked", got)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if len(recs) != 22 {
		t.Fatalf("got %d 'login failed' lines, want one per rejected request (22)", len(recs))
	}
	for _, rec := range recs {
		if rec[logKeyReason] != loginReasonUnknownClient {
			t.Errorf("reason = %v, want %s", rec[logKeyReason], loginReasonUnknownClient)
		}
	}
}

func TestLogin_RedirectURIIsCheckedBeforePassword(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	const unregistered = "https://attacker.example/cb"

	for _, pw := range []string{testLoginWrong, testLoginSecret} {
		w := ts.loginTo(ts.clientID, unregistered, testLoginUserAlice, pw, testLoginAddr)
		if w.Code != http.StatusBadRequest {
			t.Errorf("unregistered redirect_uri: status = %d, want 400 whatever the password", w.Code)
		}
		if loc := w.Header().Get("Location"); loc != "" {
			t.Errorf("redirected to %q despite an unregistered redirect_uri", loc)
		}
	}

	// More of these than the limits allow must not lock the login.
	for range 2 * cfg.LoginMaxFailuresPerUserIP {
		ts.loginTo(ts.clientID, unregistered, testLoginUserAlice, testLoginWrong, testLoginAddr)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("valid login after bad-redirect requests: status = %d, want redirect", w.Code)
	}

	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
		t.Errorf("password failures = %v, want 0: no credential was checked", got)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if want := 2 + 2*cfg.LoginMaxFailuresPerUserIP; len(recs) != want {
		t.Fatalf("got %d 'login failed' lines, want one per rejected request (%d)", len(recs), want)
	}
	for _, rec := range recs {
		if rec[logKeyReason] != loginReasonInvalidRedirectURI {
			t.Errorf("reason = %v, want %s", rec[logKeyReason], loginReasonInvalidRedirectURI)
		}
	}
}

// Repeated failures are slowed down: once the limit for one account from one
// address is reached, further attempts are refused without the password being
// checked — even the right one — until the window has passed.
func TestLogin_RepeatedFailuresAreThrottled(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	for i := range cfg.LoginMaxFailuresPerUserIP {
		if w := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, w.Code)
		}
	}

	blocked := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr)
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt past the limit: status = %d, want 429", blocked.Code)
	}
	retryAfter, err := strconv.Atoi(blocked.Header().Get("Retry-After"))
	if err != nil || retryAfter < 1 || retryAfter > cfg.LoginFailureWindow {
		t.Errorf("Retry-After = %q, want seconds within the window", blocked.Header().Get("Retry-After"))
	}
	if !strings.Contains(blocked.Body.String(), "Too many failed login attempts") {
		t.Error("the form should explain the lockout")
	}
	if !strings.Contains(blocked.Body.String(), `name="client_id" value="`+ts.clientID+`"`) {
		t.Error("the form must keep the OAuth request so the user can retry after the wait")
	}

	// The correct password does not get through either.
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); w.Code != http.StatusTooManyRequests {
		t.Errorf("correct password during the lockout: status = %d, want 429", w.Code)
	}

	// Every refused attempt is a failed login in the log and the metric.
	want := float64(cfg.LoginMaxFailuresPerUserIP + 2)
	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != want {
		t.Errorf("password failures = %v, want %v", got, want)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if len(recs) != cfg.LoginMaxFailuresPerUserIP+2 {
		t.Fatalf("got %d 'login failed' lines, want exactly one per refused attempt (%d)", len(recs), cfg.LoginMaxFailuresPerUserIP+2)
	}
	if last := recs[len(recs)-1]; last[logKeyReason] != loginReasonThrottledPrefix+auth.LoginScopeUserIP {
		t.Errorf("reason of a throttled attempt = %v, want %s", last[logKeyReason], loginReasonThrottledPrefix+auth.LoginScopeUserIP)
	}

	// The lockout ends with the window.
	ts.redis.FastForward(time.Duration(cfg.LoginFailureWindow+1) * time.Second)
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("after the window: status = %d, want redirect", w.Code)
	}
}

// One hostile address locks only itself out of an account. The account-wide
// ceiling still stops guessing that is spread over many addresses.
func TestLogin_AccountCeilingAcrossAddresses(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	for range cfg.LoginMaxFailuresPerUserIP + 2 {
		ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr)
	}
	// The owner, coming from elsewhere, is not affected by that address.
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginOtherAddr); !isRedirectWithCode(w) {
		t.Fatalf("login from another address: status = %d, want redirect", w.Code)
	}

	// Guessing from a fresh address each time runs into the account ceiling.
	allowed := 0
	for i := range 3 * cfg.LoginMaxFailuresPerUser {
		addr := fmt.Sprintf("192.0.2.%d:40000", i+1)
		if ts.login(testLoginUserAlice, testLoginWrong, addr).Code == http.StatusUnauthorized {
			allowed++
		}
	}
	if allowed != cfg.LoginMaxFailuresPerUser {
		t.Errorf("guesses from distinct addresses that reached the password check: %d, want %d", allowed, cfg.LoginMaxFailuresPerUser)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if last := recs[len(recs)-1]; last[logKeyReason] != loginReasonThrottledPrefix+auth.LoginScopeUser {
		t.Errorf("reason = %v, want %s", last[logKeyReason], loginReasonThrottledPrefix+auth.LoginScopeUser)
	}
}

// In single-password mode the typed username is not part of the credential,
// so varying it must not buy more attempts.
func TestLogin_SinglePasswordModeIgnoresTypedUsernameForLimits(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	reached := 0
	for i := range 4 * cfg.LoginMaxFailuresPerUserIP {
		if ts.login(fmt.Sprintf("name-%d", i), testLoginWrong, testLoginAddr).Code == http.StatusUnauthorized {
			reached++
		}
	}
	if reached != cfg.LoginMaxFailuresPerUserIP {
		t.Errorf("attempts that reached the password check: %d, want %d", reached, cfg.LoginMaxFailuresPerUserIP)
	}
}

// One address trying many accounts is bounded by the per-address limit even
// though no single account's limit is reached.
func TestLogin_PerAddressLimitAcrossAccounts(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}})

	reached := 0
	for i := range 3 * cfg.LoginMaxFailuresPerIP {
		if ts.login(fmt.Sprintf("user-%d", i), testLoginWrong, testLoginAddr).Code == http.StatusUnauthorized {
			reached++
		}
	}
	if reached != cfg.LoginMaxFailuresPerIP {
		t.Errorf("attempts that reached the password check: %d, want %d", reached, cfg.LoginMaxFailuresPerIP)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if last := recs[len(recs)-1]; last[logKeyReason] != loginReasonThrottledPrefix+auth.LoginScopeIP {
		t.Errorf("reason = %v, want %s", last[logKeyReason], loginReasonThrottledPrefix+auth.LoginScopeIP)
	}
}

// An unknown username must be indistinguishable from a wrong password — same
// answer, same lockout — or the login would reveal which accounts exist.
func TestLogin_UnknownUserBehavesLikeWrongPassword(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}})

	known := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr)
	unknown := ts.login("nobody", testLoginWrong, testLoginOtherAddr)
	if known.Code != unknown.Code || known.Body.String() != unknown.Body.String() {
		t.Errorf("known user: %d, unknown user: %d — responses must be identical", known.Code, unknown.Code)
	}

	statuses := func(username, addr string) []int {
		out := make([]int, 0, cfg.LoginMaxFailuresPerUserIP+1)
		for range cfg.LoginMaxFailuresPerUserIP + 1 {
			out = append(out, ts.login(username, testLoginWrong, addr).Code)
		}
		return out
	}
	a, b := statuses(testLoginUserAlice, "192.0.2.10:1"), statuses("nobody", "192.0.2.11:1")
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("lockout differs: known user %v, unknown user %v", a, b)
	}
	if a[len(a)-1] != http.StatusTooManyRequests {
		t.Errorf("last status = %d, want 429", a[len(a)-1])
	}
}

// A successful login clears the account's failures, so a user who mistyped a
// few times is not locked out by one more typo later in the window.
func TestLogin_SuccessClearsAccountFailures(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}})

	for range cfg.LoginMaxFailuresPerUserIP - 1 {
		ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Fatalf("login below the limit: status = %d, want redirect", w.Code)
	}
	for i := range cfg.LoginMaxFailuresPerUserIP - 1 {
		if w := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr); w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d after a successful login: status = %d, want 401 (a fresh allowance)", i+1, w.Code)
		}
	}

	// But the address keeps what it ran up: logging in with one account must
	// not wipe the failures the same address collected. A different username
	// per attempt leaves the per-address counter as the only one that can
	// bind here.
	recorded := 2 * (cfg.LoginMaxFailuresPerUserIP - 1) // alice's failures before and after her login
	want := cfg.LoginMaxFailuresPerIP - recorded
	reached := 0
	for i := range cfg.LoginMaxFailuresPerIP {
		if ts.login(fmt.Sprintf("other-%d", i), testLoginWrong, testLoginAddr).Code == http.StatusUnauthorized {
			reached++
		}
	}
	if reached != want {
		t.Errorf("further attempts from the address that reached the password check: %d, want %d", reached, want)
	}
}

func TestLogin_LongUsernameIsTruncatedInLog(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	ts.login(strings.Repeat("x", 5000), testLoginWrong, testLoginAddr)

	recs := ts.logs.lines(t, testMsgLoginFailed)
	if len(recs) != 1 {
		t.Fatalf("got %d 'login failed' lines, want 1", len(recs))
	}
	if got := len(recs[0]["username"].(string)); got > maxLoggedValueLen+len("…") {
		t.Errorf("logged username is %d bytes, want at most %d", got, maxLoggedValueLen+len("…"))
	}
}

// Password login only exists where a password is configured. A deployment
// that authenticates with API keys alone, or has no credential at all, must
// refuse the login instead of comparing against an empty password.
func TestLogin_RefusedWhenNoPasswordIsConfigured(t *testing.T) {
	configs := map[string]func(*config.Config){
		"api key only":  func(c *config.Config) { c.AuthPassword = ""; c.APIKey = testLoginAPIKey },
		"no credential": func(c *config.Config) { c.AuthPassword = "" },
	}
	for name, mutate := range configs {
		t.Run(name, func(t *testing.T) {
			cfg := loginTestConfig()
			mutate(cfg)
			ts := newLoginTestServer(t, cfg, loginTestOptions{})

			for _, pw := range []string{"", testLoginWrong} {
				w := ts.login(testLoginOwner, pw, testLoginAddr)
				if w.Code != http.StatusForbidden {
					t.Errorf("POST with password %q: status = %d, want 403", pw, w.Code)
				}
				if loc := w.Header().Get("Location"); loc != "" {
					t.Errorf("POST with password %q: issued a redirect to %q", pw, loc)
				}
			}

			get := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				"/authorize?client_id="+ts.clientID+"&redirect_uri="+url.QueryEscape(testLoginRedirect)+"&code_challenge="+testLoginChallenge, nil)
			w := httptest.NewRecorder()
			ts.mux.ServeHTTP(w, get)
			if w.Code != http.StatusForbidden {
				t.Errorf("GET: status = %d, want 403 instead of a login form nobody can pass", w.Code)
			}

			if got := ts.loginCount(t, loginMethodPassword, "success"); got != 0 {
				t.Errorf("password successes = %v, want 0", got)
			}
			if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 0 {
				t.Errorf("password failures = %v, want 0: no credential was checked", got)
			}
			recs := ts.logs.lines(t, testMsgLoginFailed)
			if len(recs) != 2 {
				t.Fatalf("got %d 'login failed' lines, want one per POST (2)", len(recs))
			}
			for _, rec := range recs {
				if rec[logKeyReason] != loginReasonPasswordLoginDisabled {
					t.Errorf("reason = %v, want %s", rec[logKeyReason], loginReasonPasswordLoginDisabled)
				}
			}
		})
	}
}

func TestSecretsEqual(t *testing.T) {
	const configured = testLoginSecret
	tests := []struct {
		submitted, configured string
		want                  bool
	}{
		{configured, configured, true},
		{strings.ToUpper(configured), configured, false},
		{configured[:len(configured)-1], configured, false},
		{configured + "-and-more", configured, false},
		{"", configured, false},
		{"", "", false},
		{"anything", "", false},
	}
	for _, tt := range tests {
		if got := secretsEqual(tt.submitted, tt.configured); got != tt.want {
			t.Errorf("secretsEqual(%q, %q) = %v, want %v", tt.submitted, tt.configured, got, tt.want)
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want int
	}{
		{0, 1},
		{-time.Second, 1},
		{time.Millisecond, 1},
		{time.Second, 1},
		{time.Second + time.Millisecond, 2},
		{899*time.Second + 500*time.Millisecond, 900},
	}
	for _, tt := range tests {
		if got := retryAfterSeconds(tt.in); got != tt.want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestHumanWait(t *testing.T) {
	const oneMinute = "a minute"
	tests := map[int]string{1: oneMinute, 59: oneMinute, 60: oneMinute, 61: "2 minutes", 900: "15 minutes"}
	for in, want := range tests {
		if got := humanWait(in); got != want {
			t.Errorf("humanWait(%d) = %q, want %q", in, got, want)
		}
	}
}

// mcpCall sends an MCP request with the given Authorization header value.
func (ts *loginTestServer) mcpCall(authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// issueToken stores an access token directly and returns it.
func (ts *loginTestServer) issueToken(t *testing.T, expiresAt time.Time) string {
	t.Helper()
	token := generateID()
	err := ts.srv.tokenStore.SaveToken(context.Background(), &auth.TokenInfo{
		AccessToken: token,
		ClientID:    ts.clientID,
		UserID:      testLoginOwner,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	return token
}

func (ts *loginTestServer) bearerFailures(t *testing.T) (apiKey, oauthBearer float64) {
	t.Helper()
	return ts.loginCount(t, loginMethodAPIKey, "failure"), ts.loginCount(t, loginMethodOAuthBearer, "failure")
}

// A rejected bearer is counted exactly once. Which series it lands in follows
// from what it looks like, since a rejected credential does not say which
// method the caller meant.
func TestAuthenticate_RejectedBearerIsCountedOnce(t *testing.T) {
	apiKeyConfigs := map[string]func(*config.Config, *loginTestOptions){
		"TOOLMESH_API_KEY": func(c *config.Config, _ *loginTestOptions) { c.APIKey = testLoginAPIKey },
		"apikeys.yaml":     func(_ *config.Config, o *loginTestOptions) { o.apiKeys = []string{testLoginAPIKey} },
	}
	for name, configure := range apiKeyConfigs {
		t.Run(name, func(t *testing.T) {
			cfg, opts := loginTestConfig(), loginTestOptions{}
			configure(cfg, &opts)
			ts := newLoginTestServer(t, cfg, opts)

			// A wrong API key.
			ts.mcpCall("Bearer not-the-api-key")
			if apiKey, oauth := ts.bearerFailures(t); apiKey != 1 || oauth != 0 {
				t.Errorf("wrong API key: api_key=%v oauth_bearer=%v, want 1 and 0", apiKey, oauth)
			}
			recs := ts.logs.lines(t, testMsgBearerFailed)
			if len(recs) != 1 || recs[0]["level"] != testLogLevelWarn || recs[0][logKeyReason] != loginReasonUnknownCredential || recs[0][logKeyRemote] != testLoginRemote {
				t.Errorf("wrong API key: want one WARN line with reason %s and the remote address, got %v", loginReasonUnknownCredential, recs)
			}
			if strings.Contains(ts.logs.String(), "not-the-api-key") {
				t.Error("the rejected credential must never be logged")
			}

			// Something shaped like an access token issued here, but unknown:
			// what an expired token looks like once the store has dropped it.
			stale := generateID()
			ts.mcpCall("Bearer " + stale)
			if apiKey, oauth := ts.bearerFailures(t); apiKey != 1 || oauth != 1 {
				t.Errorf("unknown token: api_key=%v oauth_bearer=%v, want 1 and 1", apiKey, oauth)
			}
			recs = ts.logs.lines(t, testMsgBearerFailed)
			if last := recs[len(recs)-1]; last["level"] != testLogLevelInfo || last[logKeyReason] != loginReasonUnknownToken {
				t.Errorf("unknown token: want an INFO line with reason %s, got %v", loginReasonUnknownToken, last)
			}
			if strings.Contains(ts.logs.String(), stale) {
				t.Error("the rejected token must never be logged")
			}

			// A token the store still has, past its expiry.
			ts.mcpCall("Bearer " + ts.issueToken(t, time.Now().Add(-time.Minute)))
			if apiKey, oauth := ts.bearerFailures(t); apiKey != 1 || oauth != 2 {
				t.Errorf("expired token: api_key=%v oauth_bearer=%v, want 1 and 2", apiKey, oauth)
			}
			recs = ts.logs.lines(t, testMsgBearerFailed)
			if last := recs[len(recs)-1]; last["level"] != testLogLevelInfo || last[logKeyReason] != loginReasonExpiredToken {
				t.Errorf("expired token: want an INFO line with reason %s, got %v", loginReasonExpiredToken, last)
			}
		})
	}
}

// Requests that are accepted, or carry no credential at all, are not failures:
// a valid OAuth token on a deployment that also has API keys fails the API-key
// check on its way to the token lookup, and that must not be counted.
func TestAuthenticate_AcceptedAndAnonymousRequestsCountNoFailure(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{apiKeys: []string{testLoginAPIKey}})

	if w := ts.mcpCall("Bearer " + ts.issueToken(t, time.Now().Add(time.Hour))); strings.Contains(w.Body.String(), "Unauthorized") {
		t.Fatal("valid OAuth token was rejected")
	}
	if w := ts.mcpCall("Bearer " + testLoginAPIKey); strings.Contains(w.Body.String(), "Unauthorized") {
		t.Fatal("valid API key was rejected")
	}
	ts.mcpCall("")                         // no credential
	ts.mcpCall("Basic dXNlcjpwYXNzd29yZA") // not a bearer credential

	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 0 {
		t.Errorf("failures: api_key=%v oauth_bearer=%v, want 0 and 0", apiKey, oauth)
	}
	if got := ts.loginCount(t, loginMethodOAuthBearer, "success"); got != 1 {
		t.Errorf("oauth_bearer successes = %v, want 1", got)
	}
	if got := ts.loginCount(t, loginMethodAPIKey, "success"); got != 1 {
		t.Errorf("api_key successes = %v, want 1", got)
	}
	if n := len(ts.logs.lines(t, testMsgBearerFailed)); n != 0 {
		t.Errorf("%d 'bearer authentication failed' lines for accepted or anonymous requests", n)
	}
}

// Without any API-key authentication there is only one method a bearer can
// have been meant for, so every rejected one is an oauth_bearer failure.
func TestAuthenticate_RejectedBearerWithoutAPIKeys(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	ts.mcpCall("Bearer some-made-up-value")
	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 1 {
		t.Errorf("failures: api_key=%v oauth_bearer=%v, want 0 and 1", apiKey, oauth)
	}
	recs := ts.logs.lines(t, testMsgBearerFailed)
	if len(recs) != 1 || recs[0]["level"] != testLogLevelWarn {
		t.Errorf("a value that cannot be an expired token should be logged at WARN, got %v", recs)
	}
}

// isIssuedTokenShape has to keep recognizing what generateID produces, or
// expired tokens would start showing up as failed API keys.
func TestIsIssuedTokenShape(t *testing.T) {
	for range 20 {
		if id := generateID(); !isIssuedTokenShape(id) {
			t.Fatalf("generateID() = %q is not recognized as an issued token", id)
		}
	}
	for _, v := range []string{"", "short", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("g", 64), testLoginAPIKey} {
		if isIssuedTokenShape(v) {
			t.Errorf("isIssuedTokenShape(%q) = true, want false", v)
		}
	}
}

// With no authentication configured a request is anonymous whatever it sends
// along; a stale bearer on it is not a failed login.
func TestAuthenticate_StaleBearerWithoutAuthIsNotAFailure(t *testing.T) {
	cfg := loginTestConfig()
	cfg.AuthPassword = ""
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	ts.mcpCall("Bearer " + generateID())

	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 0 {
		t.Errorf("failures: api_key=%v oauth_bearer=%v, want 0 and 0", apiKey, oauth)
	}
	if n := len(ts.logs.lines(t, testMsgBearerFailed)); n != 0 {
		t.Errorf("%d 'bearer authentication failed' lines although the request was not rejected", n)
	}
}

func TestLogin_AnswerIsNotCacheable(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})

	for _, pw := range []string{testLoginWrong, testLoginSecret} {
		if got := ts.login(testLoginUserAlice, pw, testLoginAddr).Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", got)
		}
	}
}

// Without Redis the limits must hold just the same: this is the throttle
// NewServer installs, which a deployment without Redis runs on.
func TestLogin_ThrottledWithProcessLocalCounters(t *testing.T) {
	cfg := loginTestConfig()
	ts := newLoginTestServer(t, cfg, loginTestOptions{localThrottle: true})

	got := make([]int, 0, cfg.LoginMaxFailuresPerUserIP+1)
	for range cfg.LoginMaxFailuresPerUserIP + 1 {
		got = append(got, ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr).Code)
	}
	want := []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); w.Code != http.StatusTooManyRequests {
		t.Errorf("correct password during the lockout: status = %d, want 429", w.Code)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginOtherAddr); !isRedirectWithCode(w) {
		t.Errorf("login from another address: status = %d, want redirect", w.Code)
	}
}

// A deployment with users.yaml and no single password is a password
// deployment like any other.
func TestLogin_UsersFileWithoutSinglePassword(t *testing.T) {
	cfg := loginTestConfig()
	cfg.AuthPassword = ""
	ts := newLoginTestServer(t, cfg, loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}})

	get := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"/authorize?client_id="+ts.clientID+"&redirect_uri="+url.QueryEscape(testLoginRedirect)+"&code_challenge="+testLoginChallenge, nil)
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, get)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<form") {
		t.Errorf("GET: status = %d, want the login form", w.Code)
	}

	if w := ts.login(testLoginUserAlice, testLoginWrong, testLoginAddr); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status = %d, want 401", w.Code)
	}
	if w := ts.login(testLoginUserAlice, testLoginSecret, testLoginAddr); !isRedirectWithCode(w) {
		t.Errorf("right password: status = %d, want redirect", w.Code)
	}
}

// The failed-login record and counter must not depend on the mode: with
// users.yaml a wrong password and an unknown user each leave one WARN line
// and one failure.
func TestLogin_FailureIsLoggedAndCountedWithUsersFile(t *testing.T) {
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{users: map[string]string{testLoginUserAlice: testLoginSecret}})

	attempts := []struct{ username, addr, remote string }{
		{testLoginUserAlice, testLoginAddr, testLoginRemote},
		{"nobody", testLoginOtherAddr, testLoginOtherRemote},
	}
	for _, a := range attempts {
		if w := ts.login(a.username, testLoginWrong, a.addr); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", a.username, w.Code)
		}
	}

	if got := ts.loginCount(t, loginMethodPassword, "failure"); got != 2 {
		t.Errorf("password failures = %v, want 2", got)
	}
	recs := ts.logs.lines(t, testMsgLoginFailed)
	if len(recs) != len(attempts) {
		t.Fatalf("got %d 'login failed' lines, want %d", len(recs), len(attempts))
	}
	for i, a := range attempts {
		rec := recs[i]
		if rec["level"] != testLogLevelWarn || rec["username"] != a.username || rec[logKeyRemote] != a.remote || rec[logKeyReason] != loginReasonInvalidCredentials {
			t.Errorf("record %d = %v, want WARN with username %s, remote %s and reason %s", i, rec, a.username, a.remote, loginReasonInvalidCredentials)
		}
	}
	if strings.Contains(ts.logs.String(), testLoginWrong) {
		t.Error("the submitted password must never be logged")
	}
}

// Where no access tokens are issued, a rejected bearer can only have been
// meant as an API key, whatever it looks like — keys are often generated as
// 64 hex characters, the form of an access token.
func TestAuthenticate_RejectedBearerWithAPIKeysOnly(t *testing.T) {
	apiKeyConfigs := map[string]func(*config.Config, *loginTestOptions){
		"TOOLMESH_API_KEY": func(c *config.Config, _ *loginTestOptions) { c.APIKey = testLoginAPIKey },
		"apikeys.yaml":     func(_ *config.Config, o *loginTestOptions) { o.apiKeys = []string{testLoginAPIKey} },
	}
	for name, configure := range apiKeyConfigs {
		t.Run(name, func(t *testing.T) {
			cfg, opts := loginTestConfig(), loginTestOptions{}
			cfg.AuthPassword = ""
			configure(cfg, &opts)
			ts := newLoginTestServer(t, cfg, opts)

			ts.mcpCall("Bearer " + generateID())

			if apiKey, oauth := ts.bearerFailures(t); apiKey != 1 || oauth != 0 {
				t.Errorf("failures: api_key=%v oauth_bearer=%v, want 1 and 0", apiKey, oauth)
			}
			recs := ts.logs.lines(t, testMsgBearerFailed)
			if len(recs) != 1 || recs[0]["level"] != testLogLevelWarn || recs[0][logKeyReason] != loginReasonUnknownCredential {
				t.Errorf("want one WARN line with reason %s, got %v", loginReasonUnknownCredential, recs)
			}
		})
	}
}

// failingTokenStore answers every token lookup with an error that is not
// "not found".
type failingTokenStore struct {
	auth.TokenStore
}

func (failingTokenStore) GetToken(context.Context, string) (*auth.TokenInfo, error) {
	return nil, fmt.Errorf("store unavailable")
}

// When the token store itself fails, the credential was not judged: the
// request is turned away, but that is a server error, not a failed login.
func TestAuthenticate_TokenStoreErrorIsNotALoginFailure(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	ts.srv.tokenStore = failingTokenStore{ts.srv.tokenStore}

	w := ts.mcpCall("Bearer " + generateID())
	if !strings.Contains(w.Body.String(), "Unauthorized") {
		t.Errorf("request was not turned away: %s", w.Body.String())
	}
	if apiKey, oauth := ts.bearerFailures(t); apiKey != 0 || oauth != 0 {
		t.Errorf("failures: api_key=%v oauth_bearer=%v, want 0 and 0", apiKey, oauth)
	}
	if n := len(ts.logs.lines(t, testMsgBearerFailed)); n != 0 {
		t.Errorf("%d 'bearer authentication failed' lines for a store error", n)
	}
	recs := ts.logs.lines(t, "token lookup failed")
	if len(recs) != 1 || recs[0]["level"] != "ERROR" {
		t.Errorf("want one ERROR line 'token lookup failed', got %v", recs)
	}
}

// token posts a grant to /token and returns the response.
func (ts *loginTestServer) token(form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = testLoginAddr
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// Access and refresh tokens come out of the password login. Where there is no
// password login — the password was removed, or the deployment never had one
// — tokens still sitting in the store must not open anything, and must not be
// renewable.
func TestOAuth_TokensAreNotHonoredWithoutPasswordLogin(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	ts := newLoginTestServer(t, cfg, loginTestOptions{})

	access := ts.issueToken(t, time.Now().Add(time.Hour))
	refresh := generateID()
	if err := ts.srv.tokenStore.SaveRefreshToken(context.Background(), &auth.TokenInfo{
		AccessToken: access, RefreshToken: refresh, ClientID: ts.clientID, UserID: testLoginOwner, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	login := ts.login(testLoginOwner, testLoginSecret, testLoginAddr)
	if !isRedirectWithCode(login) {
		t.Fatalf("login: status = %d, want redirect", login.Code)
	}
	loc, _ := url.Parse(login.Header().Get("Location"))
	code := loc.Query().Get(argNameCode)

	if w := ts.mcpCall("Bearer " + access); strings.Contains(w.Body.String(), "Unauthorized") {
		t.Fatal("with a password login configured the token must be accepted")
	}

	// The password goes away; API-key authentication stays.
	cfg.AuthPassword = ""

	if w := ts.mcpCall("Bearer " + access); !strings.Contains(w.Body.String(), "Unauthorized") {
		t.Error("access token was still accepted without a password login")
	}
	if w := ts.mcpCall("Bearer " + testLoginAPIKey); strings.Contains(w.Body.String(), "Unauthorized") {
		t.Error("the API key must keep working")
	}

	grants := map[string]url.Values{
		loginMethodOAuthRefresh: {oauthGrantType: {oauthRefreshToken}, oauthRefreshToken: {refresh}, oauthClientID: {ts.clientID}},
		loginMethodOAuthCode:    {oauthGrantType: {oauthGrantAuthCode}, argNameCode: {code}, oauthClientID: {ts.clientID}},
	}
	for method, form := range grants {
		w := ts.token(form)
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "access_token") {
			t.Errorf("%s grant: status = %d, body %s; want 400 without a token", method, w.Code, w.Body.String())
		}
		if got := ts.loginCount(t, method, "failure"); got != 1 {
			t.Errorf("%s failures = %v, want 1", method, got)
		}
	}
	recs := ts.logs.lines(t, "token grant refused")
	if len(recs) != len(grants) {
		t.Fatalf("got %d 'token grant refused' lines, want %d", len(recs), len(grants))
	}
	for _, rec := range recs {
		if rec["level"] != testLogLevelWarn || rec[logKeyReason] != loginReasonPasswordLoginDisabled || rec[logKeyRemote] != testLoginRemote {
			t.Errorf("record = %v, want WARN with reason %s and the remote address", rec, loginReasonPasswordLoginDisabled)
		}
	}

	// The refused refresh did not consume the token: with the password back,
	// the session continues.
	cfg.AuthPassword = testLoginSecret
	if w := ts.token(grants[loginMethodOAuthRefresh]); w.Code != http.StatusOK {
		t.Errorf("refresh after the password is configured again: status = %d, want 200", w.Code)
	}
}
