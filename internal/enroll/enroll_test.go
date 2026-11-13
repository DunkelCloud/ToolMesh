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

package enroll

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Fixtures of the credentials page tests.
const (
	tOrigin     = "https://toolmesh.example.com"
	tAlice      = "alice"
	tBob        = "bob"
	tPassword   = "alice-password" //nolint:gosec // test fixture, not a credential
	tBobPass    = "bob-password"   //nolint:gosec // test fixture, not a credential
	tBackend    = "mail"
	tAccount    = "alice@example.com"
	tLogin      = "MAIL_LOGIN"
	tPin        = "MAIL_PIN"
	tSecret     = "app-password-of-alice" //nolint:gosec // test fixture, not a credential
	tPinValue   = "4711-pin-value"
	tChangedPin = "changed-pin"
	tSavePath   = Path + "/save"
	tRemovePath = Path + "/remove"
	tLoginPath  = Path + "/login"
	tLogoutPath = Path + "/logout"
	tFieldLbl   = "label"
	tFieldTok   = "token"
	tFieldBE    = "backend"
	tFieldUser  = "u." + tLogin
	tFieldPass  = "p." + tLogin
	tFieldPin   = "s." + tPin
	tFieldPW    = "password"
	tFieldName  = "username"
	hOrigin     = "Origin"
	hFetchSite  = "Sec-Fetch-Site"
	hRetryAfter = "Retry-After"
	tSameOrigin = "same-origin"
	tEvil       = "https://evil.example.net"
	tInternal   = "http://tm.internal:8123"
	tSignedIn   = "Signed in as"
	tRefused401 = "the API answered HTTP 401"
	// tCSP is the policy the page must send, written out: comparing with
	// the constant of the code would pass whatever the constant says.
	tCSP = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)

// fakeAuth signs in the users of a map and counts the logins it checked.
type fakeAuth struct {
	mu        sync.Mutex
	passwords map[string]string // user → password; the fingerprint is "fp:" + password
	disabled  bool
	busy      bool
	throttled time.Duration
	logins    int
}

func (a *fakeAuth) PasswordLoginEnabled() bool { return !a.disabled }

func (a *fakeAuth) PasswordLogin(_ *http.Request, username, password string) auth.PasswordCheck {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.logins++
	switch {
	case a.disabled:
		return auth.PasswordCheck{Outcome: auth.PasswordDisabled}
	case a.busy:
		return auth.PasswordCheck{Outcome: auth.PasswordBusy}
	case a.throttled > 0:
		return auth.PasswordCheck{Outcome: auth.PasswordThrottled, RetryAfter: a.throttled}
	case a.passwords[username] == "" || a.passwords[username] != password:
		return auth.PasswordCheck{Outcome: auth.PasswordInvalid}
	}
	return auth.PasswordCheck{Outcome: auth.PasswordOK, UserID: username, Fingerprint: "fp:" + password}
}

func (a *fakeAuth) PasswordFingerprint(userID string) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, ok := a.passwords[userID]
	if !ok {
		return "", false
	}
	return "fp:" + p, true
}

// set changes the password of user; an empty password removes the user.
func (a *fakeAuth) set(user, password string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if password == "" {
		delete(a.passwords, user)
		return
	}
	a.passwords[user] = password
}

// auditLog records audit entries. Like the SQLite store it refuses to
// record under a context that has ended.
type auditLog struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
}

func (l *auditLog) Record(ctx context.Context, e audit.AuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, e)
	return nil
}

func (l *auditLog) Query(context.Context, audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, audit.ErrQueryNotSupported
}

func (l *auditLog) Healthy(context.Context) error { return nil }

func (l *auditLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func (l *auditLog) last(t *testing.T) audit.AuditEntry {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) == 0 {
		t.Fatal("no audit entry was recorded")
	}
	return l.entries[len(l.entries)-1]
}

// flakyStore is the user store of a page; failPut makes the n-th PutUser
// from now fail, failDelete every DeleteUser.
type flakyStore struct {
	*credentials.FileUserStore
	mu         sync.Mutex
	failPut    int
	failDelete bool
}

var errStoreDown = errors.New("disk full")

func (s *flakyStore) PutUser(ctx context.Context, slot credentials.UserSlot, value string) error {
	s.mu.Lock()
	fail := false
	if s.failPut > 0 {
		s.failPut--
		fail = s.failPut == 0
	}
	s.mu.Unlock()
	if fail {
		return errStoreDown
	}
	return s.FileUserStore.PutUser(ctx, slot, value)
}

func (s *flakyStore) DeleteUser(ctx context.Context, slot credentials.UserSlot) (bool, error) {
	s.mu.Lock()
	fail := s.failDelete
	s.mu.Unlock()
	if fail {
		return false, errStoreDown
	}
	return s.FileUserStore.DeleteUser(ctx, slot)
}

// failNextPut makes the n-th PutUser from now fail.
func (s *flakyStore) failNextPut(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failPut = n
}

// page is a credentials page under test with everything it talks to.
type page struct {
	t       *testing.T
	handler http.Handler
	dir     string
	store   *flakyStore
	auth    *fakeAuth
	audit   *auditLog
	logs    *bytes.Buffer

	mu  sync.Mutex
	now time.Time
	// check answers the check of a save; nil accepts.
	check   func(ctx context.Context) backend.UserCredentialCheck
	checked []string // "user/backend/account" of every check
	forgot  []string // "user/backend" of every forget
	// denied lists the users the backend is not offered to.
	denied map[string]bool
}

func tKey() []byte { return bytes.Repeat([]byte{3}, credentials.UserCredentialsKeyBytes) }

// newPage builds a page; publicURL is its configured address, "" for none.
func newPage(t *testing.T, publicURL string) *page {
	t.Helper()
	dir := t.TempDir()
	file, err := credentials.NewFileUserStore(dir, tKey())
	if err != nil {
		t.Fatal(err)
	}
	p := &page{
		t:      t,
		dir:    dir,
		store:  &flakyStore{FileUserStore: file},
		auth:   &fakeAuth{passwords: map[string]string{tAlice: tPassword, tBob: tBobPass}},
		audit:  &auditLog{},
		logs:   &bytes.Buffer{},
		now:    time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC),
		denied: map[string]bool{},
	}
	svc, err := New(Options{
		Store: p.store,
		Backends: func() []Backend {
			return []Backend{{
				Name:        tBackend,
				Description: "A mail API",
				Credentials: []backend.UserCredential{
					{Name: "mail_login", Label: "Mailbox login", Hint: "Your address and an app password.", Format: backend.UserCredentialFormatBasic},
					{Name: "mail_pin", Format: backend.UserCredentialFormatSecret},
				},
			}}
		},
		Auth: p.auth,
		Allowed: func(_ context.Context, userID, _ string) bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			return !p.denied[userID]
		},
		Check: func(ctx context.Context, userID, backendName, account string) backend.UserCredentialCheck {
			p.mu.Lock()
			p.checked = append(p.checked, userID+"/"+backendName+"/"+account)
			check := p.check
			p.mu.Unlock()
			if check != nil {
				return check(ctx)
			}
			return backend.UserCredentialCheck{Outcome: backend.UserCheckAccepted, Detail: "HTTP 200"}
		},
		Forget: func(userID, backendName string) {
			p.mu.Lock()
			defer p.mu.Unlock()
			p.forgot = append(p.forgot, userID+"/"+backendName)
		},
		Audit:     p.audit,
		Logger:    slog.New(slog.NewTextHandler(p.logs, nil)),
		Key:       tKey(),
		PublicURL: publicURL,
		Now: func() time.Time {
			p.mu.Lock()
			defer p.mu.Unlock()
			return p.now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.handler = svc.Handler()
	return p
}

func (p *page) advance(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.now = p.now.Add(d)
}

// setCheck makes every check from now on answer with outcome and detail.
func (p *page) setCheck(outcome, detail string) {
	p.setCheckFunc(func(context.Context) backend.UserCredentialCheck {
		return backend.UserCredentialCheck{Outcome: outcome, Detail: detail}
	})
}

func (p *page) setCheckFunc(check func(ctx context.Context) backend.UserCredentialCheck) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.check = check
}

func (p *page) checks() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.checked)
}

func (p *page) forgets() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.forgot)
}

// stored returns what alice has stored under name for the test account.
func (p *page) stored(name string) (string, error) {
	return p.store.GetUser(context.Background(), credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: name})
}

// browser is a client of the page that keeps cookies and says where its
// forms come from, as a browser does.
type browser struct {
	p       *page
	base    string // scheme and host the browser talks to
	origin  string // Origin of its forms; "" sends none
	site    string // Sec-Fetch-Site of its forms; "" sends none
	headers map[string]string
	cookies map[string]string
}

// newBrowser returns a browser on the page's public address that sends the
// Origin of that address with its forms.
func (p *page) newBrowser() *browser {
	return &browser{p: p, base: tOrigin, origin: tOrigin, cookies: map[string]string{}, headers: map[string]string{}}
}

func (b *browser) do(ctx context.Context, method, path string, form url.Values) *httptest.ResponseRecorder {
	b.p.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(ctx, method, b.base+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if b.origin != "" {
			req.Header.Set(hOrigin, b.origin)
		}
		if b.site != "" {
			req.Header.Set(hFetchSite, b.site)
		}
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	for name, value := range b.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value}) //nolint:gosec // G124: a request cookie built by the test
	}
	rec := httptest.NewRecorder()
	b.p.handler.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c.Value
		}
	}
	return rec
}

func (b *browser) get() *httptest.ResponseRecorder {
	return b.do(context.Background(), http.MethodGet, Path, nil)
}

func (b *browser) post(path string, form url.Values) *httptest.ResponseRecorder {
	return b.do(context.Background(), http.MethodPost, path, form)
}

// signIn signs user in and returns the form token of the session.
func (b *browser) signIn(user, password string) string {
	b.p.t.Helper()
	rec := b.post(tLoginPath, url.Values{tFieldName: {user}, tFieldPW: {password}})
	if rec.Code != http.StatusSeeOther {
		b.p.t.Fatalf("sign in: status %d, body %s", rec.Code, rec.Body.String())
	}
	return formToken(b.p.t, b.get().Body.String())
}

// outcome is what a form led to: after the redirect, the page with its
// notice.
type outcome struct {
	body   string
	kind   string
	notice string
}

var noticeRe = regexp.MustCompile(`<p class="notice (\w+)" role="status">([^<]*)</p>`)

// submit posts a form of a signed-in user and follows the redirect to the
// page. Such a form is always answered with a redirect that carries no
// page.
func (b *browser) submit(path string, form url.Values) outcome {
	b.p.t.Helper()
	rec := b.post(path, form)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != Path {
		b.p.t.Fatalf("POST %s: status %d to %q, want a redirect to the page\n%s", path, rec.Code, rec.Header().Get("Location"), rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<main>") {
		b.p.t.Errorf("the redirect of %s carries a page", path)
	}
	out := outcome{body: b.get().Body.String()}
	if m := noticeRe.FindStringSubmatch(out.body); m != nil {
		out.kind, out.notice = m[1], html.UnescapeString(m[2])
	}
	return out
}

var tokenRe = regexp.MustCompile(`name="token" value="([^"]+)"`)

func formToken(t *testing.T, page string) string {
	t.Helper()
	m := tokenRe.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the page carries no form token:\n%s", page)
	}
	return m[1]
}

// saveForm is a save of the account tAccount with both credentials.
func saveForm(token string) url.Values {
	return url.Values{
		tFieldTok:  {token},
		tFieldBE:   {tBackend},
		tFieldLbl:  {tAccount},
		tFieldUser: {tAccount},
		tFieldPass: {tSecret},
		tFieldPin:  {tPinValue},
	}
}

// pinChange changes only the pin of the test account.
func pinChange(token, pin string) url.Values {
	return url.Values{tFieldTok: {token}, tFieldBE: {tBackend}, tFieldLbl: {tAccount}, tFieldPin: {pin}}
}

func removeForm(token, backendName, label string) url.Values {
	return url.Values{tFieldTok: {token}, tFieldBE: {backendName}, tFieldLbl: {label}}
}

// loginForm is alice's login with password.
func loginForm(password string) url.Values {
	return url.Values{tFieldName: {tAlice}, tFieldPW: {password}}
}

func sessionCookieOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, sessionCookie) {
			return c
		}
	}
	return nil
}

func TestPage_LoginAndHeaders(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()

	rec := b.get()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/credentials/login"`) {
		t.Fatalf("anonymous GET: %d\n%s", rec.Code, rec.Body.String())
	}
	h := rec.Header()
	if h.Get("Content-Security-Policy") != tCSP || h.Get("Cache-Control") != "no-store" || h.Get("Referrer-Policy") != tSameOrigin {
		t.Errorf("headers = %v", h)
	}
	if strings.Contains(rec.Body.String(), "<script") {
		t.Error("the page carries a script; its policy allows none")
	}

	// A wrong password does not sign in.
	rec = b.post(tLoginPath, loginForm("wrong"))
	if rec.Code != http.StatusUnauthorized || sessionCookieOf(rec) != nil {
		t.Errorf("wrong password: %d, cookie %v", rec.Code, sessionCookieOf(rec))
	}

	rec = b.post(tLoginPath, loginForm(tPassword))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != Path {
		t.Fatalf("login: %d → %q", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookieOf(rec)
	if c == nil || c.Name != hostPrefix+sessionCookie || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode ||
		c.Path != "/" || c.MaxAge != int(sessionTTL/time.Second) {
		t.Fatalf("session cookie = %+v", c)
	}
	// The cookie is sealed: who signed in is not readable from it.
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || bytes.Contains(raw, []byte(tAlice)) {
		t.Errorf("the session cookie is not sealed (decode error %v)", err)
	}

	body := b.get().Body.String()
	if !strings.Contains(body, tSignedIn+" <strong>"+tAlice+"</strong>") || !strings.Contains(body, "Mailbox login") || !strings.Contains(body, "A mail API") {
		t.Errorf("signed-in page:\n%s", body)
	}

	// Signing out clears the cookie and ends the session: the old cookie,
	// kept by someone, is no session any more.
	old := c.Value
	rec = b.post(tLogoutPath, url.Values{})
	if out := sessionCookieOf(rec); rec.Code != http.StatusSeeOther || out == nil || out.MaxAge >= 0 {
		t.Errorf("logout: %d, cookie %+v", rec.Code, out)
	}
	b.cookies[hostPrefix+sessionCookie] = old
	if strings.Contains(b.get().Body.String(), tSignedIn) {
		t.Error("a signed-out session cookie still signs in")
	}
}

// TestPage_CookiesFollowTheScheme pins the cookie over plain http, where
// neither Secure nor the __Host- prefix can be used, and behind a proxy
// that says the request came over https.
func TestPage_CookiesFollowTheScheme(t *testing.T) {
	p := newPage(t, "")
	b := p.newBrowser()
	b.base, b.origin = tInternal, tInternal
	rec := b.post(tLoginPath, loginForm(tPassword))
	c := sessionCookieOf(rec)
	if rec.Code != http.StatusSeeOther || c == nil || c.Name != sessionCookie || c.Secure || c.Path != Path || !c.HttpOnly {
		t.Fatalf("plain http: %d, cookie %+v", rec.Code, c)
	}
	if !strings.Contains(b.get().Body.String(), tSignedIn) {
		t.Error("the plain-http session does not sign in")
	}

	proxied := p.newBrowser()
	proxied.base, proxied.origin = tInternal, "https://tm.internal:8123"
	proxied.headers["X-Forwarded-Proto"] = "https"
	rec = proxied.post(tLoginPath, loginForm(tPassword))
	c = sessionCookieOf(rec)
	if rec.Code != http.StatusSeeOther || c == nil || c.Name != hostPrefix+sessionCookie || !c.Secure || c.Path != "/" {
		t.Fatalf("behind a TLS proxy: %d, cookie %+v", rec.Code, c)
	}
}

// TestPage_FormsMustComeFromThePage pins that the forms only work when
// sent from the page itself. Another site could otherwise sign a visitor
// in under its own account, and the visitor would store their credentials
// there.
func TestPage_FormsMustComeFromThePage(t *testing.T) {
	login := loginForm(tPassword)

	// With a public address configured, Origin has to be exactly it.
	p := newPage(t, tOrigin)
	for name, origin := range map[string]string{
		"another site": tEvil,
		"no origin":    "",
		"null origin":  "null",
		"other scheme": "http://toolmesh.example.com",
		"other port":   "https://toolmesh.example.com:8443",
	} {
		b := p.newBrowser()
		b.origin = origin
		if rec := b.post(tLoginPath, login); rec.Code != http.StatusForbidden || sessionCookieOf(rec) != nil {
			t.Errorf("%s: %d, cookie %v", name, rec.Code, sessionCookieOf(rec))
		}
	}
	// A request under another host name does not make that name the origin.
	rebound := p.newBrowser()
	rebound.base, rebound.origin = tEvil, tEvil
	if rec := rebound.post(tLoginPath, login); rec.Code != http.StatusForbidden {
		t.Errorf("another Host with a matching Origin: %d", rec.Code)
	}
	// The browser's verdict decides when it is there, whatever Origin says.
	for _, site := range []string{"cross-site", "same-site", "none"} {
		b := p.newBrowser()
		b.site = site
		if rec := b.post(tLoginPath, login); rec.Code != http.StatusForbidden {
			t.Errorf("Sec-Fetch-Site %s with a matching Origin: %d", site, rec.Code)
		}
	}
	if p.auth.logins != 0 {
		t.Errorf("a refused form reached the password check %d times", p.auth.logins)
	}
	// What browsers send with the page's own form: the verdict same-origin,
	// with an Origin of "null" under a strict referrer policy, or none.
	for _, origin := range []string{"null", "", tOrigin} {
		b := p.newBrowser()
		b.site, b.origin = tSameOrigin, origin
		if rec := b.post(tLoginPath, login); rec.Code != http.StatusSeeOther {
			t.Errorf("Sec-Fetch-Site same-origin with Origin %q: %d, want the login to go through", origin, rec.Code)
		}
	}

	// Without a public address, Origin has to name the scheme and host the
	// request arrived with.
	plain := newPage(t, "")
	for origin, want := range map[string]int{
		tInternal:                  http.StatusSeeOther,
		"https://tm.internal:8123": http.StatusForbidden,
		"http://tm.internal":       http.StatusForbidden,
		"http://other.internal":    http.StatusForbidden,
		"":                         http.StatusForbidden,
	} {
		b := plain.newBrowser()
		b.base, b.origin = tInternal, origin
		if rec := b.post(tLoginPath, login); rec.Code != want {
			t.Errorf("no public address, Origin %q: %d, want %d", origin, rec.Code, want)
		}
	}

	// Signing out is a form of the page as well: another site cannot end a
	// session.
	b := p.newBrowser()
	b.signIn(tAlice, tPassword)
	b.origin = tEvil
	if rec := b.post(tLogoutPath, url.Values{}); rec.Code != http.StatusForbidden {
		t.Errorf("logout from another site: %d", rec.Code)
	}
	if !strings.Contains(b.get().Body.String(), tSignedIn) {
		t.Error("a logout from another site ended the session")
	}
}

func TestPage_LoginOutcomes(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	form := loginForm(tPassword)

	p.auth.throttled = 90 * time.Second
	rec := b.post(tLoginPath, form)
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get(hRetryAfter) != "90" || !strings.Contains(rec.Body.String(), "Try again in 2 minutes.") {
		t.Errorf("throttled: %d, Retry-After %q\n%s", rec.Code, rec.Header().Get(hRetryAfter), rec.Body.String())
	}
	p.auth.throttled = 30 * time.Second
	if rec := b.post(tLoginPath, form); !strings.Contains(rec.Body.String(), "Try again in a minute.") {
		t.Errorf("a wait under a minute:\n%s", rec.Body.String())
	}
	p.auth.throttled = 0

	p.auth.busy = true
	rec = b.post(tLoginPath, form)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(hRetryAfter) != "1" || sessionCookieOf(rec) != nil {
		t.Errorf("busy: %d, Retry-After %q", rec.Code, rec.Header().Get(hRetryAfter))
	}
	p.auth.busy = false

	p.auth.disabled = true
	body := b.get().Body.String()
	if !strings.Contains(body, "no password login") || strings.Contains(body, `name="password"`) {
		t.Errorf("without a password login the page should say so and offer no form:\n%s", body)
	}
	rec = b.post(tLoginPath, form)
	if rec.Code != http.StatusForbidden || sessionCookieOf(rec) != nil {
		t.Errorf("login without a password login: %d", rec.Code)
	}
}

// TestPage_SaveStoresAndNeverShows is the main path: a signed-in user
// stores an account, the API accepts it, and the value appears nowhere but
// in the store.
func TestPage_SaveStoresAndNeverShows(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(tAccount+":"+tSecret))
	// The check has to find the new values in the store: it tries what was
	// just stored, not what was there before.
	p.setCheckFunc(func(context.Context) backend.UserCredentialCheck {
		if got, err := p.stored(tLogin); err != nil || got != want {
			t.Errorf("at the time of the check the store holds %q, %v", got, err)
		}
		return backend.UserCredentialCheck{Outcome: backend.UserCheckAccepted, Detail: "HTTP 200"}
	})

	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeOK || !strings.Contains(out.notice, "The API accepted the credentials") {
		t.Fatalf("save: notice %q (%s)\n%s", out.notice, out.kind, out.body)
	}
	if got, err := p.stored(tLogin); err != nil || got != want {
		t.Errorf("stored login = %q, %v, want the Basic header value", got, err)
	}
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("stored pin = %q, %v", got, err)
	}
	if len(p.checked) != 1 || p.checked[0] != tAlice+"/"+tBackend+"/"+tAccount {
		t.Errorf("checks = %v", p.checked)
	}
	if len(p.forgot) != 1 || p.forgot[0] != tAlice+"/"+tBackend {
		t.Errorf("forgets = %v, want the backend told once to drop alice's sessions", p.forgot)
	}

	// The account is listed, and the notice is shown once: a reload of the
	// page sends nothing again and says nothing again.
	if !strings.Contains(out.body, `<span class="label">`+tAccount+`</span>`) || !regexp.MustCompile(`stored \d{4}-\d\d-\d\d \d\d:\d\d UTC`).MatchString(out.body) {
		t.Errorf("the page does not list the account:\n%s", out.body)
	}
	reload := b.get().Body.String()
	if noticeRe.MatchString(reload) || p.checks() != 1 {
		t.Errorf("a reload showed the notice again or repeated the save (checks %d)", p.checks())
	}

	// No value is anywhere: not on the page, not in the audit entry, not in
	// the log.
	entry := p.audit.last(t)
	if entry.Tool != auditStore || entry.UserID != tAlice || entry.Status != statusSuccess ||
		entry.Metadata["backend"] != tBackend || entry.Metadata["account"] != tAccount ||
		entry.Metadata["credentials"] != "mail_login,mail_pin" || entry.Metadata["check"] != backend.UserCheckAccepted {
		t.Errorf("audit entry = %+v", entry)
	}
	for _, secret := range []string{tSecret, tPinValue, want, base64.StdEncoding.EncodeToString([]byte(tSecret))} {
		for where, text := range map[string]string{"page": out.body + reload, "log": p.logs.String()} {
			if strings.Contains(text, secret) {
				t.Errorf("the %s contains a stored value (%q)", where, secret)
			}
		}
		for k, v := range entry.Metadata {
			if strings.Contains(v, secret) {
				t.Errorf("audit metadata %s contains a stored value", k)
			}
		}
	}

	// Bob sees nothing of it, also not a notice left for alice when he
	// presents her notice cookie.
	bob := p.newBrowser()
	bob.signIn(tBob, tBobPass)
	if strings.Contains(bob.get().Body.String(), tAccount) {
		t.Error("bob's page lists alice's account")
	}
	b.post(tSavePath, pinChange(token, tChangedPin)) // leaves a notice cookie for alice
	bob.cookies[hostPrefix+noticeCookie] = b.cookies[hostPrefix+noticeCookie]
	if noticeRe.MatchString(bob.get().Body.String()) {
		t.Error("bob's page shows a notice left for alice")
	}
}

// TestPage_RefusedCredentialsAreRolledBack pins that credentials the API
// does not accept leave the store as it was, and that the page says what
// became of the earlier state.
func TestPage_RefusedCredentialsAreRolledBack(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	p.setCheck(backend.UserCheckRefused, tRefused401)

	// Nothing stored before: nothing stored after.
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeError || !strings.Contains(out.notice, "did not accept") || !strings.HasSuffix(out.notice, "They were not stored.") {
		t.Fatalf("refused first save: notice %q (%s)", out.notice, out.kind)
	}
	if _, err := p.stored(tPin); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after a refused first save: err = %v, want nothing stored", err)
	}
	if e := p.audit.last(t); e.Status != statusError || e.Metadata["check"] != backend.UserCheckRefused ||
		!strings.Contains(e.Error, "refused") || strings.Contains(e.Error, tSecret) {
		t.Errorf("audit entry of the refusal = %+v", e)
	}
	// The label is filled in again, so the user corrects one field.
	if !strings.Contains(out.body, `name="label" value="`+tAccount+`"`) {
		t.Error("the form does not keep the label of a refused save")
	}
	// The backend is told to forget twice: after storing and after putting
	// the earlier state back. A session opened by the check must not live on.
	if p.forgets() != 2 {
		t.Errorf("forgets = %d, want one after the save and one after the rollback", p.forgets())
	}
	if strings.Contains(p.logs.String(), "account stored") {
		t.Error("the log says an account was stored that the API refused")
	}

	// An accepted account, then a refused change: the old values stay.
	p.setCheck(backend.UserCheckAccepted, "")
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	p.setCheck(backend.UserCheckRefused, "the API answered HTTP 403")
	out = b.submit(tSavePath, pinChange(token, tChangedPin))
	if out.kind != noticeError || !strings.Contains(out.notice, "what the account held before is in place") {
		t.Fatalf("refused change: %q", out.notice)
	}
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("after a refused change: pin = %q, %v, want the earlier value", got, err)
	}

	// A check that cannot tell keeps what was entered and says so.
	p.setCheck(backend.UserCheckUnknown, "no response (timeout)")
	out = b.submit(tSavePath, pinChange(token, tChangedPin))
	if out.kind != noticeWarn || !strings.Contains(out.notice, "could not be checked") {
		t.Errorf("unknown outcome: %q (%s)", out.notice, out.kind)
	}
	if got, _ := p.stored(tPin); got != tChangedPin {
		t.Errorf("after an inconclusive check: pin = %q, want the new value", got)
	}

	// A rollback that fails is not reported as one that worked.
	p.setCheck(backend.UserCheckRefused, tRefused401)
	p.store.failNextPut(2) // the save's write succeeds, the write that puts the old value back fails
	out = b.submit(tSavePath, pinChange(token, "refused-pin"))
	if out.kind != noticeError || !strings.Contains(out.notice, "still stored") {
		t.Errorf("failed rollback: %q", out.notice)
	}
	if e := p.audit.last(t); e.Status != statusError || !strings.Contains(e.Error, "still stored") {
		t.Errorf("audit entry of the failed rollback = %+v", e)
	}
}

// TestPage_UnreadableEarlierEntry covers an account whose stored values
// cannot be read any more, after a change of the key: a refused attempt to
// store it again cannot put the old entry back, and the page says so.
func TestPage_UnreadableEarlierEntry(t *testing.T) {
	p := newPage(t, tOrigin)
	// Seal the account under another key in the page's store file, then
	// reopen the page's store on that file.
	foreign, err := credentials.NewFileUserStore(p.dir, bytes.Repeat([]byte{8}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{tLogin, tPin} {
		slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: tAccount, Name: name}
		if err := foreign.PutUser(context.Background(), slot, "sealed-under-another-key"); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := credentials.NewFileUserStore(p.dir, tKey())
	if err != nil {
		t.Fatal(err)
	}
	p.store.FileUserStore = reopened

	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	if body := b.get().Body.String(); !strings.Contains(body, "can no longer be read") {
		t.Errorf("the page does not mark the unreadable account:\n%s", body)
	}
	p.setCheck(backend.UserCheckRefused, tRefused401)
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeError || !strings.Contains(out.notice, "could no longer be read and is gone") {
		t.Errorf("refused save over an unreadable entry: %q", out.notice)
	}
}

// TestPage_ChangesNeedSessionTokenAndOrigin pins what a request that
// changes something has to carry.
func TestPage_ChangesNeedSessionTokenAndOrigin(t *testing.T) {
	p := newPage(t, tOrigin)
	alice := p.newBrowser()
	token := alice.signIn(tAlice, tPassword)
	bob := p.newBrowser()
	bobToken := bob.signIn(tBob, tBobPass)
	name := hostPrefix + sessionCookie
	session := alice.cookies[name]

	cases := map[string]struct {
		token  string
		cookie string
		origin string
		status int
	}{
		"no session":            {token, "", tOrigin, http.StatusUnauthorized},
		"no token":              {"", session, tOrigin, http.StatusForbidden},
		"token of another user": {bobToken, session, tOrigin, http.StatusForbidden},
		"another origin":        {token, session, tEvil, http.StatusForbidden},
		"no origin":             {token, session, "", http.StatusForbidden},
		"forged cookie":         {token, "AAAA" + session[4:], tOrigin, http.StatusUnauthorized},
	}
	for label, c := range cases {
		for _, path := range []string{tSavePath, tRemovePath} {
			b := p.newBrowser()
			b.origin = c.origin
			if c.cookie != "" {
				b.cookies[name] = c.cookie
			}
			if rec := b.post(path, saveForm(c.token)); rec.Code != c.status {
				t.Errorf("%s %s: status %d, want %d", label, path, rec.Code, c.status)
			}
		}
	}
	if infos, _ := p.store.ListUser(context.Background(), tAlice); len(infos) != 0 {
		t.Errorf("a refused request stored %d credentials", len(infos))
	}
	if p.checks() != 0 || p.audit.count() != 0 {
		t.Errorf("a refused request reached the API check (%d) or the audit trail (%d)", p.checks(), p.audit.count())
	}

	// A session ends when its time is up ...
	p.advance(sessionTTL + time.Second)
	if rec := alice.post(tSavePath, saveForm(token)); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired session: %d", rec.Code)
	}
	p.advance(-sessionTTL - time.Second)

	// ... when the user's password changes ...
	alice.cookies[name] = session
	p.auth.set(tAlice, "new-password")
	if rec := alice.post(tSavePath, saveForm(token)); rec.Code != http.StatusUnauthorized {
		t.Errorf("session after a password change: %d", rec.Code)
	}
	p.auth.set(tAlice, tPassword)
	alice.cookies[name] = session
	if !strings.Contains(alice.get().Body.String(), tSignedIn) {
		t.Fatal("the session should be valid again with the password of its login")
	}

	// ... and when the user is removed.
	bobSession := bob.cookies[name]
	p.auth.set(tBob, "")
	if rec := bob.post(tSavePath, saveForm(bobToken)); rec.Code != http.StatusUnauthorized {
		t.Errorf("session of a removed user: %d", rec.Code)
	}
	bob.cookies[name] = bobSession
	if strings.Contains(bob.get().Body.String(), tSignedIn) {
		t.Error("the page still shows the session of a removed user")
	}
}

func TestPage_SaveValidation(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	base := func() url.Values { return saveForm(token) }
	set := func(k, v string) url.Values { f := base(); f.Set(k, v); return f }
	del := func(k string) url.Values { f := base(); f.Del(k); return f }

	for name, form := range map[string]url.Values{
		"unknown backend":                   set(tFieldBE, "gone"),
		"no label":                          del(tFieldLbl),
		"label with a space":                set(tFieldLbl, "two words"),
		"password only":                     del(tFieldUser),
		"username only":                     del(tFieldPass),
		"colon in the username":             set(tFieldUser, "a:b"),
		"line break in a secret":            set(tFieldPin, "a\nb"),
		"line break in a password":          set(tFieldPass, "a\r\nb"),
		"a value over the size limit":       set(tFieldPin, strings.Repeat("x", credentials.MaxUserCredentialBytes+1)),
		"new account, a credential missing": del(tFieldPin),
		"nothing entered":                   {tFieldTok: {token}, tFieldBE: {tBackend}, tFieldLbl: {tAccount}},
	} {
		out := b.submit(tSavePath, form)
		if out.kind != noticeError || !strings.Contains(out.notice, "Nothing was stored") {
			t.Errorf("%s: notice %q (%s)", name, out.notice, out.kind)
		}
	}
	if infos, _ := p.store.ListUser(context.Background(), tAlice); len(infos) != 0 {
		t.Fatalf("invalid forms stored %d credentials", len(infos))
	}
	if p.checks() != 0 || p.audit.count() != 0 {
		t.Errorf("an invalid form reached the API check (%d) or the audit trail (%d)", p.checks(), p.audit.count())
	}
	// A form larger than the page reads is turned away.
	if rec := b.post(tSavePath, set(tFieldPin, strings.Repeat("x", maxFormBytes+1))); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized form: %d", rec.Code)
	}

	// An existing account takes a partial change: what is left empty stays.
	if out := b.submit(tSavePath, base()); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	login, _ := p.stored(tLogin)
	change := pinChange(token, "second-pin")
	change.Set(tFieldLbl, "Alice@Example.com")
	if out := b.submit(tSavePath, change); out.kind != noticeOK {
		t.Fatalf("partial change: %q", out.notice)
	}
	if got, _ := p.stored(tPin); got != "second-pin" {
		t.Errorf("pin after the change = %q", got)
	}
	if got, _ := p.stored(tLogin); got != login {
		t.Error("a field left empty changed the stored login")
	}
}

func TestPage_AccountLimit(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	for i := range maxAccountsPerBackend {
		for _, name := range []string{tLogin, tPin} {
			slot := credentials.UserSlot{UserID: tAlice, Backend: tBackend, Account: fmt.Sprintf("box%d@example.com", i), Name: name}
			if err := p.store.PutUser(context.Background(), slot, "v"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeError || !strings.Contains(out.notice, "Remove one first") {
		t.Errorf("an account over the limit: %q (%s)", out.notice, out.kind)
	}
	// An account that exists can still be changed.
	change := pinChange(token, tChangedPin)
	change.Set(tFieldLbl, "box0@example.com")
	if out := b.submit(tSavePath, change); out.kind != noticeOK {
		t.Errorf("changing an existing account at the limit: %q", out.notice)
	}
}

// TestPage_SaveLimits pins the two limits that keep the page from serving
// as a way to try passwords against a backend's API.
func TestPage_SaveLimits(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	for i := range saveLimit {
		if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
			t.Fatalf("save %d: %q", i, out.notice)
		}
	}
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeError || !strings.Contains(out.notice, "Too many") {
		t.Errorf("save over the limit: %q", out.notice)
	}
	if p.checks() != saveLimit {
		t.Errorf("API checks = %d, want %d", p.checks(), saveLimit)
	}

	// Refused saves have a smaller budget of their own.
	bob := p.newBrowser()
	bobToken := bob.signIn(tBob, tBobPass)
	p.setCheck(backend.UserCheckRefused, tRefused401)
	for i := range refusedLimit {
		if out := bob.submit(tSavePath, saveForm(bobToken)); !strings.Contains(out.notice, "did not accept") {
			t.Fatalf("refused save %d: %q", i, out.notice)
		}
	}
	before := p.checks()
	if out := bob.submit(tSavePath, saveForm(bobToken)); !strings.Contains(out.notice, "Too many") {
		t.Errorf("save after %d refusals: %q", refusedLimit, out.notice)
	}
	if p.checks() != before {
		t.Error("a save over the refusal limit reached the API")
	}

	// The window ends for both.
	p.advance(saveWindow)
	p.setCheck(backend.UserCheckAccepted, "")
	token = b.signIn(tAlice, tPassword)
	bobToken = bob.signIn(tBob, tBobPass)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Errorf("alice's save after the window: %q", out.notice)
	}
	if out := bob.submit(tSavePath, saveForm(bobToken)); out.kind != noticeOK {
		t.Errorf("bob's save after the window: %q", out.notice)
	}
}

func TestPage_RemoveAndStaleAccounts(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	// An account of a backend that is not loaded any more is listed apart
	// and can be removed.
	old := credentials.UserSlot{UserID: tAlice, Backend: "retired", Account: "old@example.com", Name: "RETIRED_TOKEN"}
	if err := p.store.PutUser(context.Background(), old, "old-value"); err != nil {
		t.Fatal(err)
	}
	if body := b.get().Body.String(); !strings.Contains(body, "No longer used") || !strings.Contains(body, "old@example.com") {
		t.Errorf("the page does not list the stale account:\n%s", body)
	}

	forgetsBefore := p.forgets()
	if out := b.submit(tRemovePath, removeForm(token, tBackend, tAccount)); out.kind != noticeOK || !strings.Contains(out.notice, "Removed the account") {
		t.Fatalf("remove: %q (%s)", out.notice, out.kind)
	}
	if _, err := p.stored(tLogin); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("after remove: err = %v", err)
	}
	if p.forgets() != forgetsBefore+1 {
		t.Error("the backend was not told to drop the sessions of a removed account")
	}
	if e := p.audit.last(t); e.Tool != auditRemove || e.Metadata["account"] != tAccount || e.Status != statusSuccess {
		t.Errorf("audit entry of the removal = %+v", e)
	}
	if out := b.submit(tRemovePath, removeForm(token, "retired", "old@example.com")); out.kind != noticeOK {
		t.Errorf("remove stale: %q", out.notice)
	}
	if infos, _ := p.store.ListUser(context.Background(), tAlice); len(infos) != 0 {
		t.Errorf("%d credentials left after removing both accounts", len(infos))
	}
	if out := b.submit(tRemovePath, removeForm(token, tBackend, tAccount)); out.kind != noticeWarn || !strings.Contains(out.notice, "no such account") {
		t.Errorf("removing a missing account: %q", out.notice)
	}

	// A store that fails is reported and recorded as a failure.
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}
	p.store.mu.Lock()
	p.store.failDelete = true
	p.store.mu.Unlock()
	if out := b.submit(tRemovePath, removeForm(token, tBackend, tAccount)); out.kind != noticeError || !strings.Contains(out.notice, "The change failed") {
		t.Errorf("remove with a failing store: %q", out.notice)
	}
	if e := p.audit.last(t); e.Tool != auditRemove || e.Status != statusError {
		t.Errorf("audit entry of the failed removal = %+v", e)
	}
}

// TestPage_StoreFailureIsRecorded pins the audit entry of a save the store
// could not complete, and that what it had written is taken back.
func TestPage_StoreFailureIsRecorded(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	p.store.failNextPut(2) // the first of the two credentials is written, the second fails
	out := b.submit(tSavePath, saveForm(token))
	if out.kind != noticeError || !strings.Contains(out.notice, "The change failed") {
		t.Fatalf("save with a failing store: %q", out.notice)
	}
	if infos, _ := p.store.ListUser(context.Background(), tAlice); len(infos) != 0 {
		t.Errorf("a save that failed halfway left %d credentials", len(infos))
	}
	if e := p.audit.last(t); e.Tool != auditStore || e.Status != statusError || !strings.Contains(e.Error, errStoreDown.Error()) {
		t.Errorf("audit entry = %+v", e)
	}
	if p.checks() != 0 {
		t.Error("the check ran for an account that was not stored")
	}
	if p.forgets() == 0 {
		t.Error("the backend was not told to forget after a save that failed halfway")
	}
}

// TestPage_OffersOnlyWhatTheUserMayCall pins that the page follows the
// authorization of tool calls: a user who may call nothing of a backend is
// not offered it and cannot make ToolMesh try credentials against it.
func TestPage_OffersOnlyWhatTheUserMayCall(t *testing.T) {
	p := newPage(t, tOrigin)
	p.denied[tBob] = true
	// What such a user stored earlier, when the backend was still offered
	// to them, is listed as no longer used and can be removed.
	slot := credentials.UserSlot{UserID: tBob, Backend: tBackend, Account: "bob@example.com", Name: tPin}
	if err := p.store.PutUser(context.Background(), slot, "v"); err != nil {
		t.Fatal(err)
	}
	bob := p.newBrowser()
	token := bob.signIn(tBob, tBobPass)
	body := bob.get().Body.String()
	if strings.Contains(body, "Mailbox login") || strings.Contains(body, "A mail API") {
		t.Errorf("the page offers a backend the user may not call:\n%s", body)
	}
	if !strings.Contains(body, "No longer used") {
		t.Errorf("an account of a backend that is not offered any more is not listed:\n%s", body)
	}
	out := bob.submit(tSavePath, saveForm(token))
	if out.kind != noticeError || !strings.Contains(out.notice, "not offered") {
		t.Errorf("save for a backend that is not offered: %q", out.notice)
	}
	if infos, _ := p.store.ListUser(context.Background(), tBob); len(infos) != 1 || p.checks() != 0 {
		t.Errorf("%d credentials stored, %d checks after a save for a backend that is not offered", len(infos), p.checks())
	}
	if out := bob.submit(tRemovePath, removeForm(token, tBackend, "bob@example.com")); out.kind != noticeOK {
		t.Errorf("removing it: %q", out.notice)
	}
	// Alice is offered the backend as before.
	alice := p.newBrowser()
	alice.signIn(tAlice, tPassword)
	if !strings.Contains(alice.get().Body.String(), "Mailbox login") {
		t.Error("alice is not offered the backend")
	}
}

// TestPage_OverlappingSavesAreSerialized runs a second save of the same
// account while the first one's check is under way. Without a lock the
// second would read the first one's refused value as "what was there
// before" and put it back at the end.
func TestPage_OverlappingSavesAreSerialized(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	if out := b.submit(tSavePath, saveForm(token)); out.kind != noticeOK {
		t.Fatalf("save: %q", out.notice)
	}

	inCheck := make(chan struct{}, 2)
	release := make(chan struct{})
	p.setCheckFunc(func(context.Context) backend.UserCredentialCheck {
		inCheck <- struct{}{}
		<-release
		return backend.UserCredentialCheck{Outcome: backend.UserCheckRefused, Detail: tRefused401}
	})

	var wg sync.WaitGroup
	for _, pin := range []string{"refused-a", "refused-b"} {
		// Each save gets a browser of its own with the same session, as two
		// tabs have.
		tab := p.newBrowser()
		for k, v := range b.cookies {
			tab.cookies[k] = v
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tab.post(tSavePath, pinChange(token, pin))
		}()
	}
	<-inCheck
	// The other save must wait for the first to finish, not start its own
	// check.
	select {
	case <-inCheck:
		t.Error("two saves of one user ran their checks at the same time")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if got, err := p.stored(tPin); err != nil || got != tPinValue {
		t.Errorf("after two overlapping refused saves the pin is %q, %v; want the value from before both", got, err)
	}
}

// TestPage_ChangeOutlivesTheRequest pins that a browser that goes away
// does not leave an account stored without its check and its audit entry.
func TestPage_ChangeOutlivesTheRequest(t *testing.T) {
	p := newPage(t, tOrigin)
	b := p.newBrowser()
	token := b.signIn(tAlice, tPassword)
	p.setCheckFunc(func(ctx context.Context) backend.UserCredentialCheck {
		if err := ctx.Err(); err != nil {
			t.Errorf("the check runs under a context that has ended: %v", err)
		}
		return backend.UserCredentialCheck{Outcome: backend.UserCheckRefused, Detail: tRefused401}
	})

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	b.do(gone, http.MethodPost, tSavePath, saveForm(token))
	if p.checks() != 1 {
		t.Fatalf("checks = %d, want the check to run although the client is gone", p.checks())
	}
	if _, err := p.stored(tPin); !errors.Is(err, credentials.ErrCredentialNotFound) {
		t.Errorf("the refused credentials of a client that went away are stored: %v", err)
	}
	if p.audit.count() != 1 || p.audit.last(t).Status != statusError {
		t.Errorf("audit entries = %d, want the refused save recorded", p.audit.count())
	}
	p.setCheck(backend.UserCheckAccepted, "")
	b.do(gone, http.MethodPost, tSavePath, saveForm(token))
	b.do(gone, http.MethodPost, tRemovePath, removeForm(token, tBackend, tAccount))
	if p.audit.count() != 3 || p.audit.last(t).Tool != auditRemove {
		t.Errorf("audit entries = %d, want the save and the removal of a client that went away recorded", p.audit.count())
	}
}

func TestSealer(t *testing.T) {
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	key := bytes.Repeat([]byte{1}, 32)
	k, err := newSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	value, err := k.seal(sessionCookie, session{ID: "id", User: tAlice, FP: "fp", Exp: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := k.openSession(value, now); !ok || s.User != tAlice || s.FP != "fp" || s.ID != "id" {
		t.Errorf("open = %+v, %v", s, ok)
	}
	if _, ok := k.openSession(value, now.Add(time.Minute)); ok {
		t.Error("a session opens at its expiry")
	}
	other, _ := newSealer(bytes.Repeat([]byte{2}, 32))
	if _, ok := other.openSession(value, now); ok {
		t.Error("a session opens under another key")
	}
	for _, bad := range []string{"", "x", value[:len(value)-2], value + "AA", strings.Repeat("A", 80)} {
		if _, ok := k.openSession(bad, now); ok {
			t.Errorf("open accepted %q", bad)
		}
	}
	// A sealed value serves one purpose: a notice is no session and a
	// session no notice.
	note, err := k.seal(noticeCookie, flash{User: tAlice, Kind: noticeOK, Text: "x", Exp: now.Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.openSession(note, now); ok {
		t.Error("a notice cookie opens as a session")
	}
	if _, ok := k.openFlash(value, now); ok {
		t.Error("a session cookie opens as a notice")
	}
	if f, ok := k.openFlash(note, now); !ok || f.Text != "x" {
		t.Errorf("openFlash = %+v, %v", f, ok)
	}
	if _, ok := k.openFlash(note, now.Add(time.Minute)); ok {
		t.Error("a notice opens at its expiry")
	}
	// The cookies are not sealed with the key the stored credentials are
	// sealed with: that key does not open them.
	raw, _ := base64.RawURLEncoding.DecodeString(value)
	block, _ := aes.NewCipher(key)
	storeAEAD, _ := cipher.NewGCM(block)
	n := storeAEAD.NonceSize()
	if _, err := storeAEAD.Open(nil, raw[:n], raw[n:], []byte(sessionCookie)); err == nil {
		t.Error("the session cookie opens with the key of the store")
	}
	if !k.formTokenValid(value, k.formToken(value)) || k.formTokenValid(value, "") || k.formTokenValid(value, other.formToken(value)) ||
		k.formTokenValid(note, k.formToken(value)) {
		t.Error("form token check")
	}
	if _, err := newSealer(key[:16]); err == nil {
		t.Error("newSealer accepted a short key")
	}
	if _, err := New(Options{}); err == nil {
		t.Error("New accepted options without a store")
	}
}
