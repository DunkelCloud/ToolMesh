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

// Package enroll serves the credentials page: where a user signs in and
// stores the credentials of their own accounts at backends that ask every
// user for theirs (user_credentials in backends.yaml).
//
// Credentials of users reach ToolMesh on this page only. No tool takes one
// as a parameter, so a secret never passes through a model. The page shows
// what is stored and when, never a value.
package enroll

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Path is where the page is served.
const Path = credentials.EnrollPath

// webFiles holds the page's template and style sheet. They are part of the
// binary; the page loads nothing else and runs no script.
//
//go:embed web
var webFiles embed.FS

// pageTmpl is the page. Everything a request or the configuration
// contributes to it is escaped by html/template.
var pageTmpl = template.Must(template.New("credentials.html").Funcs(template.FuncMap{
	"mailAddressesAsWritten":    func() template.HTML { return emailOff },
	"endMailAddressesAsWritten": func() template.HTML { return emailOn },
}).ParseFS(webFiles, "web/credentials.html"))

// emailOff and emailOn are the comments with which a page tells Cloudflare
// to leave the mail addresses between them as written. A Cloudflare zone
// with "Email Address Obfuscation" otherwise replaces every address in the
// HTML and shows it again with a script, which the page's policy does not
// run: account labels that are mail addresses would be unreadable. They are
// values, not template text, because html/template drops comments.
const (
	emailOff template.HTML = "<!--email_off-->"
	emailOn  template.HTML = "<!--/email_off-->"
)

// pageCSP lets the page load its own style sheet and post its forms to its
// own origin, and nothing else: no script, no other origin, no framing.
const pageCSP = "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

// Audit actions and the name the page appears under as a caller.
const (
	auditStore    = "user_credential_store"
	auditRemove   = "user_credential_remove"
	auditBackend  = "toolmesh"
	auditCallerID = "credentials-page"
	statusSuccess = "success"
	statusError   = "error"
)

// Limits of the page.
const (
	// maxFormBytes bounds a submitted form.
	maxFormBytes = 4*credentials.MaxUserCredentialBytes + 64<<10
	// maxAccountsPerBackend bounds the accounts one user stores for one
	// backend.
	maxAccountsPerBackend = 50
	// A user may store credentials saveLimit times within saveWindow, and
	// have refusedLimit of those saves refused by the API. Every save can
	// send a request to the backend's API with credentials of the user's
	// choosing, so the page must not serve as a way to try passwords
	// against it. The counts are kept per process.
	saveLimit    = 20
	refusedLimit = 5
	saveWindow   = 10 * time.Minute
	// opTimeout bounds a change once it has started. The change does not
	// end with the request: a browser that goes away must not leave an
	// account stored without its check or its audit entry.
	opTimeout = 90 * time.Second
)

// Authenticator signs users in on the page. *mcp.Server implements it with
// the password login of /authorize.
type Authenticator interface {
	// PasswordLoginEnabled reports whether there is a password login.
	PasswordLoginEnabled() bool
	// PasswordLogin checks username and password, failed-login limits
	// included.
	PasswordLogin(r *http.Request, username, password string) auth.PasswordCheck
	// PasswordFingerprint returns the fingerprint of the password userID
	// signs in with now, false when the user is gone.
	PasswordFingerprint(userID string) (string, bool)
}

// Backend is a backend whose credentials every user stores for themselves,
// as the page offers it.
type Backend struct {
	Name        string
	Description string
	Credentials []backend.UserCredential
}

// Options configures a Service.
type Options struct {
	// Store holds what users store.
	Store credentials.UserStore
	// Backends returns the backends with user credentials as they are
	// loaded now.
	Backends func() []Backend
	// Auth signs users in.
	Auth Authenticator
	// Allowed reports whether the user may call any tool of the backend.
	// The page offers a backend, and sends its check, only to users for
	// whom it does. nil offers every backend to every user.
	Allowed func(ctx context.Context, userID, backendName string) bool
	// Check tries the credentials stored for one account of a user against
	// the backend's API; nil stores without a check.
	Check func(ctx context.Context, userID, backendName, account string) backend.UserCredentialCheck
	// Forget makes a backend drop the token and session it keeps for one
	// account of a user, so that a changed credential is used from the
	// account's next call on; may be nil.
	Forget func(userID, backendName, account string)
	// Audit records every stored and removed account; may be nil.
	Audit  audit.AuditStore
	Logger *slog.Logger
	// Key is the key user credentials are encrypted with. The keys of the
	// page's cookies and forms are derived from it.
	Key []byte
	// PublicURL is the address users reach the page at, without its path:
	// the address of the page's own listener when it has one, otherwise the
	// public address of this ToolMesh. "" when not configured.
	PublicURL string
	// AddressOnly says that PublicURL is the one address of the page, as
	// with a listener of its own. A request that arrives under another host
	// name gets no page, and a form has to come from PublicURL also when
	// the browser calls it same-origin. Without it the page answers under
	// every name its listener is reached at. It needs PublicURL.
	AddressOnly bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Service is the credentials page.
type Service struct {
	store     credentials.UserStore
	backends  func() []Backend
	auth      Authenticator
	allowed   func(ctx context.Context, userID, backendName string) bool
	check     func(ctx context.Context, userID, backendName, account string) backend.UserCredentialCheck
	forget    func(userID, backendName, account string)
	audit     audit.AuditStore
	logger    *slog.Logger
	sealer    *sealer
	publicURL *url.URL
	// addressOnly: publicURL is the only address the page answers under.
	addressOnly bool
	now         func() time.Time

	mu       sync.Mutex
	saves    map[string][]time.Time // user → times of recent saves
	refusals map[string][]time.Time // user → times of recent saves the API refused
	revoked  map[string]time.Time   // id of a signed-out session → its expiry
	locks    map[string]*userLock   // user → the lock that serializes their changes
}

// userLock serializes the changes of one user. users counts who holds or
// waits for it, so that the entry can go when nobody does.
type userLock struct {
	mu    sync.Mutex
	users int
}

// New creates the credentials page.
func New(opts Options) (*Service, error) {
	if opts.Store == nil || opts.Auth == nil || opts.Backends == nil {
		return nil, errors.New("credentials page: store, authenticator and backends are required")
	}
	sl, err := newSealer(opts.Key)
	if err != nil {
		return nil, err
	}
	s := &Service{
		store:    opts.Store,
		backends: opts.Backends,
		auth:     opts.Auth,
		allowed:  opts.Allowed,
		check:    opts.Check,
		forget:   opts.Forget,
		audit:    opts.Audit,
		logger:   opts.Logger,
		sealer:   sl,
		now:      opts.Now,
		saves:    map[string][]time.Time{},
		refusals: map[string][]time.Time{},
		revoked:  map[string]time.Time{},
		locks:    map[string]*userLock{},
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if opts.PublicURL != "" {
		if u, err := url.Parse(opts.PublicURL); err == nil && u.Host != "" {
			s.publicURL = u
		}
	}
	if opts.AddressOnly {
		if s.publicURL == nil {
			return nil, errors.New("credentials page: an address of its own needs that address")
		}
		s.addressOnly = true
	}
	return s, nil
}

// Handler returns the page and its endpoints:
//
//	GET  /credentials                  the page: the login form, or the user's accounts
//	POST /credentials/login            sign in
//	POST /credentials/logout           sign out
//	POST /credentials/save             store the credentials of an account
//	POST /credentials/remove           remove an account
//	GET  /credentials/credentials.css  the style sheet
//
// Every form is answered with a redirect to the page, which then shows the
// outcome. A reload of the page therefore never sends a form, and with it a
// credential, a second time.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Path, s.handlePage)
	mux.HandleFunc("GET "+Path+"/{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, Path, http.StatusSeeOther)
	})
	mux.HandleFunc("GET "+Path+"/credentials.css", s.handleCSS)
	mux.HandleFunc("POST "+Path+"/login", s.handleLogin)
	mux.HandleFunc("POST "+Path+"/logout", s.handleLogout)
	mux.HandleFunc("POST "+Path+"/save", s.handleSave)
	mux.HandleFunc("POST "+Path+"/remove", s.handleRemove)
	if !s.addressOnly {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.EqualFold(r.Host, s.publicURL.Host) {
			s.misdirected(w)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// misdirected answers a request that reached the page under a host name
// that is not the page's address. It gets no form: what a user typed into
// it would travel the path that name leads over, and keeping passwords off
// such a path is what the page's own address is for. A proxy in front of
// the page's listener therefore has to pass the Host header on.
func (s *Service) misdirected(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusMisdirectedRequest)
	_, _ = fmt.Fprintf(w, "The credentials page of this ToolMesh is at %s%s\n", s.publicURL.String(), Path)
}

// Kinds of a notice; they are the classes the style sheet colors.
const (
	noticeOK    = "ok"
	noticeWarn  = "warn"
	noticeError = "error"
)

// notice is the message at the top of the page.
type notice struct {
	// Kind is noticeOK, noticeWarn or noticeError.
	Kind string
	Text string
}

// fieldView is one credential of a backend in the form.
type fieldView struct {
	Key   string
	Label string
	Hint  string
	Basic bool
}

// accountView is one stored account.
type accountView struct {
	Label  string
	Status string
	// Usable is false when the account lacks a credential or one of its
	// credentials cannot be read.
	Usable bool
}

// backendView is one backend on the page.
type backendView struct {
	Name        string
	Description string
	Fields      []fieldView
	Accounts    []accountView
	// Label refills the account label after a refused save.
	Label string
}

// staleView is a stored account no backend offered to the user asks for.
type staleView struct {
	Backend string
	Account string
}

// pageView fills the template.
type pageView struct {
	SignedIn     bool
	User         string
	Token        string
	LoginEnabled bool
	Username     string
	Notice       *notice
	Backends     []backendView
	Stale        []staleView
}

// setHeaders sets what every answer of the page carries.
func setHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("Cache-Control", "no-store")
	// same-origin, not no-referrer: with no-referrer a browser sends
	// "Origin: null" with the page's own forms, and on plain http, where it
	// sends no Sec-Fetch-Site either, sameOrigin could not tell them from
	// another site's. Nothing goes to other origins either way.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Robots-Tag", "noindex")
}

// render writes the page.
func (s *Service) render(w http.ResponseWriter, r *http.Request, status int, v pageView) {
	setHeaders(w)
	w.WriteHeader(status)
	if err := pageTmpl.Execute(w, v); err != nil {
		s.logger.ErrorContext(r.Context(), "credentials page render failed", "error", err)
	}
}

// renderLogin writes the login form with an optional message.
func (s *Service) renderLogin(w http.ResponseWriter, r *http.Request, status int, username, msg string) {
	v := pageView{LoginEnabled: s.auth.PasswordLoginEnabled(), Username: username}
	if msg != "" {
		v.Notice = &notice{Kind: noticeError, Text: msg}
	}
	s.render(w, r, status, v)
}

// redirect sends the browser back to the page after a form.
func redirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, Path, http.StatusSeeOther)
}

func (s *Service) handleCSS(w http.ResponseWriter, r *http.Request) {
	data, err := webFiles.ReadFile("web/credentials.css")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(data) //nolint:gosec // a file embedded in the binary, not request data
}

// Schemes a request can arrive with.
const (
	schemeHTTP  = "http"
	schemeHTTPS = "https"
)

// requestScheme is the scheme the request arrived with, as far as the
// server can tell: https for a TLS connection or when a proxy says so.
func requestScheme(r *http.Request) string {
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), schemeHTTPS) {
		return schemeHTTPS
	}
	return schemeHTTP
}

// secure reports whether the page is reached over https, so that its
// cookies are marked Secure and carry the __Host- prefix. A client that
// claims https with X-Forwarded-Proto only changes the cookies it gets
// itself.
func (s *Service) secure(r *http.Request) bool {
	if s.publicURL != nil && strings.EqualFold(s.publicURL.Scheme, schemeHTTPS) {
		return true
	}
	return requestScheme(r) == schemeHTTPS
}

// sameOrigin reports whether a form was sent by a page of this ToolMesh.
// This keeps another site from signing a visitor in under an account of
// its own, after which the visitor would store their credentials in that
// account.
//
// Browsers say where a POST comes from. Sec-Fetch-Site is the browser's own
// verdict and decides when it is there; a page cannot set it. Browsers
// leave it out on connections they do not consider secure (plain http
// beyond localhost). Then Origin has to name this ToolMesh: its public
// address when one is configured, otherwise the scheme and host the request
// arrived with. A request that says neither is refused, as is an Origin of
// "null" without the verdict.
//
// The verdict compares with the address the browser used, whatever that
// was. Where the page has an address of its own, the form has to come from
// that address: an Origin the browser sends along with the verdict has to
// name it, scheme included, so that the page reached over plain http when
// its address is https takes no password either.
func (s *Service) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		if site != "same-origin" {
			return false
		}
		if s.addressOnly && origin != "" && origin != originNull {
			return s.fromPublicURL(origin)
		}
		return true
	}
	if origin == "" {
		return false
	}
	if s.publicURL != nil {
		return s.fromPublicURL(origin)
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, requestScheme(r)) && strings.EqualFold(u.Host, r.Host)
}

// originNull is the Origin header of a request whose origin the browser
// withholds, for instance under a strict referrer policy.
const originNull = "null"

// fromPublicURL reports whether origin, the value of an Origin header, is
// the configured address of the page.
func (s *Service) fromPublicURL(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Scheme, s.publicURL.Scheme) && strings.EqualFold(u.Host, s.publicURL.Host)
}

// cookieName is the name a cookie of the page has for this request: with
// the __Host- prefix over https, which makes browsers refuse a cookie of
// that name set by another host of the domain.
func (s *Service) cookieName(r *http.Request, base string) string {
	if s.secure(r) {
		return hostPrefix + base
	}
	return base
}

// setCookie sets a cookie of the page or, with an empty value, clears it.
func (s *Service) setCookie(w http.ResponseWriter, r *http.Request, base, value string, ttl time.Duration) {
	c := &http.Cookie{ //nolint:gosec // G124: HttpOnly and SameSite are set; Secure follows the scheme the page is reached over
		Name:     s.cookieName(r, base),
		Value:    value,
		Path:     Path,
		HttpOnly: true,
		Secure:   s.secure(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(ttl / time.Second),
	}
	if c.Secure {
		c.Path = "/" // the __Host- prefix requires it
	}
	if value == "" {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

// session returns the session of a request and the value of its cookie.
// A session is valid while it has not run out, its user has not signed out
// of it, and the user still signs in with the password of its login.
func (s *Service) session(r *http.Request) (sess session, cookieValue string, ok bool) {
	c, err := r.Cookie(s.cookieName(r, sessionCookie))
	if err != nil || c.Value == "" {
		return session{}, "", false
	}
	sess, ok = s.sealer.openSession(c.Value, s.now())
	if !ok || s.signedOut(sess.ID) {
		return session{}, "", false
	}
	fp, exists := s.auth.PasswordFingerprint(sess.User)
	if !exists || fp == "" || fp != sess.FP {
		return session{}, "", false
	}
	return sess, c.Value, true
}

// signOut ends the session id until its expiry. The id is kept in this
// process: another instance, or this one after a restart, would accept the
// cookie again for what is left of its 15 minutes.
func (s *Service) signOut(sess session) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, exp := range s.revoked {
		if !now.Before(exp) {
			delete(s.revoked, id)
		}
	}
	s.revoked[sess.ID] = time.Unix(sess.Exp, 0)
}

// signedOut reports whether the session id was signed out.
func (s *Service) signedOut(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, out := s.revoked[id]
	return out
}

// flash leaves the message of a change for the page the browser is
// redirected to. It travels in a sealed cookie of its own, bound to the
// user, and is shown once.
func (s *Service) flash(w http.ResponseWriter, r *http.Request, user string, n notice, backendName, label string) {
	value, err := s.sealer.seal(noticeCookie, flash{
		User: user, Kind: n.Kind, Text: n.Text, Backend: backendName, Label: label,
		Exp: s.now().Add(noticeTTL).Unix(),
	})
	if err != nil {
		s.logger.ErrorContext(r.Context(), "credentials page: sealing the notice failed", "error", err)
		return
	}
	s.setCookie(w, r, noticeCookie, value, noticeTTL)
}

// takeFlash returns the message left for user, if any, and clears it.
func (s *Service) takeFlash(w http.ResponseWriter, r *http.Request, user string) (flash, bool) {
	c, err := r.Cookie(s.cookieName(r, noticeCookie))
	if err != nil || c.Value == "" {
		return flash{}, false
	}
	s.setCookie(w, r, noticeCookie, "", 0)
	f, ok := s.sealer.openFlash(c.Value, s.now())
	if !ok || f.User != user {
		return flash{}, false
	}
	return f, true
}

func (s *Service) handlePage(w http.ResponseWriter, r *http.Request) {
	sess, cookie, ok := s.session(r)
	if !ok {
		s.renderLogin(w, r, http.StatusOK, "", "")
		return
	}
	var n *notice
	var keepBackend, keepLabel string
	if f, ok := s.takeFlash(w, r, sess.User); ok {
		n = &notice{Kind: f.Kind, Text: f.Text}
		keepBackend, keepLabel = f.Backend, f.Label
	}
	s.renderAccounts(w, r, sess, cookie, n, keepBackend, keepLabel)
}

// humanWait phrases the remaining seconds of a login lockout.
func humanWait(seconds int) string {
	minutes := (seconds + 59) / 60
	if minutes <= 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.renderLogin(w, r, http.StatusForbidden, "", "This form was not sent from this page. Open the page again and sign in there.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, http.StatusBadRequest, "", "The form could not be read.")
		return
	}
	username := r.PostFormValue("username")
	check := s.auth.PasswordLogin(r, username, r.PostFormValue("password"))
	switch check.Outcome {
	case auth.PasswordOK:
	case auth.PasswordThrottled:
		wait := max(int((check.RetryAfter+time.Second-1)/time.Second), 1)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		s.renderLogin(w, r, http.StatusTooManyRequests, username,
			fmt.Sprintf("Too many failed login attempts. Try again in %s.", humanWait(wait)))
		return
	case auth.PasswordBusy:
		w.Header().Set("Retry-After", "1")
		s.renderLogin(w, r, http.StatusServiceUnavailable, username, "The server is busy. Try again in a moment.")
		return
	case auth.PasswordDisabled:
		s.renderLogin(w, r, http.StatusForbidden, "", "")
		return
	default:
		s.renderLogin(w, r, http.StatusUnauthorized, username, "Invalid username or password.")
		return
	}
	id, err := newSessionID()
	var value string
	if err == nil {
		value, err = s.sealer.seal(sessionCookie, session{ID: id, User: check.UserID, FP: check.Fingerprint, Exp: s.now().Add(sessionTTL).Unix()})
	}
	if err != nil {
		s.logger.ErrorContext(r.Context(), "credentials page: sealing the session failed", "error", err)
		s.renderLogin(w, r, http.StatusInternalServerError, username, "Signing in failed. Try again.")
		return
	}
	s.logger.InfoContext(r.Context(), "credentials page: signed in", "user", check.UserID, "remote", auth.ClientIP(r))
	s.setCookie(w, r, sessionCookie, value, sessionTTL)
	redirect(w, r)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		s.renderLogin(w, r, http.StatusForbidden, "", "This form was not sent from this page.")
		return
	}
	if sess, _, ok := s.session(r); ok {
		s.signOut(sess)
	}
	s.setCookie(w, r, sessionCookie, "", 0)
	redirect(w, r)
}

// authorize checks a request that changes something: it comes from this
// page, carries a live session and that session's form token. On failure
// it has answered the request.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request) (sess session, ok bool) {
	if !s.sameOrigin(r) {
		s.renderLogin(w, r, http.StatusForbidden, "", "This form was not sent from this page. Open the page again.")
		return session{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderLogin(w, r, http.StatusBadRequest, "", "The form could not be read.")
		return session{}, false
	}
	sess, cookie, ok := s.session(r)
	if !ok {
		s.setCookie(w, r, sessionCookie, "", 0)
		s.renderLogin(w, r, http.StatusUnauthorized, "", "Your session has ended. Sign in again; nothing was changed.")
		return session{}, false
	}
	if !s.sealer.formTokenValid(cookie, r.PostFormValue("token")) {
		s.renderLogin(w, r, http.StatusForbidden, "", "This form does not belong to your session. Open the page again.")
		return session{}, false
	}
	return sess, true
}

// lockUser serializes the changes of one user: a save holds the lock from
// reading what an account held to putting it back after a refused check,
// so that an overlapping save or remove of the same user never sees or
// restores a state in between. The returned function releases it.
func (s *Service) lockUser(user string) func() {
	s.mu.Lock()
	l := s.locks[user]
	if l == nil {
		l = &userLock{}
		s.locks[user] = l
	}
	l.users++
	s.mu.Unlock()

	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		s.mu.Lock()
		l.users--
		if l.users == 0 {
			delete(s.locks, user)
		}
		s.mu.Unlock()
	}
}

// offered returns the loaded backends the page offers to user: those of
// which the user may call a tool.
func (s *Service) offered(ctx context.Context, user string) []Backend {
	loaded := s.backends()
	out := make([]Backend, 0, len(loaded))
	for _, b := range loaded {
		if s.allowed == nil || s.allowed(ctx, user, b.Name) {
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// fieldLabel is what the page calls a credential.
func fieldLabel(c backend.UserCredential) string {
	if c.Label != "" {
		return c.Label
	}
	return strings.ToLower(c.Name)
}

// recent drops the times older than saveWindow.
func recent(times []time.Time, now time.Time) []time.Time {
	kept := times[:0]
	for _, t := range times {
		if now.Sub(t) < saveWindow {
			kept = append(kept, t)
		}
	}
	return kept
}

// allowSave counts a save of user against the limits and reports whether it
// may proceed: saveLimit saves and refusedLimit refused ones in saveWindow.
func (s *Service) allowSave(user string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves[user] = recent(s.saves[user], now)
	if kept := recent(s.refusals[user], now); len(kept) > 0 {
		s.refusals[user] = kept
	} else {
		delete(s.refusals, user)
	}
	if len(s.saves[user]) >= saveLimit || len(s.refusals[user]) >= refusedLimit {
		return false
	}
	s.saves[user] = append(s.saves[user], now)
	// Forget users whose saves have all aged out, so the map stays small.
	if len(s.saves) > 1024 {
		for u, ts := range s.saves {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= saveWindow {
				delete(s.saves, u)
			}
		}
	}
	return true
}

// countRefusal records that the API refused a save of user.
func (s *Service) countRefusal(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusals[user] = append(s.refusals[user], s.now())
}

// singleLine reports whether a submitted value is free of line breaks and
// NUL: such a value could not be sent in a header.
func singleLine(v string) bool {
	return !strings.ContainsAny(v, "\r\n\x00")
}

// submitted reads the credentials a save form carries for backend b, by
// key. Fields left empty are absent. The error is a message for the user.
func submitted(r *http.Request, b Backend) (map[string]string, error) {
	values := map[string]string{}
	for _, c := range b.Credentials {
		key := strings.ToUpper(c.Name)
		var value string
		if c.Format == backend.UserCredentialFormatBasic {
			user := strings.TrimSpace(r.PostFormValue("u." + key))
			pass := r.PostFormValue("p." + key)
			if user == "" && pass == "" {
				continue
			}
			if user == "" || pass == "" {
				return nil, fmt.Errorf("%s: enter both the username and the password", fieldLabel(c))
			}
			if strings.Contains(user, ":") {
				return nil, fmt.Errorf("%s: the username must not contain a colon", fieldLabel(c))
			}
			if !singleLine(user) || !singleLine(pass) {
				return nil, fmt.Errorf("%s: username and password must not contain line breaks", fieldLabel(c))
			}
			value = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
		} else {
			value = r.PostFormValue("s." + key)
			if value == "" {
				continue
			}
			if !singleLine(value) {
				return nil, fmt.Errorf("%s: the value must not contain line breaks", fieldLabel(c))
			}
		}
		if len(value) > credentials.MaxUserCredentialBytes {
			return nil, fmt.Errorf("%s: the value is longer than %d bytes", fieldLabel(c), credentials.MaxUserCredentialBytes)
		}
		values[key] = value
	}
	return values, nil
}

// earlier is what the credentials of a save held before it.
type earlier struct {
	// values holds the earlier value of each credential, nil for none.
	values map[string]*string
	// readable is set when the account held a value that could be read,
	// unreadable when it held one that could not: such an entry cannot be
	// put back.
	readable, unreadable bool
}

func (s *Service) handleSave(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	// From here on the change runs to its end, also when the browser goes
	// away: the check and the audit entry belong to the stored account.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	unlock := s.lockUser(sess.User)
	defer unlock()

	backendName := r.PostFormValue("backend")
	rawLabel := r.PostFormValue("label")
	done := func(n notice, keepLabel bool) {
		label := ""
		if keepLabel {
			label = rawLabel
		}
		s.flash(w, r, sess.User, n, backendName, label)
		redirect(w, r)
	}
	refuse := func(msg string) { done(notice{Kind: noticeError, Text: msg}, true) }

	var b Backend
	found := false
	for _, candidate := range s.offered(ctx, sess.User) {
		if candidate.Name == backendName {
			b, found = candidate, true
		}
	}
	if !found {
		refuse("This backend is not offered to you here. Nothing was stored.")
		return
	}
	account, valid := credentials.NormalizeAccount(rawLabel)
	if !valid {
		refuse("Give the account a label: 1 to 100 letters, digits and @ . _ + -, for example its mail address. Nothing was stored.")
		return
	}
	values, err := submitted(r, b)
	if err != nil {
		refuse(capitalize(err.Error()) + ". Nothing was stored.")
		return
	}
	if len(values) == 0 {
		refuse("Nothing was entered. Nothing was stored.")
		return
	}

	stored, err := s.store.ListUser(ctx, sess.User)
	if err != nil {
		s.storeFailed(ctx, w, r, sess, err)
		return
	}
	have := map[string]bool{} // credentials the account holds already
	accounts := map[string]bool{}
	for _, info := range stored {
		if info.Backend != b.Name {
			continue
		}
		accounts[info.Account] = true
		if info.Account == account && info.Readable {
			have[info.Name] = true
		}
	}
	if !accounts[account] && len(accounts) >= maxAccountsPerBackend {
		refuse(fmt.Sprintf("You have stored %d accounts for this backend, the most this page takes. Remove one first.", maxAccountsPerBackend))
		return
	}
	// An account is stored whole: what is not entered must be there
	// already.
	for _, c := range b.Credentials {
		key := strings.ToUpper(c.Name)
		if _, entered := values[key]; !entered && !have[key] {
			refuse(capitalize(fieldLabel(c)) + " is missing. Nothing was stored.")
			return
		}
	}
	if !s.allowSave(sess.User) {
		refuse("Too many changes, or too many the API refused, in a short time. Try again in a few minutes. Nothing was stored.")
		return
	}

	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Remember what was there, so a refused check puts it back.
	before := earlier{values: map[string]*string{}}
	for _, k := range keys {
		old, err := s.store.GetUser(ctx, credentials.UserSlot{UserID: sess.User, Backend: b.Name, Account: account, Name: k})
		switch {
		case err == nil:
			before.values[k] = &old
			before.readable = true
		case errors.Is(err, credentials.ErrCredentialNotFound):
			before.values[k] = nil
		case errors.Is(err, credentials.ErrUserCredentialUnreadable):
			before.values[k] = nil
			before.unreadable = true
		default:
			s.storeFailed(ctx, w, r, sess, err)
			return
		}
	}
	start := s.now()
	for i, k := range keys {
		err := s.store.PutUser(ctx, credentials.UserSlot{UserID: sess.User, Backend: b.Name, Account: account, Name: k}, values[k])
		if err == nil {
			continue
		}
		// What this save has written so far is taken back.
		if rerr := s.restore(ctx, sess.User, b.Name, account, keys[:i], before.values); rerr != nil {
			err = fmt.Errorf("%w; putting the earlier state back failed as well: %w", err, rerr)
		}
		s.forgetAccount(sess.User, b.Name, account)
		s.record(ctx, auditStore, start, sess.User, b.Name, account, keys, "", err)
		s.storeFailed(ctx, w, r, sess, err)
		return
	}
	s.forgetAccount(sess.User, b.Name, account)

	outcome := backend.UserCredentialCheck{Outcome: backend.UserCheckUnavailable}
	if s.check != nil {
		outcome = s.check(ctx, sess.User, b.Name, account)
	}
	var n notice
	var auditErr error
	switch outcome.Outcome {
	case backend.UserCheckRefused:
		s.countRefusal(sess.User)
		rerr := s.restore(ctx, sess.User, b.Name, account, keys, before.values)
		s.forgetAccount(sess.User, b.Name, account)
		auditErr = fmt.Errorf("the API refused the credentials: %s", outcome.Detail)
		text := fmt.Sprintf("%s did not accept these credentials (%s). ", b.Name, outcome.Detail)
		switch {
		case rerr != nil:
			auditErr = fmt.Errorf("%w; putting the earlier state back failed, the refused credentials are still stored: %w", auditErr, rerr)
			text += "Putting the earlier state back failed: the refused credentials are still stored. Remove the account or store it again."
		case before.unreadable:
			text += "They were not stored. What the account held before could no longer be read and is gone."
		case before.readable:
			text += "They were not stored; what the account held before is in place."
		default:
			text += "They were not stored."
		}
		n = notice{Kind: noticeError, Text: text}
		s.logger.WarnContext(ctx, "credentials page: the API refused an account",
			"user", sess.User, "backend", b.Name, "account", account, "credentials", strings.Join(keys, ","), "detail", outcome.Detail)
	case backend.UserCheckAccepted:
		n = notice{Kind: noticeOK, Text: fmt.Sprintf("Stored the account %s for %s. The API accepted the credentials.", account, b.Name)}
	case backend.UserCheckUnknown:
		n = notice{Kind: noticeWarn, Text: fmt.Sprintf("Stored the account %s for %s. Whether the API accepts the credentials could not be checked: %s.", account, b.Name, outcome.Detail)}
	default:
		n = notice{Kind: noticeOK, Text: fmt.Sprintf("Stored the account %s for %s. This backend offers no way to check the credentials; the first call will tell.", account, b.Name)}
	}
	s.record(ctx, auditStore, start, sess.User, b.Name, account, keys, outcome.Outcome, auditErr)
	if auditErr == nil {
		s.logger.InfoContext(ctx, "credentials page: account stored",
			"user", sess.User, "backend", b.Name, "account", account, "credentials", strings.Join(keys, ","), "check", outcome.Outcome)
	}
	done(n, auditErr != nil)
}

// restore puts back what the credentials named keys held before a save:
// the earlier value, or nothing. It reports the first failure and goes on
// with the rest.
func (s *Service) restore(ctx context.Context, user, backendName, account string, keys []string, previous map[string]*string) error {
	var first error
	for _, k := range keys {
		slot := credentials.UserSlot{UserID: user, Backend: backendName, Account: account, Name: k}
		var err error
		if old := previous[k]; old != nil {
			err = s.store.PutUser(ctx, slot, *old)
		} else {
			_, err = s.store.DeleteUser(ctx, slot)
		}
		if err != nil {
			s.logger.ErrorContext(ctx, "credentials page: restoring a credential failed",
				"user", user, "backend", backendName, "account", account, "credential", k, "error", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

func (s *Service) handleRemove(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.authorize(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), opTimeout)
	defer cancel()
	unlock := s.lockUser(sess.User)
	defer unlock()

	backendName := r.PostFormValue("backend")
	done := func(n notice) {
		s.flash(w, r, sess.User, n, "", "")
		redirect(w, r)
	}
	account, valid := credentials.NormalizeAccount(r.PostFormValue("label"))
	if backendName == "" || !valid {
		done(notice{Kind: noticeError, Text: "Nothing was removed: the form names no account."})
		return
	}
	stored, err := s.store.ListUser(ctx, sess.User)
	if err != nil {
		s.storeFailed(ctx, w, r, sess, err)
		return
	}
	start := s.now()
	var removed []string
	for _, info := range stored {
		if info.Backend != backendName || info.Account != account {
			continue
		}
		slot := credentials.UserSlot{UserID: sess.User, Backend: backendName, Account: account, Name: info.Name}
		if _, err := s.store.DeleteUser(ctx, slot); err != nil {
			s.forgetAccount(sess.User, backendName, account)
			s.record(ctx, auditRemove, start, sess.User, backendName, account, removed, "", err)
			s.storeFailed(ctx, w, r, sess, err)
			return
		}
		removed = append(removed, info.Name)
	}
	s.forgetAccount(sess.User, backendName, account)
	if len(removed) == 0 {
		done(notice{Kind: noticeWarn, Text: "There was no such account; nothing was removed."})
		return
	}
	s.record(ctx, auditRemove, start, sess.User, backendName, account, removed, "", nil)
	s.logger.InfoContext(ctx, "credentials page: account removed", "user", sess.User, "backend", backendName, "account", account)
	done(notice{Kind: noticeOK, Text: fmt.Sprintf("Removed the account %s for %s.", account, backendName)})
}

// forgetAccount makes the backend drop what it keeps for one account of
// the user.
func (s *Service) forgetAccount(user, backendName, account string) {
	if s.forget != nil {
		s.forget(user, backendName, account)
	}
}

// storeFailed answers a request whose store operation failed.
func (s *Service) storeFailed(ctx context.Context, w http.ResponseWriter, r *http.Request, sess session, err error) {
	s.logger.ErrorContext(ctx, "credentials page: user credential store failed", "user", sess.User, "error", err)
	s.flash(w, r, sess.User, notice{Kind: noticeError,
		Text: "The change failed: the store for credentials of users did not work. Tell the operator of this ToolMesh."}, "", "")
	redirect(w, r)
}

// record writes the audit entry of a stored or removed account. It names
// the account and its credentials, never a value.
func (s *Service) record(ctx context.Context, action string, start time.Time, user, backendName, account string, names []string, check string, err error) {
	if s.audit == nil {
		return
	}
	md := map[string]string{
		"backend":     backendName,
		"account":     account,
		"credentials": strings.ToLower(strings.Join(names, ",")),
	}
	if check != "" {
		md["check"] = check
	}
	entry := audit.AuditEntry{
		TraceID:    uuid.New().String(),
		Timestamp:  start,
		UserID:     user,
		CallerID:   auditCallerID,
		CallerName: auditCallerID,
		Tool:       action,
		Backend:    auditBackend,
		DurationMs: s.now().Sub(start).Milliseconds(),
		Status:     statusSuccess,
		Metadata:   md,
	}
	if err != nil {
		entry.Status = statusError
		entry.Error = err.Error()
	}
	if rerr := s.audit.Record(ctx, entry); rerr != nil {
		s.logger.ErrorContext(ctx, "failed to record audit entry", "traceId", entry.TraceID, "tool", entry.Tool, "error", rerr)
	}
}

// renderAccounts writes the page of a signed-in user: per offered backend
// the stored accounts and the form to add or replace one. keepBackend and
// keepLabel refill the label of a refused save.
func (s *Service) renderAccounts(w http.ResponseWriter, r *http.Request, sess session, cookie string, n *notice, keepBackend, keepLabel string) {
	status := http.StatusOK
	v := pageView{SignedIn: true, User: sess.User, Token: s.sealer.formToken(cookie), Notice: n}
	stored, err := s.store.ListUser(r.Context(), sess.User)
	if err != nil {
		s.logger.ErrorContext(r.Context(), "credentials page: listing user credentials failed", "user", sess.User, "error", err)
		if v.Notice == nil {
			v.Notice = &notice{Kind: noticeError, Text: "What you have stored could not be read: the store failed."}
		}
		status = http.StatusInternalServerError
	}
	shown := map[staleView]bool{}
	for _, b := range s.offered(r.Context(), sess.User) {
		bv := backendView{Name: b.Name, Description: b.Description}
		if b.Name == keepBackend {
			bv.Label = keepLabel
		}
		declared := map[string]bool{}
		for _, c := range b.Credentials {
			key := strings.ToUpper(c.Name)
			declared[key] = true
			bv.Fields = append(bv.Fields, fieldView{Key: key, Label: fieldLabel(c), Hint: c.Hint, Basic: c.Format == backend.UserCredentialFormatBasic})
		}
		// Group what is stored for this backend by account.
		type held struct {
			names      map[string]bool
			unreadable bool
			latest     time.Time
		}
		byAccount := map[string]*held{}
		var labels []string
		for _, info := range stored {
			if info.Backend != b.Name || !declared[info.Name] {
				continue
			}
			h := byAccount[info.Account]
			if h == nil {
				h = &held{names: map[string]bool{}}
				byAccount[info.Account] = h
				labels = append(labels, info.Account)
			}
			h.names[info.Name] = true
			if !info.Readable {
				h.unreadable = true
			}
			if info.UpdatedAt.After(h.latest) {
				h.latest = info.UpdatedAt
			}
		}
		sort.Strings(labels)
		for _, label := range labels {
			h := byAccount[label]
			shown[staleView{Backend: b.Name, Account: label}] = true
			av := accountView{Label: label, Usable: true}
			var missing []string
			for _, f := range bv.Fields {
				if !h.names[f.Key] {
					missing = append(missing, f.Label)
				}
			}
			switch {
			case h.unreadable:
				av.Usable = false
				av.Status = "stored, but it can no longer be read: store it again"
			case len(missing) > 0:
				av.Usable = false
				av.Status = "incomplete, missing: " + strings.Join(missing, ", ")
			default:
				av.Status = "stored " + h.latest.UTC().Format("2006-01-02 15:04") + " UTC"
			}
			bv.Accounts = append(bv.Accounts, av)
		}
		v.Backends = append(v.Backends, bv)
	}
	// Accounts no offered backend asks for can still be removed.
	for _, info := range stored {
		key := staleView{Backend: info.Backend, Account: info.Account}
		if shown[key] {
			continue
		}
		shown[key] = true
		v.Stale = append(v.Stale, key)
	}
	s.render(w, r, status, v)
}

// capitalize upper-cases the first letter of a message.
func capitalize(msg string) string {
	if msg == "" {
		return msg
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}
