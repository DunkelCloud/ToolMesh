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

package dadl

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/urlredact"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// resettableJar wraps an http.CookieJar so it can be cleared on re-login
// without replacing the jar reference held by multiple HTTP clients.
//
// A cookie jar keys cookies by host and path only, and Go's client asks it
// for every redirect hop after CheckRedirect ran. With a host scope set, the
// jar therefore answers only for destinations the scope allows (scheme,
// host and port), so a session cookie never follows a redirect to another
// port or scheme of the same host, and takes no cookies from such a
// destination either.
type resettableJar struct {
	mu    sync.Mutex
	jar   http.CookieJar
	scope *HostScope
}

// allows reports whether the jar may answer for or store cookies of u.
// The caller holds r.mu.
func (r *resettableJar) allows(u *url.URL) bool {
	return r.scope == nil || r.scope.check(u.Scheme, u.Hostname(), u.Port()).ok
}

// setScope binds the jar to the backend's host scope; nil unbinds it.
func (r *resettableJar) setScope(s *HostScope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scope = s
}

// SetCookies implements http.CookieJar. Cookies from a destination outside
// the host scope are dropped.
func (r *resettableJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.allows(u) {
		return
	}
	r.jar.SetCookies(u, cookies)
}

// Cookies implements http.CookieJar. A destination outside the host scope
// gets no cookies.
func (r *resettableJar) Cookies(u *url.URL) []*http.Cookie {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.allows(u) {
		return nil
	}
	return r.jar.Cookies(u)
}

// Reset discards all stored cookies by replacing the inner jar.
func (r *resettableJar) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}

// AuthConfig.Type values.
const (
	authTypeBearer  = "bearer"
	authTypeBasic   = "basic"
	authTypeAPIKey  = "apikey"
	authTypeOAuth2  = "oauth2"
	authTypeSession = "session"

	// authTypeAPIKeyAlias is accepted and normalized to authTypeAPIKey —
	// a Core Runtime MUST accept "api_key" as an alias (spec §15.4).
	authTypeAPIKeyAlias = "api_key"
)

// Common HTTP header names and API-key / session auth literals.
const (
	headerAuthorization = "Authorization"
	headerXAPIKey       = "X-API-Key" //nolint:gosec // header name, not a credential
	authInjectQuery     = "query"
	sessionRefreshLogin = "re_login"
)

// AuthConfig.Flow values for oauth2 auth. An empty flow defaults to
// client_credentials. The first two double as the grant_type sent to the
// token endpoint; jwt_bearer sends the RFC 7523 grant-type URN, and
// authorization_code renews via grant_type=refresh_token at runtime — its
// interactive consent leg lives in the setup tooling (spec §5.3).
const (
	oauth2FlowClientCredentials = "client_credentials" //nolint:gosec // OAuth2 grant_type value, not a credential
	oauth2FlowRefreshToken      = "refresh_token"      //nolint:gosec // OAuth2 grant_type value, not a credential
	oauth2FlowJWTBearer         = "jwt_bearer"
	oauth2FlowAuthorizationCode = "authorization_code"
)

// RestAuth manages authentication token lifecycle for REST API calls.
type RestAuth struct {
	config     AuthConfig
	baseURL    string
	creds      credentials.CredentialStore
	logger     *slog.Logger
	httpClient *http.Client
	cookieJar  *resettableJar // session auth: the jar shared with the adapter's clients

	// shared is the token state of a backend whose credentials belong to
	// the instance: one OAuth2 token, one session for all callers.
	shared *authState

	// perUser is set when the auth block reads a credential of the calling
	// user (SetPerUser). Token state then exists once per user and account,
	// in users, and nothing of one state is used for another's call.
	perUser     bool
	backendName string
	accounts    UserAccounts
	mu          sync.Mutex
	users       map[userStateKey]*authState

	// hostScope, when set, is the set of hosts credentials may be sent to
	// (SetScope); nil leaves the hosts unbound.
	hostScope *HostScope
}

// UserAccounts tells RestAuth which credentials belong to the calling user
// and which of the user's accounts a call uses.
// *credentials.UserScopedStore implements it.
type UserAccounts interface {
	// PerUser reports whether the credential name is read from the calling
	// user's namespace.
	PerUser(name string) bool
	// ResolveAccount returns the label of the account the call of tenant
	// uses, or an error that says why there is none.
	ResolveAccount(ctx context.Context, tenant credentials.TenantInfo) (string, error)
	// JSONValue reports whether the value of the credential name is a JSON
	// object that a login body carries as such, not as a string.
	JSONValue(name string) bool
}

// userStateKey names the token state of one account of one user.
type userStateKey struct {
	user    string
	account string
}

// authState is what RestAuth keeps between calls for one identity at the
// API: the backend as a whole, or one account of one user of a backend
// with per-user credentials. Its lock also serializes logins and token
// requests of that identity, so concurrent calls wait for one login instead
// of starting their own.
type authState struct {
	// sem is the lock, as a channel of one: a caller whose context ends
	// while it waits for another call's login gives up instead of waiting
	// that login out (see lock).
	sem             chan struct{}
	cachedToken     string
	tokenExpiry     time.Time
	sessionTokens   map[string]string // for session auth: token name → value
	sessionTokenTTL time.Time         // expiry time for session tokens
	// jar holds the cookies of a per-user session. The shared state uses
	// RestAuth.cookieJar, which the adapter's HTTP clients carry.
	jar      *resettableJar
	lastUsed time.Time
}

// newAuthState returns an empty state.
func newAuthState() *authState {
	return &authState{sem: make(chan struct{}, 1), sessionTokens: make(map[string]string)}
}

// lock takes the state for the caller. It fails when ctx ends first.
func (st *authState) lock(ctx context.Context) error {
	select {
	case st.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("gave up waiting for the login of another call: %w", ctx.Err())
	}
}

// unlock releases the state.
func (st *authState) unlock() { <-st.sem }

// Per-user states are dropped when there are maxUserAuthStates of them and
// one has not been used for userAuthStateIdle.
const (
	maxUserAuthStates = 256
	userAuthStateIdle = 2 * defaultSessionTTL
)

// NewRestAuth creates a RestAuth handler for the given auth configuration.
//
// Token and login requests never follow redirects: they carry client secrets,
// refresh tokens or login credentials in the body, and a 307/308 would re-send
// that body to wherever the redirect points. They use Go's default transport
// until the owner installs its own with SetTransport.
func NewRestAuth(config AuthConfig, baseURL string, creds credentials.CredentialStore, logger *slog.Logger) *RestAuth {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: refuseAuthRedirect,
	}

	var jar *resettableJar
	if config.Type == authTypeSession {
		// The public suffix list keeps a login response from setting a
		// cookie for a whole public suffix (e.g. ".co.uk"), which the
		// jar would then send to every host under it.
		inner, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
		jar = &resettableJar{jar: inner}
		client.Jar = jar
	}

	return &RestAuth{
		config:     config,
		baseURL:    baseURL,
		creds:      creds,
		logger:     logger,
		httpClient: client,
		cookieJar:  jar,
		shared:     newAuthState(),
		users:      make(map[userStateKey]*authState),
	}
}

// AuthExchangeError is returned when the API answers a session login or an
// OAuth2 token request with an HTTP error: the credentials were sent and
// not accepted, or the exchange failed on the API's side.
type AuthExchangeError struct {
	// What is "session login" or "oauth2 token request".
	What string
	// Status is the HTTP status of the answer.
	Status int
	// Body is the answer's body.
	Body string
}

// Error implements error.
func (e *AuthExchangeError) Error() string {
	return fmt.Sprintf("%s failed: HTTP %d: %s", e.What, e.Status, e.Body)
}

// Refused reports whether the status says the credentials were not
// accepted, as opposed to a failure of the API.
func (e *AuthExchangeError) Refused() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return true
	}
	return false
}

// refuseAuthRedirect is the CheckRedirect policy for token and login
// requests: no redirect is followed. The error names only the target host.
func refuseAuthRedirect(req *http.Request, _ []*http.Request) error {
	return fmt.Errorf("redirect to %s refused: token and login requests do not follow redirects", req.URL.Host)
}

// SetTransport sets the transport for token and login requests. The REST
// adapter passes the transport of its own backend client, so these requests
// get the same SSRF dial checks and TLS settings as tool calls. Call it before
// the first request; a nil transport keeps the current one.
func (a *RestAuth) SetTransport(rt http.RoundTripper) {
	if rt != nil {
		a.httpClient.Transport = rt
	}
}

// SetScope binds this RestAuth to the scopes of its backend: credentials are
// read only within creds, and sent, as tool request auth, token request or
// session login, only to hosts within hosts. The load-time CheckScope makes
// both checks unreachable for a valid configuration; they stay as a second
// line. A token URL that a jwt_bearer service-account credential supplies
// itself (token_uri) is operator data and not checked against hosts, unless
// users store that credential (SetPerUser): then it is checked. Call
// SetScope before the first request; nil leaves that side unbound.
func (a *RestAuth) SetScope(creds *CredentialScope, hosts *HostScope) {
	if creds != nil {
		a.creds = &scopedStore{inner: a.creds, scope: creds}
	}
	a.hostScope = hosts
	if a.cookieJar != nil {
		a.cookieJar.setScope(hosts)
	}
}

// CredentialNames returns the credential names the auth block reads for its
// type, as the DADL writes them: the fields of that type and every
// "credential:<name>" of a session login body. The NoCredential placeholder
// is not among them.
//
// For oauth2 only the names of the configured flow count: a
// refresh_token_credential next to the default client_credentials flow is
// never read, so it is not listed. A name that is declared per user but
// never read would otherwise leave a backend running on the instance's
// credentials while its users believe it uses theirs.
func (a AuthConfig) CredentialNames() []string {
	refs := readCredentialRefs(a)
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.name)
	}
	return names
}

// readCredentialRefs lists the credential names the runtime reads for the
// auth type and, for oauth2, its flow (see buildOAuth2TokenRequest).
func readCredentialRefs(auth AuthConfig) []credentialRef {
	if !strings.EqualFold(auth.Type, authTypeOAuth2) {
		return staticCredentialRefs(auth)
	}
	var refs []credentialRef
	add := func(where, name string) {
		if strings.TrimSpace(name) != "" && !isNoCredential(name) {
			refs = append(refs, credentialRef{where: where, name: name})
		}
	}
	switch auth.Flow {
	case oauth2FlowJWTBearer:
		add("auth.service_account_credential", auth.ServiceAccountCredential)
	case oauth2FlowRefreshToken, oauth2FlowAuthorizationCode:
		add("auth.client_id_credential", auth.ClientIDCredential)
		add("auth.refresh_token_credential", auth.RefreshTokenCredential)
		add("auth.client_secret_credential", auth.ClientSecretCredential)
	default:
		add("auth.client_id_credential", auth.ClientIDCredential)
		add("auth.client_secret_credential", auth.ClientSecretCredential)
	}
	return refs
}

// SetPerUser tells RestAuth which credential names belong to the calling
// user instead of the instance (user_credentials in backends.yaml). When
// the auth block reads one of them, everything RestAuth keeps between
// calls, the OAuth2 token, the session tokens and the session's cookies,
// exists once per user and account, and a call without a user is refused.
// backend is the backend's name for messages. Call it before the first
// request and before CookieJar; nil keeps every credential with the
// instance.
func (a *RestAuth) SetPerUser(backend string, accounts UserAccounts) {
	a.backendName = backend
	a.perUser = false
	a.accounts = nil
	if accounts == nil {
		return
	}
	for _, name := range a.config.CredentialNames() {
		if accounts.PerUser(name) {
			a.perUser = true
			a.accounts = accounts
			// Per-user sessions keep their cookies per user; the clients
			// carry no jar (see CookieJar).
			a.httpClient.Jar = nil
			return
		}
	}
}

// PerUser reports whether the auth block reads a credential of the calling
// user.
func (a *RestAuth) PerUser() bool { return a.perUser }

// ForgetAccount drops what RestAuth keeps for one account of userID: its
// OAuth2 token, its session and the session's cookies. The account's next
// call authenticates anew, with the credentials stored then. The other
// accounts of the user keep their sessions. Call it when a user changes or
// removes the credentials of the account.
func (a *RestAuth) ForgetAccount(userID, account string) {
	if label, ok := credentials.NormalizeAccount(account); ok {
		account = label
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.users, userStateKey{user: userID, account: account})
}

// stateFor returns the token state and the tenant of the call in ctx: the
// shared state for a backend with instance credentials; for a backend with
// per-user credentials the state of the caller's account, which is
// resolved first, so a state is never used for a call that names another
// account or, with several stored, none.
func (a *RestAuth) stateFor(ctx context.Context) (*authState, credentials.TenantInfo, error) {
	var tenant credentials.TenantInfo
	uc := userctx.FromContext(ctx)
	if uc != nil {
		tenant = credentials.TenantInfo{
			CompanyID:   uc.CompanyID,
			UserID:      uc.UserID,
			CallerID:    uc.CallerID,
			CallerClass: uc.CallerClass,
		}
	}
	if !a.perUser {
		return a.shared, tenant, nil
	}
	// Only an authenticated caller has accounts: an anonymous one is no
	// user, whatever id it carries.
	if uc == nil || !uc.Authenticated || tenant.UserID == "" {
		return nil, tenant, &credentials.UserCredentialError{
			Backend: a.backendName,
			Reason:  credentials.UserCredentialNoUser,
		}
	}
	tenant.Account = credentials.AccountFromContext(ctx)
	account, err := a.accounts.ResolveAccount(ctx, tenant)
	if err != nil {
		return nil, tenant, err
	}
	tenant.Account = account
	key := userStateKey{user: tenant.UserID, account: account}

	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	st, ok := a.users[key]
	if !ok {
		if len(a.users) >= maxUserAuthStates {
			for k, other := range a.users {
				if now.Sub(other.lastUsed) > userAuthStateIdle {
					delete(a.users, k)
				}
			}
		}
		st = newAuthState()
		if a.config.Type == authTypeSession {
			st.jar = a.newUserJar()
		}
		a.users[key] = st
	}
	st.lastUsed = now
	return st, tenant, nil
}

// newUserJar returns an empty cookie jar for one user's session, bound to
// the backend's host scope.
func (a *RestAuth) newUserJar() *resettableJar {
	inner, _ := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	return &resettableJar{jar: inner, scope: a.hostScope}
}

// checkHost refuses to send credentials to a host outside the scope.
func (a *RestAuth) checkHost(rawURL string) error {
	if a.hostScope == nil {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("credentials not sent: parse %q: %w", rawURL, err)
	}
	if d := a.hostScope.check(u.Scheme, u.Hostname(), u.Port()); !d.ok {
		return fmt.Errorf("credentials are not sent to %s://%s: %s (allowed_hosts in backends.yaml)", u.Scheme, u.Host, d.reason)
	}
	return nil
}

// CookieJar returns the shared cookie jar, or nil if cookie forwarding
// is not enabled. The RESTAdapter uses this to attach the same jar to
// its HTTP clients so cookies from login are sent with tool requests.
//
// With per-user credentials it returns nil: a jar on the clients would mix
// the cookies of all users. RestAuth then keeps the cookies of each user's
// login itself and adds them to that user's requests; cookies a tool
// response sets are not kept.
func (a *RestAuth) CookieJar() http.CookieJar {
	if a.cookieJar == nil || a.perUser {
		return nil
	}
	return a.cookieJar
}

// InjectAuth adds authentication credentials to an HTTP request.
func (a *RestAuth) InjectAuth(ctx context.Context, req *http.Request) error {
	if a.config.Type != "" {
		if err := a.checkHost(req.URL.String()); err != nil {
			return err
		}
	}
	if a.config.Type == "" {
		return nil // no auth
	}
	st, tenant, err := a.stateFor(ctx)
	if err != nil {
		return err
	}
	switch a.config.Type {
	case authTypeBearer:
		return a.injectBearer(ctx, req, tenant)
	case authTypeBasic:
		return a.injectBasic(ctx, req, tenant)
	case authTypeAPIKey:
		return a.injectAPIKey(ctx, req, tenant)
	case authTypeOAuth2:
		return a.injectOAuth2(ctx, req, st, tenant)
	case authTypeSession:
		return a.injectSession(ctx, req, st, tenant)
	default:
		return fmt.Errorf("unsupported auth type: %s", a.config.Type)
	}
}

// CanReauthenticate reports whether HandleUnauthorized can renew the
// credential — a session re-login or a fresh OAuth2 token — so that a retry
// after a 401 may succeed. For static credentials a retry would only repeat
// the rejected request.
func (a *RestAuth) CanReauthenticate() bool {
	switch a.config.Type {
	case authTypeSession:
		return a.config.Refresh != nil && a.config.Refresh.Action == sessionRefreshLogin
	case authTypeOAuth2:
		return true
	}
	return false
}

// HandleUnauthorized is called when a 401 response is received.
// For session auth, it triggers re-login. With per-user credentials it
// renews the state of the user in ctx only.
func (a *RestAuth) HandleUnauthorized(ctx context.Context) error {
	return a.HandleUnauthorizedFor(ctx, nil)
}

// HandleUnauthorizedFor is HandleUnauthorized for the request that was
// answered 401. When that request carried another session or token than
// the current one, a concurrent call has renewed it meanwhile: nothing is
// renewed again, and the caller's retry uses the current one. Several calls
// that fail at once on an expired session therefore cause one re-login.
// With a nil request the session is always renewed.
func (a *RestAuth) HandleUnauthorizedFor(ctx context.Context, sent *http.Request) error {
	renewsSession := a.config.Type == authTypeSession && a.config.Refresh != nil && a.config.Refresh.Action == sessionRefreshLogin
	if !renewsSession && a.config.Type != authTypeOAuth2 {
		return nil
	}
	st, tenant, err := a.stateFor(ctx)
	if err != nil {
		return err
	}
	if err := st.lock(ctx); err != nil {
		return err
	}
	defer st.unlock()
	if renewsSession {
		if sent != nil && a.sessionRenewedSince(st, sent) {
			return nil
		}
		st.sessionTokens = make(map[string]string)
		if jar := a.jarOf(st); jar != nil {
			jar.Reset()
		}
		return a.doSessionLogin(ctx, st, tenant)
	}
	if sent != nil && st.cachedToken != "" && sent.Header.Get(headerAuthorization) != "Bearer "+st.cachedToken {
		return nil
	}
	st.cachedToken = ""
	st.tokenExpiry = time.Time{}
	return nil // next request will fetch a new token
}

// sessionRenewedSince reports whether the session in st is another one
// than the request sent was built with. Only sessions whose tokens travel
// in headers can be compared; for the others it reports false. The caller
// holds the state's lock.
func (a *RestAuth) sessionRenewedSince(st *authState, sent *http.Request) bool {
	if len(st.sessionTokens) == 0 {
		return false
	}
	for _, rule := range a.config.Inject {
		if sent.Header.Get(rule.Header) != sessionHeaderValue(rule, st) {
			return true
		}
	}
	return false
}

// sessionHeaderValue fills the session's tokens into the value of an inject
// rule.
func sessionHeaderValue(rule InjectRule, st *authState) string {
	value := rule.Value
	for name, token := range st.sessionTokens {
		value = strings.ReplaceAll(value, "{{"+name+"}}", token)
	}
	return value
}

// credentialNotSet decides what a credential the store does not have means.
// For a backend with credentials of the instance the call goes out without
// authentication, as it always has: public endpoints of an API work without
// a key. A backend that authenticates as the calling user never does that:
// a call that should carry a user's identity is not sent without one.
func (a *RestAuth) credentialNotSet(ctx context.Context, msg, name string) error {
	if a.perUser {
		return fmt.Errorf("credential %q is not set, and backend %q authenticates as the calling user: the call is not sent without authentication", name, a.backendName)
	}
	a.logger.InfoContext(ctx, msg, "credential", name)
	return nil
}

// jarOf returns the cookie jar of a session state: the user's own with
// per-user credentials, the shared one otherwise.
func (a *RestAuth) jarOf(st *authState) *resettableJar {
	if st.jar != nil {
		return st.jar
	}
	return a.cookieJar
}

func (a *RestAuth) injectBearer(ctx context.Context, req *http.Request, tenant credentials.TenantInfo) error {
	token, err := a.creds.Get(ctx, a.config.Credential, tenant)
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			return a.credentialNotSet(ctx, "bearer credential not found, skipping auth header", a.config.Credential)
		}
		return fmt.Errorf("get bearer credential %q: %w", a.config.Credential, err)
	}

	headerName := a.config.HeaderName
	if headerName == "" {
		headerName = headerAuthorization
	}
	prefix := a.config.Prefix
	if prefix == "" {
		prefix = "Bearer "
	}
	req.Header.Set(headerName, prefix+token)
	return nil
}

func (a *RestAuth) injectBasic(ctx context.Context, req *http.Request, tenant credentials.TenantInfo) error {
	username, err := a.creds.Get(ctx, a.config.UsernameCredential, tenant)
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			return a.credentialNotSet(ctx, "basic auth credential not found, skipping auth header", a.config.UsernameCredential)
		}
		return fmt.Errorf("get basic username credential %q: %w", a.config.UsernameCredential, err)
	}

	var password string
	if a.config.PasswordCredential != "" {
		password, err = a.creds.Get(ctx, a.config.PasswordCredential, tenant)
		if err != nil {
			if errors.Is(err, credentials.ErrCredentialNotFound) {
				return a.credentialNotSet(ctx, "basic auth password credential not found, skipping auth header", a.config.PasswordCredential)
			}
			return fmt.Errorf("get basic password credential %q: %w", a.config.PasswordCredential, err)
		}
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set(headerAuthorization, "Basic "+encoded)
	return nil
}

func (a *RestAuth) injectAPIKey(ctx context.Context, req *http.Request, tenant credentials.TenantInfo) error {
	key, err := a.creds.Get(ctx, a.config.Credential, tenant)
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			return a.credentialNotSet(ctx, "apikey credential not found, skipping auth header", a.config.Credential)
		}
		return fmt.Errorf("get apikey credential %q: %w", a.config.Credential, err)
	}

	if a.config.InjectInto == authInjectQuery {
		q := req.URL.Query()
		q.Set(a.config.QueryParam, key)
		req.URL.RawQuery = q.Encode()
	} else {
		headerName := a.config.HeaderName
		if headerName == "" {
			headerName = headerXAPIKey
		}
		prefix := a.config.Prefix
		req.Header.Set(headerName, prefix+key)
	}
	return nil
}

func (a *RestAuth) injectOAuth2(ctx context.Context, req *http.Request, st *authState, tenant credentials.TenantInfo) error {
	token, err := a.getOAuth2Token(ctx, st, tenant)
	if err != nil {
		return err
	}
	if token == "" {
		return a.credentialNotSet(ctx, "oauth2 credentials not found, skipping auth header", "oauth2")
	}
	req.Header.Set(headerAuthorization, "Bearer "+token)
	return nil
}

func (a *RestAuth) getOAuth2Token(ctx context.Context, st *authState, tenant credentials.TenantInfo) (string, error) {
	if err := st.lock(ctx); err != nil {
		return "", err
	}
	defer st.unlock()

	// Check cache
	refreshBefore := parseDelayOrDefault(a.config.RefreshBeforeExpiry, 30*time.Second)
	if st.cachedToken != "" && time.Now().Add(refreshBefore).Before(st.tokenExpiry) {
		return st.cachedToken, nil
	}

	// Fetch new token
	data, tokenURL, err := a.buildOAuth2TokenRequest(ctx, tenant)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil // required credential missing: caller skips the auth header
	}
	// A declared token_url must be one of the backend's hosts. A token_uri
	// taken from a jwt_bearer service-account credential is operator data
	// when the operator stored that credential; when a user did, it has to
	// be one of the backend's hosts as well.
	if a.config.TokenURL != "" || a.perUser {
		if err := a.checkHost(tokenURL); err != nil {
			return "", fmt.Errorf("oauth2 token request: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create oauth2 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth2 token request: %w", urlredact.TransportError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read oauth2 token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", &AuthExchangeError{What: "oauth2 token request", Status: resp.StatusCode, Body: string(body)}
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse oauth2 token response: %w", err)
	}

	if tokenResp.AccessToken == "" && a.perUser {
		// Not cached and not sent: the call fails instead of going out
		// without the user's token.
		return "", errors.New("oauth2 token request: the answer carries no access_token")
	}
	st.cachedToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		st.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		st.tokenExpiry = time.Now().Add(time.Hour) // default 1h
	}

	a.logger.Info("oauth2 token acquired", "flow", data.Get("grant_type"), "expires_in", tokenResp.ExpiresIn, "per_user", a.perUser)
	return st.cachedToken, nil
}

// buildOAuth2TokenRequest assembles the token-endpoint form values and the
// endpoint URL for the configured oauth2 flow. It returns (nil, "", nil)
// when a required credential is not in the store — callers treat that as
// "skip auth", consistent with the other inject* methods.
func (a *RestAuth) buildOAuth2TokenRequest(ctx context.Context, tenant credentials.TenantInfo) (url.Values, string, error) {
	tokenURL := a.config.TokenURL

	// jwt_bearer needs no client_id — the signed assertion is the client
	// identity (RFC 7523).
	if a.config.Flow == oauth2FlowJWTBearer {
		raw, err := a.creds.Get(ctx, a.config.ServiceAccountCredential, tenant)
		if err != nil {
			if errors.Is(err, credentials.ErrCredentialNotFound) {
				return nil, "", nil
			}
			return nil, "", fmt.Errorf("get oauth2 service account: %w", err)
		}
		key, err := parseServiceAccountKey(raw)
		if err != nil {
			return nil, "", err
		}
		// A declared token_url takes precedence; else the key's token_uri.
		if tokenURL == "" {
			tokenURL = key.TokenURI
		}
		if tokenURL == "" {
			return nil, "", fmt.Errorf("jwt_bearer: no token_url declared and service account key has no token_uri")
		}
		assertion, err := buildJWTAssertion(key, tokenURL, a.config.Subject, a.config.Scopes, time.Now())
		if err != nil {
			return nil, "", err
		}
		return url.Values{
			"grant_type": {jwtBearerGrantType},
			"assertion":  {assertion},
		}, tokenURL, nil
	}

	clientID, err := a.creds.Get(ctx, a.config.ClientIDCredential, tenant)
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("get oauth2 client_id: %w", err)
	}
	data := url.Values{"client_id": {clientID}}

	switch a.config.Flow {
	case oauth2FlowRefreshToken, oauth2FlowAuthorizationCode:
		// authorization_code differs from refresh_token only in how the
		// refresh token came to exist (consent driven by the setup tooling,
		// spec §5.3) — runtime renewal is the same silent exchange.
		refreshToken, err := a.creds.Get(ctx, a.config.RefreshTokenCredential, tenant)
		if err != nil {
			if errors.Is(err, credentials.ErrCredentialNotFound) {
				if a.config.Flow == oauth2FlowAuthorizationCode {
					a.logger.InfoContext(ctx, "authorization_code refresh token not in store — run the setup flow to complete consent",
						"credential", a.config.RefreshTokenCredential)
				}
				return nil, "", nil
			}
			return nil, "", fmt.Errorf("get oauth2 refresh_token: %w", err)
		}
		data.Set("grant_type", oauth2FlowRefreshToken)
		data.Set("refresh_token", refreshToken)
		// Scopes are fixed at consent time for these flows, so no scope
		// parameter is sent. client_secret is optional: public (PKCE)
		// clients have none.
		if a.config.ClientSecretCredential != "" {
			clientSecret, err := a.creds.Get(ctx, a.config.ClientSecretCredential, tenant)
			if err != nil {
				if errors.Is(err, credentials.ErrCredentialNotFound) {
					return nil, "", nil
				}
				return nil, "", fmt.Errorf("get oauth2 client_secret: %w", err)
			}
			data.Set("client_secret", clientSecret)
		}
	default: // "" defaults to client_credentials
		clientSecret, err := a.creds.Get(ctx, a.config.ClientSecretCredential, tenant)
		if err != nil {
			if errors.Is(err, credentials.ErrCredentialNotFound) {
				return nil, "", nil
			}
			return nil, "", fmt.Errorf("get oauth2 client_secret: %w", err)
		}
		data.Set("grant_type", oauth2FlowClientCredentials)
		data.Set("client_secret", clientSecret)
		if len(a.config.Scopes) > 0 {
			data.Set("scope", strings.Join(a.config.Scopes, " "))
		}
	}
	return data, tokenURL, nil
}

// defaultSessionTTL is the maximum lifetime for session tokens before re-login.
const defaultSessionTTL = time.Hour

// injectSession logs in when the state has no live session and sets the
// session's headers on req. The state stays locked from the check to the
// injection, so a request never goes out with the tokens of a session that
// a concurrent re-login has just discarded.
func (a *RestAuth) injectSession(ctx context.Context, req *http.Request, st *authState, tenant credentials.TenantInfo) error {
	if err := st.lock(ctx); err != nil {
		return err
	}
	defer st.unlock()

	if !st.sessionTokenTTL.IsZero() && time.Now().After(st.sessionTokenTTL) {
		st.sessionTokens = make(map[string]string)
	}
	if len(st.sessionTokens) == 0 {
		if err := a.doSessionLogin(ctx, st, tenant); err != nil {
			return err
		}
	}

	for _, rule := range a.config.Inject {
		req.Header.Set(rule.Header, sessionHeaderValue(rule, st))
	}
	// The cookies of a per-user login travel with that user's requests
	// only; the clients carry no jar (see CookieJar).
	if st.jar != nil {
		for _, c := range st.jar.Cookies(req.URL) {
			req.AddCookie(c)
		}
	}
	return nil
}

// doSessionLogin logs in and stores the session's tokens in st. The caller
// holds the state's lock.
func (a *RestAuth) doSessionLogin(ctx context.Context, st *authState, tenant credentials.TenantInfo) error {
	if a.config.Login == nil {
		return fmt.Errorf("session auth requires login config")
	}

	loginURL, err := sessionLoginURL(a.baseURL, a.config.Login.Path)
	if err != nil {
		return err
	}
	if err := a.checkHost(loginURL); err != nil {
		return fmt.Errorf("session login: %w", err)
	}

	// Resolve credential references anywhere in the (possibly nested) login body.
	// Body is map[string]any, so a JSON-RPC-style login can nest credentials inside
	// an object — e.g. {"method":"account.login","params":{"user":"credential:..",
	// "pass":"credential:.."}} — not just at the top level.
	// A field listed in login.optional is left out when its credential has no
	// value (resolveLoginBody).
	resolvedBody, err := a.resolveLoginBody(ctx, tenant)
	if err != nil {
		return err
	}

	bodyJSON, err := json.Marshal(resolvedBody)
	if err != nil {
		return fmt.Errorf("marshal login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, a.config.Login.Method, loginURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := a.httpClient
	if st.jar != nil {
		// A per-user login keeps its cookies in the user's own jar.
		userClient := *a.httpClient
		userClient.Jar = st.jar
		client = &userClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("session login request: %w", urlredact.TransportError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &AuthExchangeError{What: "session login", Status: resp.StatusCode, Body: string(respBody)}
	}

	// Extract tokens
	var respData any
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}

	// All tokens or none: a login whose answer lacks one of them leaves no
	// partial session behind.
	tokens := make(map[string]string, len(a.config.Login.Extract))
	for name, jpExpr := range a.config.Login.Extract {
		jp, err := NewJSONPath(jpExpr)
		if err != nil {
			return fmt.Errorf("parse extract path %q: %w", jpExpr, err)
		}
		val, err := jp.Extract(respData)
		if err != nil {
			return fmt.Errorf("extract token %q: %w", name, err)
		}
		tokens[name] = fmt.Sprintf("%v", val)
	}
	st.sessionTokens = tokens

	st.sessionTokenTTL = time.Now().Add(defaultSessionTTL)
	a.logger.Info("session login successful", "tokens", len(st.sessionTokens), "ttl", defaultSessionTTL, "per_user", a.perUser)
	return nil
}

// sessionLoginURL appends the login path to the base URL, as the DADL spec
// describes, and verifies that the result still points at the base URL's
// scheme and host. Plain concatenation would let a path such as
// "@attacker.example/x" or ".attacker.example/x" move the login request, and
// the credentials in its body, to another host when base_url has no path.
func sessionLoginURL(baseURL, loginPath string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("session login: parse base_url: %w", err)
	}
	joined := baseURL + loginPath
	u, err := url.Parse(joined)
	if err != nil {
		return "", fmt.Errorf("session login: parse login URL: %w", err)
	}
	if u.User.String() != base.User.String() || !strings.EqualFold(u.Scheme, base.Scheme) || !strings.EqualFold(u.Host, base.Host) ||
		!strings.HasPrefix(u.Path, base.Path) {
		return "", fmt.Errorf("session login: login.path %q does not stay on the base_url host %s; it must start with \"/\"", loginPath, base.Host)
	}
	return joined, nil
}

// resolveLoginCredentials walks a session-login body and replaces any string of
// the form "credential:<name>" with the resolved secret, at any depth. This lets
// a login body nest credentials inside an object (e.g. a JSON-RPC envelope's
// params:{user,pass}) instead of only at the top level. Maps and slices are
// rebuilt; all other values pass through unchanged.
func (a *RestAuth) resolveLoginCredentials(ctx context.Context, v any, tenant credentials.TenantInfo) (any, error) {
	switch val := v.(type) {
	case string:
		name, ok := strings.CutPrefix(val, "credential:")
		if !ok {
			return val, nil
		}
		resolved, err := a.creds.Get(ctx, name, tenant)
		if err != nil {
			return nil, fmt.Errorf("resolve login credential %q: %w", name, err)
		}
		return a.loginValue(name, resolved)
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			resolved, err := a.resolveLoginCredentials(ctx, child, tenant)
			if err != nil {
				return nil, err
			}
			out[k] = resolved
		}
		return out, nil
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			resolved, err := a.resolveLoginCredentials(ctx, child, tenant)
			if err != nil {
				return nil, err
			}
			out[i] = resolved
		}
		return out, nil
	default:
		return v, nil
	}
}
