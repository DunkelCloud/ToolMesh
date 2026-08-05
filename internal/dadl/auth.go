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

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// resettableJar wraps an http.CookieJar so it can be cleared on re-login
// without replacing the jar reference held by multiple HTTP clients.
type resettableJar struct {
	mu  sync.Mutex
	jar http.CookieJar
}

// SetCookies implements http.CookieJar.
func (r *resettableJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jar.SetCookies(u, cookies)
}

// Cookies implements http.CookieJar.
func (r *resettableJar) Cookies(u *url.URL) []*http.Cookie {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jar.Cookies(u)
}

// Reset discards all stored cookies by replacing the inner jar.
func (r *resettableJar) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.jar, _ = cookiejar.New(nil)
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
	cookieJar  *resettableJar // non-nil when login.cookies = "forward"

	mu              sync.Mutex
	cachedToken     string
	tokenExpiry     time.Time
	sessionTokens   map[string]string // for session auth: token name → value
	sessionTokenTTL time.Time         // expiry time for session tokens
}

// NewRestAuth creates a RestAuth handler for the given auth configuration.
func NewRestAuth(config AuthConfig, baseURL string, creds credentials.CredentialStore, logger *slog.Logger) *RestAuth {
	client := &http.Client{Timeout: 30 * time.Second}

	var jar *resettableJar
	if config.Type == authTypeSession {
		inner, _ := cookiejar.New(nil)
		jar = &resettableJar{jar: inner}
		client.Jar = jar
	}

	return &RestAuth{
		config:        config,
		baseURL:       baseURL,
		creds:         creds,
		logger:        logger,
		httpClient:    client,
		cookieJar:     jar,
		sessionTokens: make(map[string]string),
	}
}

// CookieJar returns the shared cookie jar, or nil if cookie forwarding
// is not enabled. The RESTAdapter uses this to attach the same jar to
// its HTTP clients so cookies from login are sent with tool requests.
func (a *RestAuth) CookieJar() http.CookieJar {
	if a.cookieJar == nil {
		return nil
	}
	return a.cookieJar
}

// InjectAuth adds authentication credentials to an HTTP request.
func (a *RestAuth) InjectAuth(ctx context.Context, req *http.Request) error {
	switch a.config.Type {
	case authTypeBearer:
		return a.injectBearer(ctx, req)
	case authTypeBasic:
		return a.injectBasic(ctx, req)
	case authTypeAPIKey:
		return a.injectAPIKey(ctx, req)
	case authTypeOAuth2:
		return a.injectOAuth2(ctx, req)
	case authTypeSession:
		return a.injectSession(ctx, req)
	case "":
		return nil // no auth
	default:
		return fmt.Errorf("unsupported auth type: %s", a.config.Type)
	}
}

// HandleUnauthorized is called when a 401 response is received.
// For session auth, it triggers re-login.
func (a *RestAuth) HandleUnauthorized(ctx context.Context) error {
	if a.config.Type == authTypeSession && a.config.Refresh != nil && a.config.Refresh.Action == sessionRefreshLogin {
		a.mu.Lock()
		a.sessionTokens = make(map[string]string)
		a.mu.Unlock()
		if a.cookieJar != nil {
			a.cookieJar.Reset()
		}
		return a.doSessionLogin(ctx)
	}
	if a.config.Type == authTypeOAuth2 {
		a.mu.Lock()
		a.cachedToken = ""
		a.tokenExpiry = time.Time{}
		a.mu.Unlock()
		return nil // next request will fetch a new token
	}
	return nil
}

func (a *RestAuth) injectBearer(ctx context.Context, req *http.Request) error {
	token, err := a.creds.Get(ctx, a.config.Credential, credentials.TenantInfo{})
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			a.logger.InfoContext(ctx, "bearer credential not found, skipping auth header", "credential", a.config.Credential)
			return nil
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

func (a *RestAuth) injectBasic(ctx context.Context, req *http.Request) error {
	username, err := a.creds.Get(ctx, a.config.UsernameCredential, credentials.TenantInfo{})
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			a.logger.InfoContext(ctx, "basic auth credential not found, skipping auth header", "credential", a.config.UsernameCredential)
			return nil
		}
		return fmt.Errorf("get basic username credential %q: %w", a.config.UsernameCredential, err)
	}

	var password string
	if a.config.PasswordCredential != "" {
		password, err = a.creds.Get(ctx, a.config.PasswordCredential, credentials.TenantInfo{})
		if err != nil {
			if errors.Is(err, credentials.ErrCredentialNotFound) {
				a.logger.InfoContext(ctx, "basic auth password credential not found, skipping auth header", "credential", a.config.PasswordCredential)
				return nil
			}
			return fmt.Errorf("get basic password credential %q: %w", a.config.PasswordCredential, err)
		}
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	req.Header.Set(headerAuthorization, "Basic "+encoded)
	return nil
}

func (a *RestAuth) injectAPIKey(ctx context.Context, req *http.Request) error {
	key, err := a.creds.Get(ctx, a.config.Credential, credentials.TenantInfo{})
	if err != nil {
		if errors.Is(err, credentials.ErrCredentialNotFound) {
			a.logger.InfoContext(ctx, "apikey credential not found, skipping auth header", "credential", a.config.Credential)
			return nil
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

func (a *RestAuth) injectOAuth2(ctx context.Context, req *http.Request) error {
	token, err := a.getOAuth2Token(ctx)
	if err != nil {
		return err
	}
	if token == "" {
		a.logger.InfoContext(ctx, "oauth2 credentials not found, skipping auth header")
		return nil
	}
	req.Header.Set(headerAuthorization, "Bearer "+token)
	return nil
}

func (a *RestAuth) getOAuth2Token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Check cache
	refreshBefore := parseDelayOrDefault(a.config.RefreshBeforeExpiry, 30*time.Second)
	if a.cachedToken != "" && time.Now().Add(refreshBefore).Before(a.tokenExpiry) {
		return a.cachedToken, nil
	}

	// Fetch new token
	data, tokenURL, err := a.buildOAuth2TokenRequest(ctx)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil // required credential missing: caller skips the auth header
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create oauth2 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth2 token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read oauth2 token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth2 token request failed: HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("parse oauth2 token response: %w", err)
	}

	a.cachedToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		a.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	} else {
		a.tokenExpiry = time.Now().Add(time.Hour) // default 1h
	}

	a.logger.Info("oauth2 token acquired", "flow", data.Get("grant_type"), "expires_in", tokenResp.ExpiresIn)
	return a.cachedToken, nil
}

// buildOAuth2TokenRequest assembles the token-endpoint form values and the
// endpoint URL for the configured oauth2 flow. It returns (nil, "", nil)
// when a required credential is not in the store — callers treat that as
// "skip auth", consistent with the other inject* methods.
func (a *RestAuth) buildOAuth2TokenRequest(ctx context.Context) (url.Values, string, error) {
	tokenURL := a.config.TokenURL

	// jwt_bearer needs no client_id — the signed assertion is the client
	// identity (RFC 7523).
	if a.config.Flow == oauth2FlowJWTBearer {
		raw, err := a.creds.Get(ctx, a.config.ServiceAccountCredential, credentials.TenantInfo{})
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

	clientID, err := a.creds.Get(ctx, a.config.ClientIDCredential, credentials.TenantInfo{})
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
		refreshToken, err := a.creds.Get(ctx, a.config.RefreshTokenCredential, credentials.TenantInfo{})
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
			clientSecret, err := a.creds.Get(ctx, a.config.ClientSecretCredential, credentials.TenantInfo{})
			if err != nil {
				if errors.Is(err, credentials.ErrCredentialNotFound) {
					return nil, "", nil
				}
				return nil, "", fmt.Errorf("get oauth2 client_secret: %w", err)
			}
			data.Set("client_secret", clientSecret)
		}
	default: // "" defaults to client_credentials
		clientSecret, err := a.creds.Get(ctx, a.config.ClientSecretCredential, credentials.TenantInfo{})
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

func (a *RestAuth) injectSession(ctx context.Context, req *http.Request) error {
	a.mu.Lock()
	hasTokens := len(a.sessionTokens) > 0
	expired := !a.sessionTokenTTL.IsZero() && time.Now().After(a.sessionTokenTTL)
	a.mu.Unlock()

	if expired {
		a.mu.Lock()
		a.sessionTokens = make(map[string]string)
		a.mu.Unlock()
		hasTokens = false
	}

	if !hasTokens {
		if err := a.doSessionLogin(ctx); err != nil {
			return err
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, rule := range a.config.Inject {
		value := rule.Value
		for name, token := range a.sessionTokens {
			value = strings.ReplaceAll(value, "{{"+name+"}}", token)
		}
		req.Header.Set(rule.Header, value)
	}
	return nil
}

func (a *RestAuth) doSessionLogin(ctx context.Context) error {
	if a.config.Login == nil {
		return fmt.Errorf("session auth requires login config")
	}

	loginURL := a.baseURL + a.config.Login.Path

	// Resolve credential references anywhere in the (possibly nested) login body.
	// Body is map[string]any, so a JSON-RPC-style login can nest credentials inside
	// an object — e.g. {"method":"account.login","params":{"user":"credential:..",
	// "pass":"credential:.."}} — not just at the top level.
	resolvedBody, err := a.resolveLoginCredentials(ctx, a.config.Login.Body)
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

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("session login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read login response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("session login failed: HTTP %d: %s", resp.StatusCode, respBody)
	}

	// Extract tokens
	var respData any
	if err := json.Unmarshal(respBody, &respData); err != nil {
		return fmt.Errorf("parse login response: %w", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	for name, jpExpr := range a.config.Login.Extract {
		jp, err := NewJSONPath(jpExpr)
		if err != nil {
			return fmt.Errorf("parse extract path %q: %w", jpExpr, err)
		}
		val, err := jp.Extract(respData)
		if err != nil {
			return fmt.Errorf("extract token %q: %w", name, err)
		}
		a.sessionTokens[name] = fmt.Sprintf("%v", val)
	}

	a.sessionTokenTTL = time.Now().Add(defaultSessionTTL)
	a.logger.Info("session login successful", "tokens", len(a.sessionTokens), "ttl", defaultSessionTTL)
	return nil
}

// resolveLoginCredentials walks a session-login body and replaces any string of
// the form "credential:<name>" with the resolved secret, at any depth. This lets
// a login body nest credentials inside an object (e.g. a JSON-RPC envelope's
// params:{user,pass}) instead of only at the top level. Maps and slices are
// rebuilt; all other values pass through unchanged.
func (a *RestAuth) resolveLoginCredentials(ctx context.Context, v any) (any, error) {
	switch val := v.(type) {
	case string:
		name, ok := strings.CutPrefix(val, "credential:")
		if !ok {
			return val, nil
		}
		resolved, err := a.creds.Get(ctx, name, credentials.TenantInfo{})
		if err != nil {
			return nil, fmt.Errorf("resolve login credential %q: %w", name, err)
		}
		return resolved, nil
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, child := range val {
			resolved, err := a.resolveLoginCredentials(ctx, child)
			if err != nil {
				return nil, err
			}
			out[k] = resolved
		}
		return out, nil
	case []any:
		out := make([]any, len(val))
		for i, child := range val {
			resolved, err := a.resolveLoginCredentials(ctx, child)
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
