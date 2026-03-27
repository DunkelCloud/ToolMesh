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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// RestAuth manages authentication token lifecycle for REST API calls.
type RestAuth struct {
	config  AuthConfig
	baseURL string
	creds   credentials.CredentialStore
	logger  *slog.Logger

	mu            sync.Mutex
	cachedToken   string
	tokenExpiry   time.Time
	sessionTokens map[string]string // for session auth: token name → value
}

// NewRestAuth creates a RestAuth handler for the given auth configuration.
func NewRestAuth(config AuthConfig, baseURL string, creds credentials.CredentialStore, logger *slog.Logger) *RestAuth {
	return &RestAuth{
		config:        config,
		baseURL:       baseURL,
		creds:         creds,
		logger:        logger,
		sessionTokens: make(map[string]string),
	}
}

// InjectAuth adds authentication credentials to an HTTP request.
func (a *RestAuth) InjectAuth(ctx context.Context, req *http.Request) error {
	switch a.config.Type {
	case "bearer":
		return a.injectBearer(ctx, req)
	case "apikey":
		return a.injectAPIKey(ctx, req)
	case "oauth2":
		return a.injectOAuth2(ctx, req)
	case "session":
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
	if a.config.Type == "session" && a.config.Refresh != nil && a.config.Refresh.Action == "re_login" {
		a.mu.Lock()
		a.sessionTokens = make(map[string]string)
		a.mu.Unlock()
		return a.doSessionLogin(ctx)
	}
	if a.config.Type == "oauth2" {
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
		return fmt.Errorf("get bearer credential %q: %w", a.config.Credential, err)
	}

	headerName := a.config.HeaderName
	if headerName == "" {
		headerName = "Authorization"
	}
	prefix := a.config.Prefix
	if prefix == "" {
		prefix = "Bearer "
	}
	req.Header.Set(headerName, prefix+token)
	return nil
}

func (a *RestAuth) injectAPIKey(ctx context.Context, req *http.Request) error {
	key, err := a.creds.Get(ctx, a.config.Credential, credentials.TenantInfo{})
	if err != nil {
		return fmt.Errorf("get apikey credential %q: %w", a.config.Credential, err)
	}

	if a.config.InjectInto == "query" {
		q := req.URL.Query()
		q.Set(a.config.QueryParam, key)
		req.URL.RawQuery = q.Encode()
	} else {
		headerName := a.config.HeaderName
		if headerName == "" {
			headerName = "X-API-Key"
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
	req.Header.Set("Authorization", "Bearer "+token)
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
	clientID, err := a.creds.Get(ctx, a.config.ClientIDCredential, credentials.TenantInfo{})
	if err != nil {
		return "", fmt.Errorf("get oauth2 client_id: %w", err)
	}
	clientSecret, err := a.creds.Get(ctx, a.config.ClientSecretCredential, credentials.TenantInfo{})
	if err != nil {
		return "", fmt.Errorf("get oauth2 client_secret: %w", err)
	}

	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	if len(a.config.Scopes) > 0 {
		data.Set("scope", strings.Join(a.config.Scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", a.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create oauth2 token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req) //nolint:gosec // URL from trusted config
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

	a.logger.Info("oauth2 token acquired", "expires_in", tokenResp.ExpiresIn)
	return a.cachedToken, nil
}

func (a *RestAuth) injectSession(ctx context.Context, req *http.Request) error {
	a.mu.Lock()
	hasTokens := len(a.sessionTokens) > 0
	a.mu.Unlock()

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

	// Resolve credential references in body
	body := make(map[string]string, len(a.config.Login.Body))
	for k, v := range a.config.Login.Body {
		if strings.HasPrefix(v, "credential:") {
			credName := strings.TrimPrefix(v, "credential:")
			resolved, err := a.creds.Get(ctx, credName, credentials.TenantInfo{})
			if err != nil {
				return fmt.Errorf("resolve login credential %q: %w", credName, err)
			}
			body[k] = resolved
		} else {
			body[k] = v
		}
	}

	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, a.config.Login.Method, loginURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return fmt.Errorf("create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
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

	a.logger.Info("session login successful", "tokens", len(a.sessionTokens))
	return nil
}
