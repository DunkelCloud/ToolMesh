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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestServer(t *testing.T, cfg *config.Config) (*Server, *http.ServeMux) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, logger)
	handler := NewHandler(exec, mb, nil, "", logger)

	srv := NewServer(handler, cfg, logger, nil, nil, nil, nil)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	return srv, mux
}

func newTestServerWithRedis(t *testing.T, cfg *config.Config) (*Server, *http.ServeMux, *miniredis.Miniredis) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	tokenStore := auth.NewRedisTokenStore(rdb)
	rateLimiter := auth.NewDCRRateLimiter(rdb)

	mb := &mockTestBackend{}
	exec := executor.New(nil, nil, mb, nil, logger)
	handler := NewHandler(exec, mb, nil, "", logger)

	srv := NewServer(handler, cfg, logger, tokenStore, nil, nil, rateLimiter)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	return srv, mux, mr
}

type mockTestBackend struct{}

func (m *mockTestBackend) Execute(_ context.Context, toolName string, params map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{
		Content: []any{map[string]any{"type": "text", "text": "ok"}},
	}, nil
}

func (m *mockTestBackend) ListTools(_ context.Context) ([]backend.ToolDescriptor, error) {
	return []backend.ToolDescriptor{
		{Name: "test:tool", Description: "A test tool"},
	}, nil
}

func (m *mockTestBackend) Healthy(_ context.Context) error {
	return nil
}

func TestServer_Health(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want \"ok\"", resp["status"])
	}
}

func TestServer_OAuthMetadata(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{Issuer: "https://toolmesh.io/"})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["issuer"] != "https://toolmesh.io/" {
		t.Errorf("issuer = %v, want \"https://toolmesh.io/\"", resp["issuer"])
	}
	if resp["authorization_endpoint"] != "https://toolmesh.io/authorize" {
		t.Errorf("authorization_endpoint = %v", resp["authorization_endpoint"])
	}
	if resp["token_endpoint"] != "https://toolmesh.io/token" {
		t.Errorf("token_endpoint = %v", resp["token_endpoint"])
	}
}

func TestServer_ProtectedResource(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{Issuer: "https://toolmesh.io/"})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

func TestServer_Register(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})

	body := `{"redirect_uris": ["https://example.com/callback"], "client_name": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["client_id"] == nil || resp["client_id"] == "" {
		t.Error("expected client_id in response")
	}
	if resp["client_secret"] == nil || resp["client_secret"] == "" {
		t.Error("expected client_secret in response")
	}
}

func TestServer_CORSHeaders(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	req.Header.Set("Origin", "https://claude.ai")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Header().Get("Access-Control-Allow-Origin") != "https://claude.ai" {
		t.Errorf("CORS origin = %q, want \"https://claude.ai\"", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Error("expected Access-Control-Allow-Credentials: true")
	}
}

func TestServer_MCP_Initialize(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatal("expected result object")
	}
	if result["protocolVersion"] != "2025-11-25" {
		t.Errorf("protocolVersion = %v, want \"2025-11-25\"", result["protocolVersion"])
	}
}

func TestServer_MCP_Ping(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 2, "method": "ping"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["error"] != nil {
		t.Errorf("unexpected error: %v", resp["error"])
	}
}

func TestServer_MCP_UnknownMethod(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 3, "method": "unknown/method"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error object")
	}
	if errObj["code"].(float64) != -32601 {
		t.Errorf("error code = %v, want -32601", errObj["code"])
	}
}

func TestServer_MCP_InvalidJSON(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error object for invalid JSON")
	}
	if errObj["code"].(float64) != -32700 {
		t.Errorf("error code = %v, want -32700 (Parse error)", errObj["code"])
	}
}

func TestServer_MCP_MethodNotAllowed(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

func TestServer_MCP_Unauthorized(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{AuthPassword: "secret"})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	errObj, ok := resp["error"].(map[string]any)
	if !ok {
		t.Fatal("expected error for unauthorized request")
	}
	if errObj["message"] != "Unauthorized" {
		t.Errorf("error message = %v, want \"Unauthorized\"", errObj["message"])
	}
}

func TestServer_MCP_APIKeyAuth(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{APIKey: "my-secret-key"})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer my-secret-key")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["error"] != nil {
		t.Errorf("unexpected error with valid API key: %v", resp["error"])
	}
}

func TestServer_OAuthFlow(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{
		AuthPassword: "test-password",
		Issuer:       "https://toolmesh.io/",
	})

	// Step 1: Register client
	regBody := `{"redirect_uris": ["https://example.com/callback"], "client_name": "test"}`
	regReq := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)

	var regResp map[string]any
	json.NewDecoder(regW.Body).Decode(&regResp)
	clientID := regResp["client_id"].(string)

	// Step 2: Authorize (POST with correct password + PKCE)
	codeVerifier := "test-verifier-with-enough-entropy-1234567890"
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	form := url.Values{
		"password":       {"test-password"},
		"client_id":      {clientID},
		"redirect_uri":   {"https://example.com/callback"},
		"state":          {"test-state"},
		"code_challenge": {codeChallenge},
		"scope":          {"claudeai"},
	}
	authReq := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	authReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	authW := httptest.NewRecorder()
	mux.ServeHTTP(authW, authReq)

	if authW.Code != http.StatusFound {
		t.Fatalf("authorize status = %d, want %d", authW.Code, http.StatusFound)
	}

	location := authW.Header().Get("Location")
	if !strings.Contains(location, "code=") {
		t.Fatalf("redirect location missing code: %s", location)
	}

	// Extract the code from the redirect URL
	u, _ := url.Parse(location)
	code := u.Query().Get("code")

	// Step 3: Exchange code for token (with PKCE verifier)
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {codeVerifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()
	mux.ServeHTTP(tokenW, tokenReq)

	if tokenW.Code != http.StatusOK {
		t.Fatalf("token status = %d, want %d", tokenW.Code, http.StatusOK)
	}

	var tokenResp map[string]any
	json.NewDecoder(tokenW.Body).Decode(&tokenResp)

	accessToken, ok := tokenResp["access_token"].(string)
	if !ok || accessToken == "" {
		t.Fatal("expected access_token in response")
	}
	refreshToken, ok := tokenResp["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatal("expected refresh_token in response")
	}
	if tokenResp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want \"Bearer\"", tokenResp["token_type"])
	}

	// Step 4: Use access token to make an MCP call
	mcpBody := `{"jsonrpc": "2.0", "id": 1, "method": "ping"}`
	mcpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpBody))
	mcpReq.Header.Set("Content-Type", "application/json")
	mcpReq.Header.Set("Authorization", "Bearer "+accessToken)
	mcpW := httptest.NewRecorder()
	mux.ServeHTTP(mcpW, mcpReq)

	var mcpResp map[string]any
	json.NewDecoder(mcpW.Body).Decode(&mcpResp)
	if mcpResp["error"] != nil {
		t.Errorf("unexpected error with valid token: %v", mcpResp["error"])
	}

	// Step 5: Refresh token
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshForm.Encode()))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshW := httptest.NewRecorder()
	mux.ServeHTTP(refreshW, refreshReq)

	if refreshW.Code != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d", refreshW.Code, http.StatusOK)
	}

	var refreshResp map[string]any
	json.NewDecoder(refreshW.Body).Decode(&refreshResp)
	if refreshResp["access_token"] == nil || refreshResp["access_token"] == "" {
		t.Error("expected new access_token from refresh")
	}

}

func TestServer_Authorize_WrongPassword(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{AuthPassword: "correct"})

	form := url.Values{
		"password":     {"wrong"},
		"client_id":    {"c1"},
		"redirect_uri": {"https://example.com/callback"},
		"state":        {"s1"},
	}
	req := httptest.NewRequest(http.MethodPost, "/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Should re-render login form (200 with HTML), not redirect
	if w.Code == http.StatusFound {
		t.Error("should not redirect with wrong password")
	}
	if !strings.Contains(w.Body.String(), "ToolMesh") {
		t.Error("expected login form HTML in response")
	}
}

func TestServer_Token_InvalidGrant(t *testing.T) {
	_, mux, _ := newTestServerWithRedis(t, &config.Config{})

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"invalid-code"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_grant" {
		t.Errorf("error = %v, want \"invalid_grant\"", resp["error"])
	}
}

func TestServer_Token_UnsupportedGrantType(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v, want \"unsupported_grant_type\"", resp["error"])
	}
}

func TestServer_ToolsList(t *testing.T) {
	_, mux := newTestServer(t, &config.Config{})

	body := `{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)

	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatal("expected result object")
	}

	tools, ok := result["tools"].([]any)
	if !ok {
		t.Fatal("expected tools array")
	}

	// Should have at least list_tools, execute_code, and test:tool
	if len(tools) < 3 {
		t.Errorf("expected at least 3 tools, got %d", len(tools))
	}
}
