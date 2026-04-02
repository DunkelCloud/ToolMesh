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
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/DunkelCloud/ToolMesh/internal/version"
)

// Server is the ToolMesh MCP server that handles Streamable HTTP transport,
// OAuth 2.1 authentication, and tool call routing.
type Server struct {
	handler       *Handler
	cfg           *config.Config
	logger        *slog.Logger
	tokenStore    auth.TokenStore
	userStore     *auth.UserStore
	apiKeys       *auth.APIKeyStore
	rateLimiter   *auth.DCRRateLimiter
	callerClasses *config.CallerClasses
}

// NewServer creates a new MCP server.
func NewServer(handler *Handler, cfg *config.Config, logger *slog.Logger, tokenStore auth.TokenStore, userStore *auth.UserStore, apiKeys *auth.APIKeyStore, rateLimiter *auth.DCRRateLimiter, callerClasses *config.CallerClasses) *Server {
	if len(cfg.CORSAllowedOrigins) == 0 {
		logger.Warn("TOOLMESH_CORS_ORIGINS not set: CORS will reflect any origin (open policy)")
	}
	return &Server{
		handler:       handler,
		cfg:           cfg,
		logger:        logger,
		tokenStore:    tokenStore,
		userStore:     userStore,
		apiKeys:       apiKeys,
		rateLimiter:   rateLimiter,
		callerClasses: callerClasses,
	}
}

// SetupRoutes registers all HTTP routes on the given mux.
func (s *Server) SetupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/mcp", s.cors(s.handleMCP))
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.cors(s.handleOAuthMetadata))
	mux.HandleFunc("/.well-known/oauth-protected-resource", s.cors(s.handleProtectedResource))
	mux.HandleFunc("/register", s.cors(s.handleRegister))
	mux.HandleFunc("/authorize", s.cors(s.handleAuthorize))
	mux.HandleFunc("/token", s.cors(s.handleToken))
	mux.HandleFunc("/health", s.cors(s.handleHealth))
}

// cors wraps a handler with CORS headers.
// If CORSAllowedOrigins is configured, only matching origins are reflected.
// Otherwise, falls back to reflecting any origin for backwards compatibility.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if len(s.cfg.CORSAllowedOrigins) > 0 {
				if s.originAllowed(origin) {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			} else {
				// No allowlist configured — reflect any origin (backwards compat)
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Protocol-Version")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// originAllowed checks whether the given origin matches any entry in the
// configured CORS allowlist. Entries can be exact domains or use a "*."
// prefix for subdomain matching.
func (s *Server) originAllowed(origin string) bool {
	for _, allowed := range s.cfg.CORSAllowedOrigins {
		if allowed == origin {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			// Wildcard subdomain match: "*.example.com" matches "https://foo.example.com"
			suffix := allowed[1:] // ".example.com"
			if strings.HasSuffix(origin, suffix) {
				return true
			}
		}
	}
	return false
}

// handleMCP processes MCP Streamable HTTP requests.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodGet {
		// MCP clients may attempt GET for SSE streaming.
		// We don't support server-initiated events; return 405.
		s.logger.DebugContext(ctx, "mcp GET request rejected (SSE not supported)")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate
	uc := s.authenticate(r)
	if !uc.Authenticated && s.authRequired() {
		s.logger.DebugContext(ctx, "mcp request rejected: unauthorized", "remote", clientIP(r))
		s.writeJSONRPCError(w, nil, -32001, "Unauthorized")
		return
	}

	ctx = userctx.WithUserContext(ctx, uc)

	// Parse JSON-RPC request
	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONRPCError(w, nil, -32700, "Parse error")
		return
	}

	s.logger.InfoContext(ctx, "mcp request", "method", req.Method, "id", req.ID)
	s.logger.DebugContext(ctx, "mcp request payload", "method", req.Method, "id", req.ID, "params", req.Params)

	// JSON-RPC notifications have no "id" field.
	// Per MCP Streamable HTTP spec, respond with 202 Accepted (no body).
	if req.ID == nil {
		s.logger.DebugContext(ctx, "mcp notification (no id)", "method", req.Method)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(w, &req)
	case "tools/list":
		s.handleToolsList(w, ctx, &req)
	case "tools/call":
		s.handleToolsCall(w, ctx, &req)
	case "ping":
		s.writeJSONRPCResult(w, req.ID, map[string]any{})
	default:
		s.writeJSONRPCError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

// authRequired returns true if any authentication mechanism is configured.
func (s *Server) authRequired() bool {
	return s.cfg.AuthPassword != "" || s.cfg.APIKey != "" || s.userStore != nil || s.apiKeys != nil
}

func (s *Server) handleInitialize(w http.ResponseWriter, req *jsonRPCRequest) {
	s.writeJSONRPCResult(w, req.ID, map[string]any{
		"protocolVersion": "2025-11-25",
		"capabilities": map[string]any{
			"tools": map[string]any{
				"listChanged": false,
			},
		},
		"serverInfo": map[string]any{
			"name":    "toolmesh",
			"version": version.Version,
		},
	})
}

func (s *Server) handleToolsList(w http.ResponseWriter, ctx context.Context, req *jsonRPCRequest) {
	tools, err := s.handler.BuildToolList(ctx)
	if err != nil {
		s.writeJSONRPCError(w, req.ID, -32603, fmt.Sprintf("Failed to list tools: %s", err))
		return
	}

	mcpTools := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		mcpTools = append(mcpTools, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"inputSchema": t.InputSchema,
		})
	}

	s.writeJSONRPCResult(w, req.ID, map[string]any{
		"tools": mcpTools,
	})
}

func (s *Server) handleToolsCall(w http.ResponseWriter, ctx context.Context, req *jsonRPCRequest) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}

	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		s.writeJSONRPCError(w, req.ID, -32602, "Invalid params")
		return
	}
	if err := json.Unmarshal(paramsJSON, &params); err != nil {
		s.writeJSONRPCError(w, req.ID, -32602, "Invalid params")
		return
	}

	result, err := s.handler.HandleToolCall(ctx, params.Name, params.Arguments)
	if err != nil {
		s.writeJSONRPCError(w, req.ID, -32603, err.Error())
		return
	}

	s.writeJSONRPCResult(w, req.ID, toolResultToMCP(result))
}

func toolResultToMCP(result *backend.ToolResult) map[string]any {
	return map[string]any{
		"content": result.Content,
		"isError": result.IsError,
	}
}

// authenticate extracts user context from the request.
func (s *Server) authenticate(r *http.Request) *userctx.UserContext {
	bearer := extractBearer(r)

	// 1. API-Key Check (from apikeys.yaml — bcrypt hashed)
	if bearer != "" && s.apiKeys != nil {
		if entry := s.apiKeys.Match(bearer); entry != nil {
			callerID := entry.CallerID
			if callerID == "" {
				callerID = entry.UserID
			}
			return &userctx.UserContext{
				UserID:        entry.UserID,
				CompanyID:     entry.CompanyID,
				Roles:         entry.Roles,
				Plan:          entry.Plan,
				Authenticated: true,
				CallerID:      callerID,
				CallerName:    callerID, // API key CallerID is admin-configured, use as display name
				CallerClass:   s.callerClasses.Resolve(callerID),
			}
		}
	}

	// 2. Legacy single API key (env var fallback)
	if s.cfg.APIKey != "" && bearer != "" && s.apiKeys == nil {
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(s.cfg.APIKey)) == 1 {
			return &userctx.UserContext{
				UserID:        s.cfg.AuthUser,
				CompanyID:     "default",
				Roles:         s.cfg.AuthRolesList(),
				Plan:          s.cfg.AuthPlan,
				Authenticated: true,
				CallerID:      s.cfg.AuthUser,
				CallerClass:   s.callerClasses.Resolve(s.cfg.AuthUser),
			}
		}
	}

	// 3. OAuth Bearer Token (from Redis)
	if bearer != "" && s.tokenStore != nil {
		ti, err := s.tokenStore.GetToken(r.Context(), bearer)
		if err == nil && time.Now().Before(ti.ExpiresAt) {
			callerID := ti.CallerID
			if callerID == "" {
				callerID = ti.ClientID
			}
			return &userctx.UserContext{
				UserID:        ti.UserID,
				CompanyID:     ti.CompanyID,
				Roles:         ti.Roles,
				Plan:          ti.Plan,
				Authenticated: true,
				CallerID:      callerID,
				CallerName:    ti.CallerName,
				CallerClass:   s.callerClasses.Resolve(callerID),
			}
		}
	}

	// 4. No auth configured — allow anonymous
	if !s.authRequired() {
		return &userctx.UserContext{
			UserID:        "anonymous",
			CompanyID:     "default",
			Roles:         []string{},
			Plan:          "free",
			Authenticated: true,
			CallerID:      "anonymous",
			CallerClass:   "untrusted",
		}
	}

	return &userctx.UserContext{
		UserID:        "anonymous",
		Authenticated: false,
		CallerID:      "anonymous",
		CallerClass:   "untrusted",
	}
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return h
}

// clientIP extracts the client IP address, preferring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// OAuth 2.1 Endpoints

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := s.cfg.Issuer
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "authorize",
		"token_endpoint":                        iss + "token",
		"registration_endpoint":                 iss + "register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"claudeai"},
	})
}

func (s *Server) handleProtectedResource(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.cfg.Issuer,
		"authorization_servers":    []string{s.cfg.Issuer},
		"bearer_methods_supported": []string{"header"},
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// DCR Rate Limiting
	if s.rateLimiter != nil {
		ip := clientIP(r)
		allowed, err := s.rateLimiter.Allow(ctx, ip)
		if err != nil {
			s.logger.ErrorContext(ctx, "dcr rate limit check failed", "error", err)
		} else if !allowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_requests"})
			return
		}
	}

	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	clientID := generateID()
	clientSecret := generateID()

	client := &auth.OAuthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
	}

	if s.tokenStore != nil {
		if err := s.tokenStore.SaveClient(ctx, client); err != nil {
			s.logger.ErrorContext(ctx, "failed to save client", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
	}

	s.logger.InfoContext(ctx, "registered oauth client", "clientId", clientID)

	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
	})
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		clientID := r.URL.Query().Get("client_id")
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		codeChallenge := r.URL.Query().Get("code_challenge")
		scope := r.URL.Query().Get("scope")

		s.renderLoginForm(w, clientID, redirectURI, state, codeChallenge, scope)
		return
	}

	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		codeChallenge := r.FormValue("code_challenge")
		scope := r.FormValue("scope")

		// Authenticate user
		var userID, companyID, plan string
		var roles []string

		if s.userStore != nil {
			// Multi-user mode (users.yaml)
			user := s.userStore.Authenticate(username, password)
			if user == nil {
				s.renderLoginForm(w, clientID, redirectURI, state, codeChallenge, scope)
				return
			}
			userID = user.Username
			companyID = user.Company
			plan = user.Plan
			roles = user.Roles
		} else {
			// Legacy single-password mode
			if subtle.ConstantTimeCompare([]byte(password), []byte(s.cfg.AuthPassword)) != 1 {
				s.renderLoginForm(w, clientID, redirectURI, state, codeChallenge, scope)
				return
			}
			userID = s.cfg.AuthUser
			companyID = "default"
			plan = s.cfg.AuthPlan
			roles = s.cfg.AuthRolesList()
		}

		// Validate redirect_uri against registered client
		if s.tokenStore != nil {
			client, err := s.tokenStore.GetClient(r.Context(), clientID)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri", "error_description": "unknown client"})
				return
			}
			uriValid := false
			for _, uri := range client.RedirectURIs {
				if uri == redirectURI {
					uriValid = true
					break
				}
			}
			if !uriValid {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
				return
			}
		}

		code := generateID()
		ac := &auth.AuthCode{
			Code:          code,
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			CodeChallenge: codeChallenge,
			Scope:         scope,
			UserID:        userID,
			CompanyID:     companyID,
			Plan:          plan,
			Roles:         roles,
			ExpiresAt:     time.Now().Add(5 * time.Minute),
		}

		if s.tokenStore != nil {
			if err := s.tokenStore.SaveAuthCode(r.Context(), ac); err != nil {
				s.logger.ErrorContext(r.Context(), "failed to save auth code", "error", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
		}

		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		http.Redirect(w, r, fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, sep, code, state), http.StatusFound)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.FormValue("code")                  //nolint:gosec // G120: body size limited in handleToken
	codeVerifier := r.FormValue("code_verifier") //nolint:gosec // G120: body size limited in handleToken

	if s.tokenStore == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	ac, err := s.tokenStore.ConsumeAuthCode(ctx, code)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if time.Now().After(ac.ExpiresAt) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	// PKCE S256 verification — required when a code_challenge was provided
	if ac.CodeChallenge != "" {
		if codeVerifier == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "code_verifier required"})
			return
		}
		h := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(ac.CodeChallenge)) != 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
	}

	// CallerID is always the opaque client_id (UUID) — never the self-reported
	// client_name, which is untrusted (like a browser User-Agent). The client_name
	// is stored separately as CallerName for audit/display purposes only.
	callerID := ac.ClientID
	var callerName string
	if client, err := s.tokenStore.GetClient(ctx, ac.ClientID); err == nil && client.ClientName != "" {
		callerName = client.ClientName
	}

	accessToken := generateID()
	refreshToken := generateID()

	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ClientID:         ac.ClientID,
		UserID:           ac.UserID,
		CompanyID:        ac.CompanyID,
		Plan:             ac.Plan,
		Roles:            ac.Roles,
		CallerID:         callerID,
		CallerName:       callerName,
		Scope:            ac.Scope,
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
	}

	if err := s.tokenStore.SaveToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save refresh token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         ac.Scope,
	})
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refreshToken := r.FormValue("refresh_token") //nolint:gosec // G120: body size limited in handleToken

	if s.tokenStore == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	oldTI, err := s.tokenStore.ConsumeRefreshToken(ctx, refreshToken)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	// Delete old access token
	_ = s.tokenStore.DeleteToken(ctx, oldTI.AccessToken)

	newAccessToken := generateID()
	newRefreshToken := generateID()

	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken:      newAccessToken,
		RefreshToken:     newRefreshToken,
		ClientID:         oldTI.ClientID,
		UserID:           oldTI.UserID,
		CompanyID:        oldTI.CompanyID,
		Plan:             oldTI.Plan,
		Roles:            oldTI.Roles,
		CallerID:         oldTI.CallerID,
		CallerName:       oldTI.CallerName,
		Scope:            oldTI.Scope,
		ExpiresAt:        now.Add(time.Hour),
		RefreshExpiresAt: now.Add(7 * 24 * time.Hour),
	}

	if err := s.tokenStore.SaveToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save refresh token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  newAccessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": newRefreshToken,
		"scope":         oldTI.Scope,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>ToolMesh Login</title>
<style>body{font-family:system-ui;max-width:400px;margin:80px auto;padding:20px}
input{width:100%;padding:8px;margin:8px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#2563eb;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#1d4ed8}</style></head>
<body>
<h2>ToolMesh</h2>
<p>Enter your credentials to authorize access.</p>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="text" name="username" placeholder="Username" autofocus>
<input type="password" name="password" placeholder="Password">
<button type="submit">Authorize</button>
</form>
</body>
</html>`))

func (s *Server) renderLoginForm(w http.ResponseWriter, clientID, redirectURI, state, codeChallenge, scope string) {
	w.Header().Set("Content-Type", "text/html")
	if err := loginTmpl.Execute(w, map[string]string{
		"ClientID":      clientID,
		"RedirectURI":   redirectURI,
		"State":         state,
		"CodeChallenge": codeChallenge,
		"Scope":         scope,
	}); err != nil {
		s.logger.Error("failed to render login form", "error", err)
	}
}

func (s *Server) writeJSONRPCResult(w http.ResponseWriter, id, result any) {
	s.logger.Debug("mcp response", "id", id, "result", result)
	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func (s *Server) writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	s.logger.Debug("mcp error response", "id", id, "code", code, "message", message)
	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data) // error is client-disconnect; nothing to do
}

func generateID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
