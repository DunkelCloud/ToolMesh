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
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/DunkelCloud/ToolMesh/internal/version"
)

// Server is the ToolMesh MCP server that handles Streamable HTTP transport,
// OAuth 2.1 authentication, and tool call routing.
type Server struct {
	handler *Handler
	cfg     *config.Config
	logger  *slog.Logger

	// OAuth state
	mu            sync.RWMutex
	clients       map[string]*oauthClient
	authCodes     map[string]*authCode
	tokens        map[string]*tokenInfo
	refreshTokens map[string]*tokenInfo
}

type oauthClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	CreatedAt    time.Time
}

type authCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	Scope         string
	ExpiresAt     time.Time
}

type tokenInfo struct {
	AccessToken  string
	RefreshToken string
	ClientID     string
	UserID       string
	Scope        string
	ExpiresAt    time.Time
}

// NewServer creates a new MCP server.
func NewServer(handler *Handler, cfg *config.Config, logger *slog.Logger) *Server {
	return &Server{
		handler:       handler,
		cfg:           cfg,
		logger:        logger,
		clients:       make(map[string]*oauthClient),
		authCodes:     make(map[string]*authCode),
		tokens:        make(map[string]*tokenInfo),
		refreshTokens: make(map[string]*tokenInfo),
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

// cors wraps a handler with CORS headers that reflect the request origin.
// This is required for Claude.ai compatibility which sends cross-origin requests.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Protocol-Version")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next(w, r)
	}
}

// handleMCP processes MCP Streamable HTTP requests.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate
	uc := s.authenticate(r)
	if !uc.Authenticated && s.cfg.AuthPassword != "" {
		s.writeJSONRPCError(w, nil, -32001, "Unauthorized")
		return
	}

	ctx := userctx.WithUserContext(r.Context(), uc)

	// Parse JSON-RPC request
	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeJSONRPCError(w, nil, -32700, "Parse error")
		return
	}

	s.logger.Info("mcp request", "method", req.Method, "id", req.ID)

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

	// Check static API key
	if s.cfg.APIKey != "" && bearer != "" {
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(s.cfg.APIKey)) == 1 {
			return &userctx.UserContext{
				UserID:        "api-key-user",
				CompanyID:     "default",
				Roles:         []string{"admin"},
				Plan:          "pro",
				Authenticated: true,
			}
		}
	}

	// Check OAuth bearer token
	if bearer != "" {
		s.mu.RLock()
		ti, ok := s.tokens[bearer]
		s.mu.RUnlock()
		if ok && time.Now().Before(ti.ExpiresAt) {
			return &userctx.UserContext{
				UserID:        ti.UserID,
				CompanyID:     "default",
				Roles:         []string{"admin"},
				Plan:          "pro",
				Authenticated: true,
			}
		}
	}

	// No auth configured — allow anonymous
	if s.cfg.AuthPassword == "" && s.cfg.APIKey == "" {
		return &userctx.UserContext{
			UserID:        "anonymous",
			CompanyID:     "default",
			Roles:         []string{},
			Plan:          "free",
			Authenticated: true,
		}
	}

	return &userctx.UserContext{
		UserID:        "anonymous",
		Authenticated: false,
	}
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return h
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
		"code_challenge_methods_supported":       []string{"S256"},
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
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
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

	client := &oauthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    time.Now(),
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	s.logger.Info("registered oauth client", "clientId", clientID)

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
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		password := r.FormValue("password")
		clientID := r.FormValue("client_id")
		redirectURI := r.FormValue("redirect_uri")
		state := r.FormValue("state")
		codeChallenge := r.FormValue("code_challenge")
		scope := r.FormValue("scope")

		if subtle.ConstantTimeCompare([]byte(password), []byte(s.cfg.AuthPassword)) != 1 {
			s.renderLoginForm(w, clientID, redirectURI, state, codeChallenge, scope)
			return
		}

		code := generateID()
		s.mu.Lock()
		s.authCodes[code] = &authCode{
			Code:          code,
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			CodeChallenge: codeChallenge,
			Scope:         scope,
			ExpiresAt:     time.Now().Add(5 * time.Minute),
		}
		s.mu.Unlock()

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
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	s.mu.Lock()
	ac, ok := s.authCodes[code]
	if ok {
		delete(s.authCodes, code)
	}
	s.cleanupExpiredLocked()
	s.mu.Unlock()

	if !ok || time.Now().After(ac.ExpiresAt) {
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

	accessToken := generateID()
	refreshToken := generateID()

	ti := &tokenInfo{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ClientID:     ac.ClientID,
		UserID:       "owner",
		Scope:        ac.Scope,
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	s.mu.Lock()
	s.tokens[accessToken] = ti
	s.refreshTokens[refreshToken] = ti
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": refreshToken,
		"scope":         ac.Scope,
	})
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")

	s.mu.Lock()
	oldTI, ok := s.refreshTokens[refreshToken]
	if ok {
		delete(s.refreshTokens, refreshToken)
		delete(s.tokens, oldTI.AccessToken)
	}
	s.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	newAccessToken := generateID()
	newRefreshToken := generateID()

	ti := &tokenInfo{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		ClientID:     oldTI.ClientID,
		UserID:       oldTI.UserID,
		Scope:        oldTI.Scope,
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	s.mu.Lock()
	s.tokens[newAccessToken] = ti
	s.refreshTokens[newRefreshToken] = ti
	s.mu.Unlock()

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

// cleanupExpiredLocked removes expired auth codes and tokens.
// Must be called with s.mu held.
func (s *Server) cleanupExpiredLocked() {
	now := time.Now()
	for k, ac := range s.authCodes {
		if now.After(ac.ExpiresAt) {
			delete(s.authCodes, k)
		}
	}
	for k, ti := range s.tokens {
		if now.After(ti.ExpiresAt) {
			delete(s.tokens, k)
		}
	}
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
<p>Enter your password to authorize access.</p>
<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<input type="password" name="password" placeholder="Password" autofocus>
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

func (s *Server) writeJSONRPCResult(w http.ResponseWriter, id any, result any) {
	writeJSON(w, http.StatusOK, map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	})
}

func (s *Server) writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
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
