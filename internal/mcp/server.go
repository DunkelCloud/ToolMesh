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
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
	"github.com/DunkelCloud/ToolMesh/internal/version"
	"github.com/redis/go-redis/v9"
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
	loginThrottle *auth.LoginThrottle
	callerClasses *config.CallerClasses
	metrics       *metrics.Registry
	blobStore     *blob.Store
	uploadLimits  blob.UploadLimits
}

// SetBlobStore enables the file broker upload endpoint (POST /files/upload).
// Uploads are authenticated with the same credentials as the MCP endpoint;
// the storage mechanics live in the blob store itself.
func (s *Server) SetBlobStore(store *blob.Store, limits blob.UploadLimits) {
	s.blobStore = store
	s.uploadLimits = limits
}

// NewServer creates a new MCP server. The metrics registry is optional; pass
// nil to disable instrumentation.
func NewServer(handler *Handler, cfg *config.Config, logger *slog.Logger, tokenStore auth.TokenStore, userStore *auth.UserStore, apiKeys *auth.APIKeyStore, rateLimiter *auth.DCRRateLimiter, callerClasses *config.CallerClasses, m *metrics.Registry) *Server {
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
		loginThrottle: auth.NewLoginThrottle(loginThrottleConfig(cfg), nil, logger),
		callerClasses: callerClasses,
		metrics:       m,
	}
}

// UseRedisLoginThrottle moves the failed-login counters from process memory,
// where NewServer keeps them, to Redis, so the limits hold across replicas and
// restarts. Call it before the server starts handling requests.
func (s *Server) UseRedisLoginThrottle(rdb *redis.Client) {
	s.loginThrottle = auth.NewLoginThrottle(loginThrottleConfig(s.cfg), rdb, s.logger)
}

func loginThrottleConfig(cfg *config.Config) auth.LoginThrottleConfig {
	return auth.LoginThrottleConfig{
		MaxFailuresPerUserIP: cfg.LoginMaxFailuresPerUserIP,
		MaxFailuresPerUser:   cfg.LoginMaxFailuresPerUser,
		MaxFailuresPerIP:     cfg.LoginMaxFailuresPerIP,
		Window:               time.Duration(cfg.LoginFailureWindow) * time.Second,
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
	if s.blobStore != nil {
		mux.HandleFunc("/files/upload", s.cors(s.handleFileUpload))
		mux.HandleFunc("/blobs/", s.handleBlobs)
	}
	// Registered last: "/" is the catch-all, so every pattern above still wins.
	mux.HandleFunc("/", s.cors(s.handleRoot))
}

// handleFileUpload guards the broker upload endpoint with MCP authentication
// and delegates the multipart mechanics to the blob store (DADL spec §6.2.3).
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	if !s.requireAuth(w, r) {
		return
	}
	s.blobStore.HandleUpload(w, r, s.uploadLimits)
}

// handleBlobs serves blob download and deletion (DADL spec §6.2.3). GET and
// HEAD are capability-based: the unguessable blob ID is the only credential,
// bounded by the TTL — this is deliberate so download URLs can be handed to
// backends (e.g. via a #url handle) without sharing MCP credentials. DELETE is
// destructive and has no capability use case, so it additionally requires MCP
// authentication; a party that merely holds a blob ID cannot destroy it.
func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete && !s.requireAuth(w, r) {
		return
	}
	s.blobStore.ServeHTTP(w, r)
}

// requireAuth enforces MCP authentication when the server has any auth
// configured. It returns true when the request may proceed and, on failure,
// writes the 401 response itself. When no auth is configured the whole server
// is open, so the call passes through unchanged.
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if !s.authRequired() {
		return true
	}
	if user := s.authenticate(r); user != nil && user.Authenticated {
		return true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="toolmesh"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// cors wraps a handler with CORS headers.
// If CORSAllowedOrigins is configured, only matching origins are reflected.
// Otherwise, falls back to reflecting any origin for backwards compatibility.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Always set Vary: Origin so caching proxies key on origin (M-1).
		w.Header().Add("Vary", "Origin")

		if origin != "" {
			allowed := false
			if len(s.cfg.CORSAllowedOrigins) > 0 {
				if s.originAllowed(origin) {
					allowed = true
				}
			} else {
				// No allowlist configured — reflect origin but do NOT set
				// Allow-Credentials to prevent CSRF-like attacks (H-2).
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}

			// Only set credentials and full CORS headers when origin is explicitly allowed (L-8).
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Mcp-Protocol-Version")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
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
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return false
	}

	for _, allowed := range s.cfg.CORSAllowedOrigins {
		if allowed == origin {
			return true
		}
		if strings.HasPrefix(allowed, "*.") {
			// Wildcard subdomain match: "*.example.com" matches "https://foo.example.com"
			// but NOT "https://evil-example.com" (H-1).
			domain := allowed[2:] // "example.com"
			if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
				return true
			}
		}
	}
	return false
}

// handleMCP processes MCP Streamable HTTP requests.
func (s *Server) handleMCP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		// A browser that was handed this URL gets a page explaining what the
		// endpoint is, instead of a bare "Method not allowed" that reads like
		// a broken service. Only Accept: text/html takes that branch — MCP
		// clients attempting a server-initiated SSE stream send
		// text/event-stream and keep the 405 below, since we do not support
		// server-initiated events.
		if wantsHTML(r) {
			s.logger.DebugContext(ctx, "mcp browser GET served landing page")
			s.serveLanding(w, r)
			return
		}
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

	// L-2: Validate Content-Type
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		s.writeJSONRPCError(w, nil, -32700, "Content-Type must be application/json")
		return
	}

	// M-2: Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB

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
		// A tool call can run far longer than the default WriteTimeout — a
		// reasoning model, a slow upstream, or a committee of backend calls
		// inside execute_code. Clear the per-request write deadline so the
		// transport does not silently truncate a legitimately long call at
		// 60s; the executor and code-runner timeouts remain the real bound.
		// Best-effort: ResponseController returns ErrNotSupported behind a
		// writer that cannot expose the deadline (e.g. a test recorder).
		if derr := http.NewResponseController(w).SetWriteDeadline(time.Time{}); derr != nil && !errors.Is(derr, http.ErrNotSupported) {
			s.logger.DebugContext(ctx, "could not clear write deadline for tool call", outcomeError, derr)
		}
		// When the client advertises SSE (every MCP Streamable HTTP client
		// does), stream the response and emit keepalives so the client's idle
		// timer cannot fire mid-call. Otherwise fall back to buffered JSON.
		if flusher, ok := unwrapFlusher(w); ok && acceptsSSE(r) {
			s.handleToolsCallStreaming(w, ctx, &req, flusher)
		} else {
			s.handleToolsCall(w, ctx, &req)
		}
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
			jsonKeyName: "toolmesh",
			"version":   version.Version,
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
			"name":               t.Name,
			schemaKeyDescription: t.Description,
			"inputSchema":        t.InputSchema,
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
		// M-17: Log full error server-side, return a safe message to client.
		s.logger.ErrorContext(ctx, "tool call failed", logKeyTool, params.Name, outcomeError, err)
		s.writeJSONRPCError(w, req.ID, -32603, toolCallErrorMessage(err))
		return
	}

	s.writeJSONRPCResult(w, req.ID, toolResultToMCP(result))
}

// sseKeepaliveInterval is how often a comment ping is written to a streaming
// tool-call response to keep the connection alive. It must stay well below
// typical MCP client idle timeouts (observed ~30s) so that slow backends
// (reasoning models, committees) do not trip a "connector not responding"
// error before the real result arrives.
const sseKeepaliveInterval = 10 * time.Second

// handleToolsCallStreaming executes a tool call while holding the HTTP response
// open as an MCP Streamable HTTP SSE stream. It flushes the response headers
// immediately, emits a keepalive comment every sseKeepaliveInterval while the
// call runs, and finally writes the JSON-RPC response as an SSE "message"
// event. This keeps the client's idle timer from firing during long calls and
// — because the result is delivered the moment the call returns — preserves
// partial results from execute_code that the buffered path would lose if the
// client gave up early.
func (s *Server) handleToolsCallStreaming(w http.ResponseWriter, ctx context.Context, req *jsonRPCRequest, flusher http.Flusher) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	paramsJSON, err := json.Marshal(req.Params)
	if err == nil {
		err = json.Unmarshal(paramsJSON, &params)
	}
	if err != nil {
		s.writeJSONRPCError(w, req.ID, -32602, "Invalid params")
		return
	}

	// SSE handshake: announce the stream and flush headers immediately so the
	// client starts reading before the (possibly slow) tool call completes.
	h := w.Header()
	h.Set("Content-Type", mimeEventStream)
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // disable response buffering in nginx-style proxies
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Run the call in the background; stream keepalives until it returns.
	type callResult struct {
		result *backend.ToolResult
		err    error
	}
	resCh := make(chan callResult, 1)
	go func() {
		result, callErr := s.handler.HandleToolCall(ctx, params.Name, params.Arguments)
		resCh <- callResult{result, callErr}
	}()

	ticker := time.NewTicker(sseKeepaliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Client disconnected or server is shutting down; the background
			// call observes the same canceled context and unwinds.
			s.logger.DebugContext(ctx, "sse tool call canceled before completion", logKeyTool, params.Name)
			return
		case <-ticker.C:
			// SSE comment line: invisible to the JSON-RPC layer but the bytes
			// reset the client's read-idle timer (the standard SSE keepalive).
			if _, werr := io.WriteString(w, ": keepalive\n\n"); werr != nil {
				s.logger.DebugContext(ctx, "sse keepalive write failed; client gone", logKeyTool, params.Name, outcomeError, werr)
				return
			}
			flusher.Flush()
		case cr := <-resCh:
			var envelope map[string]any
			if cr.err != nil {
				// M-17: log full error server-side, return a safe message.
				s.logger.ErrorContext(ctx, "tool call failed", logKeyTool, params.Name, outcomeError, cr.err)
				envelope = jsonRPCErrorEnvelope(req.ID, -32603, toolCallErrorMessage(cr.err))
			} else {
				envelope = jsonRPCResultEnvelope(req.ID, toolResultToMCP(cr.result))
			}
			if werr := writeSSEMessage(w, flusher, envelope); werr != nil {
				s.logger.DebugContext(ctx, "sse final message write failed; client gone", logKeyTool, params.Name, outcomeError, werr)
			}
			return
		}
	}
}

// acceptsSSE reports whether the client explicitly accepts an event-stream
// response. Per MCP Streamable HTTP, clients advertise
// "Accept: application/json, text/event-stream". A client that does not list
// text/event-stream gets the buffered JSON response instead.
func acceptsSSE(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), mimeEventStream)
}

// unwrapFlusher walks the ResponseWriter's Unwrap chain to find an
// http.Flusher. A direct type assertion does not work here because the
// logging middleware embeds the http.ResponseWriter interface (which does not
// promote Flush) but exposes the underlying writer via Unwrap.
func unwrapFlusher(w http.ResponseWriter) (http.Flusher, bool) {
	for {
		if f, ok := w.(http.Flusher); ok {
			return f, true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return nil, false
		}
		w = u.Unwrap()
	}
}

// writeSSEMessage writes a JSON-RPC payload as a single SSE "message" event and
// flushes it. The payload is marshaled compactly so it occupies one data line.
func writeSSEMessage(w http.ResponseWriter, flusher http.Flusher, payload map[string]any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: message\ndata: %s\n\n", data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// toolCallErrorMessage maps a handler error to a client-safe JSON-RPC message.
// Timeouts and cancellations get a specific, actionable message; every other
// error stays generic so internal details are not leaked (M-17).
func toolCallErrorMessage(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "Tool call timed out before the backend responded"
	case errors.Is(err, context.Canceled):
		return "Tool call was canceled"
	default:
		return "Internal error"
	}
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

	// Which methods the bearer was checked against, so that a credential no
	// method accepts is counted as a failure of one that could have.
	var checkedAPIKey, checkedOAuth, expiredToken, storeFailed bool

	// 1. API-Key Check (from apikeys.yaml — bcrypt hashed)
	if bearer != "" && s.apiKeys != nil {
		checkedAPIKey = true
		if entry := s.apiKeys.Match(bearer); entry != nil {
			callerID := entry.CallerID
			if callerID == "" {
				callerID = entry.UserID
			}
			s.metrics.RecordLogin(loginMethodAPIKey, "success")
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
		checkedAPIKey = true
		if subtle.ConstantTimeCompare([]byte(bearer), []byte(s.cfg.APIKey)) == 1 {
			s.metrics.RecordLogin(loginMethodAPIKey, "success")
			return &userctx.UserContext{
				UserID:        s.cfg.AuthUser,
				CompanyID:     userDefault,
				Roles:         s.cfg.AuthRolesList(),
				Plan:          s.cfg.AuthPlan,
				Authenticated: true,
				CallerID:      s.cfg.AuthUser,
				CallerClass:   s.callerClasses.Resolve(s.cfg.AuthUser),
			}
		}
	}

	// 3. OAuth Bearer Token (from Redis). Access tokens come out of the
	// password login and are honored only where there is one: a token still in
	// the store from a time when the configuration was different is not a
	// credential anymore.
	if bearer != "" && s.tokenStore != nil && s.passwordLoginConfigured() {
		ti, err := s.tokenStore.GetToken(r.Context(), bearer)
		switch {
		case err == nil && time.Now().Before(ti.ExpiresAt):
			callerID := ti.CallerID
			if callerID == "" {
				callerID = ti.ClientID
			}
			s.metrics.RecordLogin(loginMethodOAuthBearer, "success")
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
		case err == nil:
			checkedOAuth = true
			expiredToken = true
		case errors.Is(err, auth.ErrNotFound):
			checkedOAuth = true
		default:
			// The store failed, not the credential: logged, but not counted
			// as a login failure.
			storeFailed = true
			s.logger.ErrorContext(r.Context(), "token lookup failed", outcomeError, err)
		}
	}

	// 4. No auth configured — allow anonymous (L-4: Authenticated=false for anonymous).
	if !s.authRequired() {
		return &userctx.UserContext{
			UserID:        userAnonymous,
			CompanyID:     userDefault,
			Roles:         []string{},
			Plan:          "free",
			Authenticated: false,
			CallerID:      userAnonymous,
			CallerClass:   "untrusted",
		}
	}

	// A credential was presented and nothing accepted it. A request without
	// one is anonymous, not a failed login.
	if bearer != "" && !storeFailed {
		s.bearerRejected(r, bearer, checkedAPIKey, checkedOAuth, expiredToken)
	}

	return &userctx.UserContext{
		UserID:        userAnonymous,
		Authenticated: false,
		CallerID:      userAnonymous,
		CallerClass:   "untrusted",
	}
}

// bearerRejected records a bearer credential that no method accepted: one
// failure on the login counter and one log line. The credential itself is
// never logged.
//
// A rejected credential does not say which method the caller meant, so it is
// attributed by what it looks like. A token that was found but has expired,
// or a value with the shape of an access token issued here, counts as a
// failed oauth_bearer — an expired token that the store has already dropped
// looks exactly like that, which makes this the routine case and an INFO
// line. Anything else counts as a failed api_key and is logged at WARN. If
// only one of the two methods comes into question — no API key is configured,
// or access tokens are not honored because there is no password login — the
// failure goes to that one.
func (s *Server) bearerRejected(r *http.Request, bearer string, checkedAPIKey, checkedOAuth, expiredToken bool) {
	tokenShaped := expiredToken || isIssuedTokenShape(bearer)

	var method string
	switch {
	case checkedOAuth && (tokenShaped || !checkedAPIKey):
		method = loginMethodOAuthBearer
	case checkedAPIKey:
		method = loginMethodAPIKey
	default:
		return // no method was in a position to accept it
	}
	s.metrics.RecordLogin(method, "failure")

	level, reason := slog.LevelWarn, loginReasonUnknownCredential
	switch {
	case expiredToken:
		level, reason = slog.LevelInfo, loginReasonExpiredToken
	case tokenShaped && checkedOAuth:
		level, reason = slog.LevelInfo, loginReasonUnknownToken
	}
	s.logger.Log(r.Context(), level, "bearer authentication failed",
		"method", method, logKeyRemote, clientIP(r), logKeyReason, reason)
}

// isIssuedTokenShape reports whether v has the form generateID gives the
// access tokens issued here: 32 random bytes in lowercase hex.
func isIssuedTokenShape(v string) bool {
	if len(v) != 2*generatedIDBytes {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// loginFailed records a failed password login at /authorize: one WARN line
// and one failure on the login counter. The password is not a parameter, so
// it cannot end up in the log.
func (s *Server) loginFailed(r *http.Request, username, reason string) {
	s.metrics.RecordLogin(loginMethodPassword, "failure")
	s.loginRejected(r, username, reason)
}

// loginRejected logs a password login that was turned away. On its own it is
// for requests rejected before any credential was looked at, which are not
// login failures in the metric's sense.
func (s *Server) loginRejected(r *http.Request, username, reason string) {
	s.logger.WarnContext(r.Context(), "login failed",
		"username", truncateForLog(username), logKeyRemote, clientIP(r), logKeyReason, reason)
}

// tokenGrantRefused records a token request on a server that has no password
// login, where no grant can be valid: one WARN line and one failure for the
// grant's method.
func (s *Server) tokenGrantRefused(r *http.Request, method string) {
	s.metrics.RecordLogin(method, "failure")
	s.logger.WarnContext(r.Context(), "token grant refused",
		"method", method, logKeyRemote, clientIP(r), logKeyReason, loginReasonPasswordLoginDisabled)
}

// truncateForLog bounds an attacker-chosen value before it is logged.
func truncateForLog(v string) string {
	if len(v) <= maxLoggedValueLen {
		return v
	}
	return strings.ToValidUTF8(v[:maxLoggedValueLen], "") + "…"
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	// L-1: Do not return raw header for non-Bearer auth types.
	return ""
}

// clientIP extracts the client IP address. Uses the rightmost non-private IP
// from X-Forwarded-For to prevent spoofing (H-6), falling back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		// Walk from right to left, return the first non-private IP.
		// The rightmost entry is set by the closest trusted proxy.
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			parsed := net.ParseIP(ip)
			if parsed == nil {
				continue
			}
			if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
				continue
			}
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// OAuth 2.1 Endpoints

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := strings.TrimRight(s.cfg.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss + "/",
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"registration_endpoint":                 iss + "/register",
		"response_types_supported":              []string{oauthCode},
		"grant_types_supported":                 []string{oauthGrantAuthCode, oauthRefreshToken},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{clientClaudeAI},
	})
}

func (s *Server) handleProtectedResource(w http.ResponseWriter, _ *http.Request) {
	iss := strings.TrimRight(s.cfg.Issuer, "/") + "/"
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 iss,
		"authorization_servers":    []string{iss},
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
			s.logger.ErrorContext(ctx, "dcr rate limit check failed", outcomeError, err)
		} else if !allowed {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{outcomeError: "too_many_requests"})
			return
		}
	}

	// L-2: Validate Content-Type
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: "Content-Type must be application/json"})
		return
	}

	// M-3: Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB

	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq})
		return
	}

	// Validate redirect_uri schemes — only HTTPS (or http://localhost for dev)
	for _, uri := range req.RedirectURIs {
		parsed, err := url.Parse(uri)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: fmt.Sprintf("malformed URI: %s", uri)})
			return
		}
		if parsed.Scheme == schemeHTTP && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
			continue // http://localhost is allowed for development
		}
		if parsed.Scheme != schemeHTTPS {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: fmt.Sprintf("redirect_uri must use https scheme: %s", uri)})
			return
		}
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
			s.logger.ErrorContext(ctx, "failed to save client", outcomeError, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{outcomeError: oauthErrServerError})
			return
		}
	}

	s.logger.InfoContext(ctx, "registered oauth client", "clientId", clientID)

	writeJSON(w, http.StatusCreated, map[string]any{
		oauthClientID:                clientID,
		"client_secret":              clientSecret,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
	})
}

// passwordLoginConfigured reports whether a password login can succeed at all:
// either users.yaml is loaded or a single password is set. Without one — an
// API-key-only deployment, say — the authorization endpoint has nothing to
// check a password against and must refuse instead of comparing with an empty
// value. The same goes for what follows from a login: authorization codes are
// not exchanged, and access and refresh tokens are not honored.
func (s *Server) passwordLoginConfigured() bool {
	return s.userStore != nil || s.cfg.AuthPassword != ""
}

// validateClientRedirect checks that clientID is a registered client and
// redirectURI is one of its redirect URIs. It returns the reason for a
// rejection, or "" when the pair is valid.
func (s *Server) validateClientRedirect(ctx context.Context, clientID, redirectURI string) string {
	if s.tokenStore == nil {
		return ""
	}
	client, err := s.tokenStore.GetClient(ctx, clientID)
	if err != nil {
		return loginReasonUnknownClient
	}
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return ""
		}
	}
	return loginReasonInvalidRedirectURI
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.Method == http.MethodGet {
		clientID := r.URL.Query().Get(oauthClientID)
		redirectURI := r.URL.Query().Get(oauthRedirectURI)
		state := r.URL.Query().Get(oauthState)
		codeChallenge := r.URL.Query().Get(oauthCodeChallenge)
		codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
		scope := r.URL.Query().Get(oauthScope)

		// PKCE is mandatory (OAuth 2.1)
		if codeChallenge == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: "code_challenge is required (PKCE)"})
			return
		}
		if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: "only S256 code_challenge_method is supported"})
			return
		}

		// Validate redirect_uri against registered client before rendering login form
		switch s.validateClientRedirect(r.Context(), clientID, redirectURI) {
		case loginReasonUnknownClient:
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: descUnknownClient})
			return
		case loginReasonInvalidRedirectURI:
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI})
			return
		}
		if !s.passwordLoginConfigured() {
			writeJSON(w, http.StatusForbidden, map[string]string{outcomeError: oauthErrAccessDenied, oauthErrorDescription: descPasswordLoginDisabled})
			return
		}

		s.renderLoginForm(w, http.StatusOK, loginForm{ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	form := loginForm{
		ClientID:      r.FormValue(oauthClientID),
		RedirectURI:   r.FormValue(oauthRedirectURI),
		State:         r.FormValue(oauthState),
		CodeChallenge: r.FormValue(oauthCodeChallenge),
		Scope:         r.FormValue(oauthScope),
	}

	// PKCE is mandatory (OAuth 2.1)
	if form.CodeChallenge == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: "code_challenge is required (PKCE)"})
		return
	}

	// Whatever the outcome, the answer to a credential submission is not for
	// caches.
	w.Header().Set("Cache-Control", "no-store")

	// The checks below turn the request away before any credential is looked
	// at, so they are logged but are not login failures. The client and its
	// redirect_uri come first: the password check is not reachable without a
	// registered client.
	switch reason := s.validateClientRedirect(r.Context(), form.ClientID, form.RedirectURI); reason {
	case loginReasonUnknownClient:
		s.loginRejected(r, username, reason)
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: descUnknownClient})
		return
	case loginReasonInvalidRedirectURI:
		s.loginRejected(r, username, reason)
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI})
		return
	}
	if !s.passwordLoginConfigured() {
		s.loginRejected(r, username, loginReasonPasswordLoginDisabled)
		writeJSON(w, http.StatusForbidden, map[string]string{outcomeError: oauthErrAccessDenied, oauthErrorDescription: descPasswordLoginDisabled})
		return
	}

	// Reserve a slot against the failed-login limits before verifying the
	// password. In single-password mode the submitted username is not part of
	// the credential, so every attempt counts against the one configured
	// account — typing a different name must not start a fresh count.
	account := username
	if s.userStore == nil {
		account = s.cfg.AuthUser
	}
	attempt := s.loginThrottle.Acquire(r.Context(), account, clientIP(r))
	if !attempt.Allowed {
		s.loginFailed(r, username, loginReasonThrottledPrefix+attempt.Scope)
		wait := retryAfterSeconds(attempt.RetryAfter)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		form.Error = fmt.Sprintf("Too many failed login attempts. Try again in %s.", humanWait(wait))
		s.renderLoginForm(w, http.StatusTooManyRequests, form)
		return
	}

	// Authenticate user
	var userID, companyID, plan string
	var roles []string

	if s.userStore != nil {
		// Multi-user mode (users.yaml)
		user := s.userStore.Authenticate(username, password)
		if user == nil {
			s.loginFailed(r, username, loginReasonInvalidCredentials)
			form.Error = msgInvalidCredentials
			s.renderLoginForm(w, http.StatusUnauthorized, form)
			return
		}
		userID = user.Username
		companyID = user.Company
		plan = user.Plan
		roles = user.Roles
	} else {
		// Legacy single-password mode
		if !secretsEqual(password, s.cfg.AuthPassword) {
			s.loginFailed(r, username, loginReasonInvalidCredentials)
			form.Error = msgInvalidCredentials
			s.renderLoginForm(w, http.StatusUnauthorized, form)
			return
		}
		userID = s.cfg.AuthUser
		companyID = "default"
		plan = s.cfg.AuthPlan
		roles = s.cfg.AuthRolesList()
	}

	// The password was right, whatever happens to the auth code below.
	s.loginThrottle.Success(r.Context(), attempt)

	code := generateID()
	ac := &auth.AuthCode{
		Code:          code,
		ClientID:      form.ClientID,
		RedirectURI:   form.RedirectURI,
		CodeChallenge: form.CodeChallenge,
		Scope:         form.Scope,
		UserID:        userID,
		CompanyID:     companyID,
		Plan:          plan,
		Roles:         roles,
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}

	if s.tokenStore != nil {
		if err := s.tokenStore.SaveAuthCode(r.Context(), ac); err != nil {
			s.logger.ErrorContext(r.Context(), "failed to save auth code", outcomeError, err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}
	s.metrics.RecordLogin(loginMethodPassword, "success")

	sep := "?"
	if strings.Contains(form.RedirectURI, "?") {
		sep = "&"
	}
	http.Redirect(w, r, fmt.Sprintf("%s%scode=%s&state=%s", form.RedirectURI, sep, url.QueryEscape(code), url.QueryEscape(form.State)), http.StatusFound)
}

// secretsEqual compares a submitted secret with the configured one in constant
// time. Both are hashed first so that the comparison does not stop early on a
// length difference and reveal how long the configured secret is. An empty
// configured secret matches nothing.
func secretsEqual(submitted, configured string) bool {
	if configured == "" {
		return false
	}
	a, b := sha256.Sum256([]byte(submitted)), sha256.Sum256([]byte(configured))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// humanWait phrases a lockout's remaining seconds for the login form.
func humanWait(seconds int) string {
	minutes := (seconds + 59) / 60
	if minutes <= 1 {
		return "a minute"
	}
	return fmt.Sprintf("%d minutes", minutes)
}

// retryAfterSeconds rounds a lockout's remaining time up to whole seconds for
// the Retry-After header, so a client that honors it never retries early.
func retryAfterSeconds(d time.Duration) int {
	secs := int((d + time.Second - 1) / time.Second)
	return max(secs, 1)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// M-4: Prevent caching of token responses.
	w.Header().Set("Cache-Control", "no-store")

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq})
		return
	}

	switch r.FormValue("grant_type") {
	case oauthGrantAuthCode:
		s.handleAuthorizationCodeGrant(w, r)
	case oauthRefreshToken:
		s.handleRefreshTokenGrant(w, r)
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: "unsupported_grant_type"})
	}
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	code := r.FormValue("code")                  //nolint:gosec // G120: body size limited in handleToken
	codeVerifier := r.FormValue("code_verifier") //nolint:gosec // G120: body size limited in handleToken
	clientID := r.FormValue(oauthClientID)       //nolint:gosec // G120: body size limited in handleToken

	if s.tokenStore == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}
	if !s.passwordLoginConfigured() {
		s.tokenGrantRefused(r, loginMethodOAuthCode)
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	ac, err := s.tokenStore.ConsumeAuthCode(ctx, code)
	if err != nil {
		s.metrics.RecordLogin(loginMethodOAuthCode, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	if time.Now().After(ac.ExpiresAt) {
		s.metrics.RecordLogin(loginMethodOAuthCode, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	// Verify client_id matches the auth code (H-7).
	if clientID == "" || clientID != ac.ClientID {
		s.logger.WarnContext(ctx, "client_id mismatch in auth code grant",
			"expected", ac.ClientID, "got", clientID)
		s.metrics.RecordLogin(loginMethodOAuthCode, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	// PKCE S256 verification — always required (OAuth 2.1).
	// Use a single generic error for all PKCE failures (L-3).
	if ac.CodeChallenge == "" || codeVerifier == "" {
		s.metrics.RecordLogin(loginMethodOAuthCode, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError, oauthErrorDescription: "PKCE verification failed"})
		return
	}
	{
		h := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(computed), []byte(ac.CodeChallenge)) != 1 {
			s.metrics.RecordLogin(loginMethodOAuthCode, "failure")
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError, oauthErrorDescription: "PKCE verification failed"})
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
		s.logger.ErrorContext(ctx, "failed to save token", outcomeError, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{outcomeError: oauthErrServerError})
		return
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save refresh token", outcomeError, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{outcomeError: oauthErrServerError})
		return
	}

	s.metrics.RecordLogin(loginMethodOAuthCode, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":    accessToken,
		"token_type":      authSchemeBearer,
		"expires_in":      3600,
		oauthRefreshToken: refreshToken,
		oauthScope:        ac.Scope,
	})
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	refreshToken := r.FormValue(oauthRefreshToken) //nolint:gosec // G120: body size limited in handleToken
	clientID := r.FormValue(oauthClientID)         //nolint:gosec // G120: body size limited in handleToken

	if s.tokenStore == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}
	if !s.passwordLoginConfigured() {
		s.tokenGrantRefused(r, loginMethodOAuthRefresh)
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	oldTI, err := s.tokenStore.ConsumeRefreshToken(ctx, refreshToken)
	if err != nil {
		s.metrics.RecordLogin(loginMethodOAuthRefresh, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	// Verify client_id matches the refresh token's client (H-7).
	if clientID == "" || clientID != oldTI.ClientID {
		s.logger.WarnContext(ctx, "client_id mismatch in refresh token grant",
			"expected", oldTI.ClientID, "got", clientID)
		s.metrics.RecordLogin(loginMethodOAuthRefresh, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
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
		s.logger.ErrorContext(ctx, "failed to save token", outcomeError, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{outcomeError: oauthErrServerError})
		return
	}
	if err := s.tokenStore.SaveRefreshToken(ctx, ti); err != nil {
		s.logger.ErrorContext(ctx, "failed to save refresh token", outcomeError, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{outcomeError: oauthErrServerError})
		return
	}

	s.metrics.RecordLogin(loginMethodOAuthRefresh, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":    newAccessToken,
		"token_type":      authSchemeBearer,
		"expires_in":      3600,
		oauthRefreshToken: newRefreshToken,
		oauthScope:        oldTI.Scope,
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
button:hover{background:#1d4ed8}
.error{color:#b91c1c}</style></head>
<body>
<h2>ToolMesh</h2>
<p>Enter your credentials to authorize access.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>
{{end}}<form method="POST" action="/authorize">
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

// loginForm is the data the login page is rendered from: the OAuth request it
// carries along in hidden fields, and an optional message about why the
// previous attempt was turned away.
type loginForm struct {
	ClientID      string
	RedirectURI   string
	State         string
	CodeChallenge string
	Scope         string
	Error         string
}

// renderLoginForm writes the login page with the given status. A 401 goes out
// without a WWW-Authenticate challenge on purpose: there is no scheme that
// describes an HTML form, and "Basic" would make the browser put its own
// password dialog in front of the page.
func (s *Server) renderLoginForm(w http.ResponseWriter, status int, form loginForm) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	if err := loginTmpl.Execute(w, form); err != nil {
		s.logger.Error("failed to render login form", outcomeError, err)
	}
}

// jsonRPCResultEnvelope builds a JSON-RPC 2.0 success response object. It is
// shared by the buffered (writeJSONRPCResult) and streaming (SSE) paths so both
// emit byte-identical envelopes.
func jsonRPCResultEnvelope(id, result any) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"result":  result,
	}
}

// jsonRPCErrorEnvelope builds a JSON-RPC 2.0 error response object.
func jsonRPCErrorEnvelope(id any, code int, message string) map[string]any {
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		outcomeError: map[string]any{
			oauthCode: code,
			"message": message,
		},
	}
}

func (s *Server) writeJSONRPCResult(w http.ResponseWriter, id, result any) {
	s.logger.Debug("mcp response", "id", id, "result", result)
	writeJSON(w, http.StatusOK, jsonRPCResultEnvelope(id, result))
}

func (s *Server) writeJSONRPCError(w http.ResponseWriter, id any, code int, message string) {
	s.logger.Debug("mcp error response", "id", id, "code", code, "message", message)
	writeJSON(w, http.StatusOK, jsonRPCErrorEnvelope(id, code, message))
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
	b := make([]byte, generatedIDBytes)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
