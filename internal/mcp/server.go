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
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/health"
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
	// bearerThrottle limits failed bearer credentials per client address.
	bearerThrottle *auth.LoginThrottle
	callerClasses  *config.CallerClasses
	metrics        *metrics.Registry
	blobStore      *blob.Store
	uploadLimits   blob.UploadLimits
	health         HealthReporter

	// ownerFP caches the credential fingerprint of the single-password
	// owner for the password it was derived from (ownerFPFor).
	ownerFPMu  sync.Mutex
	ownerFP    string
	ownerFPFor string
}

// HealthReporter supplies the backend health /health reports.
type HealthReporter interface {
	Report() health.Report
}

// SetHealthReporter makes /health report backend health — a degraded or
// warning status naming the affected backends — instead of a bare ok.
func (s *Server) SetHealthReporter(h HealthReporter) {
	s.health = h
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
		handler:        handler,
		cfg:            cfg,
		logger:         logger,
		tokenStore:     tokenStore,
		userStore:      userStore,
		apiKeys:        apiKeys,
		rateLimiter:    rateLimiter,
		loginThrottle:  auth.NewLoginThrottle(loginThrottleConfig(cfg), nil, logger),
		bearerThrottle: auth.NewLoginThrottle(bearerThrottleConfig(cfg), nil, logger),
		callerClasses:  callerClasses,
		metrics:        m,
	}
}

// UseRedisLoginThrottle moves the failed-login counters from process memory,
// where NewServer keeps them, to Redis, so the limits hold across replicas and
// restarts. Call it before the server starts handling requests.
func (s *Server) UseRedisLoginThrottle(rdb *redis.Client) {
	s.loginThrottle = auth.NewLoginThrottle(loginThrottleConfig(s.cfg), rdb, s.logger)
	s.bearerThrottle = auth.NewLoginThrottle(bearerThrottleConfig(s.cfg), rdb, s.logger)
}

// bearerThrottleConfig limits failed bearer credentials per client address
// (TOOLMESH_APIKEY_MAX_FAILURES_PER_IP) within the window of the password
// login, in counters of their own. There is no account to count against: a
// bearer credential names none.
func bearerThrottleConfig(cfg *config.Config) auth.LoginThrottleConfig {
	return auth.LoginThrottleConfig{
		MaxFailuresPerIP: cfg.APIKeyMaxFailuresPerIP,
		Window:           time.Duration(cfg.LoginFailureWindow) * time.Second,
		Namespace:        "bearer",
	}
}

// errBearerThrottled is returned by authenticate when the client address has
// used up its failed bearer attempts.
type errBearerThrottled struct {
	retryAfter time.Duration
}

func (e *errBearerThrottled) Error() string {
	return "too many failed authentication attempts"
}

// writeThrottled answers a request refused by the bearer throttle and
// reports whether err was such a refusal.
func writeThrottled(w http.ResponseWriter, err error, body func(msg string)) bool {
	var throttled *errBearerThrottled
	if !errors.As(err, &throttled) {
		return false
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(throttled.retryAfter)))
	body("Too many failed authentication attempts. Try again in " + humanWait(retryAfterSeconds(throttled.retryAfter)) + ".")
	return true
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
	mux.HandleFunc(pathMCP, s.cors(s.handleMCP))
	mux.HandleFunc("/.well-known/oauth-authorization-server", s.cors(s.handleOAuthMetadata))
	mux.HandleFunc(pathProtectedResource, s.cors(s.handleProtectedResource))
	mux.HandleFunc(pathProtectedResource+pathMCP, s.cors(s.handleProtectedResourceMCP))
	mux.HandleFunc("/register", s.cors(s.handleRegister))
	mux.HandleFunc("/authorize", s.cors(s.handleAuthorize))
	mux.HandleFunc("/token", s.cors(s.handleToken))
	mux.HandleFunc(pathRevoke, s.cors(s.handleRevoke))
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
// The file counts against the quota of the authenticated user.
func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	user, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	s.blobStore.HandleUpload(w, r, s.uploadLimits, user.UserID)
}

// handleBlobs serves blob download and deletion (DADL spec §6.2.3). GET and
// HEAD are capability-based: the unguessable blob ID is the only credential,
// bounded by the TTL — this is deliberate so download URLs can be handed to
// backends (e.g. via a #url handle) without sharing MCP credentials. DELETE is
// destructive and has no capability use case, so it additionally requires MCP
// authentication; a party that merely holds a blob ID cannot destroy it.
//
// Only the user a blob was created for may delete it.
func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		user, ok := s.requireUser(w, r)
		if !ok {
			return
		}
		r = r.WithContext(blob.WithRequester(r.Context(), user.UserID))
	}
	s.blobStore.ServeHTTP(w, r)
}

// requireAuth enforces MCP authentication. It returns true when the request
// may proceed and, on failure, writes the response itself: 401 for a missing
// or rejected credential, 503 when the credential could not be checked. A
// server without any credential configured rejects every request.
func (s *Server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	_, ok := s.requireUser(w, r)
	return ok
}

// requireUser is requireAuth for handlers that need to know who the caller
// is. The user is nil exactly when ok is false.
func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (user *userctx.UserContext, ok bool) {
	user, err := s.authenticate(r)
	if writeThrottled(w, err, func(msg string) { http.Error(w, msg, http.StatusTooManyRequests) }) {
		return nil, false
	}
	if err != nil {
		w.Header().Set("Retry-After", authUnavailableRetryAfter)
		http.Error(w, msgAuthUnavailable, http.StatusServiceUnavailable)
		return nil, false
	}
	if user.Authenticated {
		return user, true
	}
	w.Header().Set("WWW-Authenticate", `Bearer realm="toolmesh"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return nil, false
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
				// Without this a client running in a browser cannot read the
				// challenge of a 401 and has to guess where the metadata is.
				w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
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
	uc, err := s.authenticate(r)
	if writeThrottled(w, err, func(msg string) {
		writeJSON(w, http.StatusTooManyRequests, jsonRPCErrorEnvelope(nil, -32000, msg))
	}) {
		return
	}
	if err != nil {
		// The credential was not judged, so this is not a 401: a client told
		// that its token is invalid would throw the token away.
		w.Header().Set("Retry-After", authUnavailableRetryAfter)
		writeJSON(w, http.StatusServiceUnavailable, jsonRPCErrorEnvelope(nil, -32000, msgAuthUnavailable))
		return
	}
	if !uc.Authenticated {
		presented := extractBearer(r) != ""
		credential := credentialNone
		if presented {
			credential = credentialRejected
		}
		s.logger.InfoContext(ctx, "mcp request rejected: unauthorized", logKeyRemote, auth.ClientIP(r), logKeyCredential, credential)
		s.writeMCPUnauthorized(w, presented)
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

// credentialConfigured reports whether any credential is configured: a
// password, users.yaml, an API key or apikeys.yaml. Authentication does not
// depend on it; without one, every request is rejected.
func (s *Server) credentialConfigured() bool {
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

// authenticate extracts user context from the request. It returns an error
// when a bearer credential was presented that no method accepted and at least
// one method could not look at it, because a part of the server was not
// available. That is not a verdict on the credential: the request is answered
// 503, not 401.
//
// A bearer credential is tried in order of cost. First what is decided in
// memory: the index of the API keys, and the single API key from the
// environment. Then the access tokens in the token store. Only what is still
// unknown after that is compared with bcrypt, against the API key entries
// that are not in the index yet. A valid access token therefore never costs a
// bcrypt comparison, and neither does a value that is no credential at all
// once every key has been seen (see auth.APIKeyStore).
//
// The index comes before the token store, although it is the API keys that
// used to cost the most, so that a caller with an API key does not depend on
// the token store being reachable.
func (s *Server) authenticate(r *http.Request) (*userctx.UserContext, error) {
	bearer := extractBearer(r)

	// Guessing at API keys from one address is throttled like password
	// logins: a slot is reserved before the credential is looked at, so
	// concurrent guesses cannot all pass a check made before any of them was
	// counted. A wrong credential keeps its slot; a right one hands it back.
	// Values shaped like the access tokens issued here reserve no slot up
	// front: they cannot be guessed, and expired ones arrive routinely, often
	// from the shared addresses of hosted clients. They reserve one only
	// before a bcrypt comparison (see checkBearer).
	var slot bearerSlot
	if bearer != "" && !isIssuedTokenShape(bearer) {
		if err := s.reserveBearerSlot(r, &slot); err != nil {
			return nil, err
		}
	}
	uc, err := s.checkBearer(r, bearer, &slot)
	s.settleBearerSlot(r, &slot, uc, err)
	return uc, err
}

// bearerSlot is a reservation against the per-address limit of failed bearer
// credentials.
type bearerSlot struct {
	attempt  auth.LoginAttempt
	reserved bool
}

// reserveBearerSlot reserves a slot for one bearer check from the request's
// client address, or returns errBearerThrottled when the address has used up
// its failed attempts.
func (s *Server) reserveBearerSlot(r *http.Request, slot *bearerSlot) error {
	if s.bearerThrottle == nil {
		return nil
	}
	ip := auth.ClientIP(r)
	a := s.bearerThrottle.Acquire(r.Context(), "", ip)
	if !a.Allowed {
		s.logger.InfoContext(r.Context(), "bearer authentication throttled",
			logKeyRemote, ip, "retry_after", retryAfterSeconds(a.RetryAfter))
		return &errBearerThrottled{retryAfter: a.RetryAfter}
	}
	slot.attempt, slot.reserved = a, true
	return nil
}

// settleBearerSlot settles a reservation once the bearer was checked: an
// accepted credential hands the slot back, one that could not be checked
// cancels it, and a rejected one keeps it as a failure.
func (s *Server) settleBearerSlot(r *http.Request, slot *bearerSlot, uc *userctx.UserContext, err error) {
	if !slot.reserved {
		return
	}
	switch {
	case err != nil:
		s.bearerThrottle.Cancel(r.Context(), slot.attempt)
	case uc != nil && uc.Authenticated:
		s.bearerThrottle.Success(r.Context(), slot.attempt)
	}
}

// checkBearer resolves the bearer credential of r. slot is the throttle
// reservation; a token-shaped value that reached no verdict by lookup
// reserves one here before it costs bcrypt comparisons.
func (s *Server) checkBearer(r *http.Request, bearer string, slot *bearerSlot) (*userctx.UserContext, error) {
	// Which methods the bearer was checked against, so that a credential no
	// method accepts is counted as a failure of one that could have.
	var checkedAPIKey, checkedOAuth, expiredToken bool
	// revokedUser is set for a valid token whose user is no longer configured.
	var revokedUser bool
	// unchecked is set when a method could not look at the bearer at all.
	var unchecked error

	if bearer != "" {
		// 1. API keys from apikeys.yaml that are in the index.
		if s.apiKeys != nil {
			checkedAPIKey = true
			if entry := s.apiKeys.Find(bearer); entry != nil {
				return s.apiKeyCaller(entry), nil
			}
		}

		// 2. Single API key (env var), compared in constant time.
		if s.cfg.APIKey != "" && s.apiKeys == nil {
			checkedAPIKey = true
			if secretsEqual(bearer, s.cfg.APIKey) {
				s.metrics.RecordLogin(loginMethodAPIKey, "success")
				return &userctx.UserContext{
					UserID:        s.cfg.AuthUser,
					CompanyID:     userDefault,
					Roles:         s.cfg.AuthRolesList(),
					Plan:          s.cfg.AuthPlan,
					Authenticated: true,
					CallerID:      s.cfg.AuthUser,
					CallerClass:   s.callerClasses.Resolve(s.cfg.AuthUser),
				}, nil
			}
		}

		// 3. OAuth Bearer Token (from Redis). Access tokens come out of the
		// password login and are honored only where there is one: a token
		// still in the store from a time when the configuration was
		// different is not a credential anymore.
		if s.tokenStore != nil && s.passwordLoginConfigured() {
			ti, err := s.tokenStore.GetToken(r.Context(), bearer)
			// The identity a token stands for is resolved against the
			// configuration in force now: a user removed or disabled since
			// the login loses access at once, and changed roles or plans
			// apply to tokens already issued.
			var id tokenIdentity
			current := false
			valid := err == nil && time.Now().Before(ti.ExpiresAt)
			if valid {
				id, current = s.currentIdentity(ti.UserID)
				current = current && id.matches(ti.CredentialFP)
				if !current {
					// The pair ends as a whole: a user who is added again
					// must log in, not resume the old refresh chain.
					_ = s.tokenStore.DeleteToken(r.Context(), bearer)
					if ti.RefreshToken != "" {
						_, _ = s.tokenStore.ConsumeRefreshToken(r.Context(), ti.RefreshToken)
					}
					s.logger.InfoContext(r.Context(), "access token refused: its user is no longer configured or the credential changed",
						"user", truncateForLog(ti.UserID), logKeyRemote, auth.ClientIP(r))
				}
			}
			switch {
			case current:
				callerID := ti.CallerID
				if callerID == "" {
					callerID = ti.ClientID
				}
				s.metrics.RecordLogin(loginMethodOAuthBearer, "success")
				return &userctx.UserContext{
					UserID:        ti.UserID,
					CompanyID:     id.companyID,
					Roles:         id.roles,
					Plan:          id.plan,
					Authenticated: true,
					CallerID:      callerID,
					CallerName:    ti.CallerName,
					CallerClass:   s.callerClasses.Resolve(callerID),
				}, nil
			case valid:
				// A valid token of a user who is gone: not accepted.
				checkedOAuth = true
				revokedUser = true
			case err == nil:
				checkedOAuth = true
				expiredToken = true
			case errors.Is(err, auth.ErrNotFound):
				checkedOAuth = true
			default:
				// The store failed, not the credential: logged, but not
				// counted as a login failure.
				unchecked = err
				s.logger.ErrorContext(r.Context(), "token lookup failed", outcomeError, err)
			}
		}

		// 4. API keys from apikeys.yaml that are not in the index yet. A
		// value the token store knows as an expired token is not a key.
		// A token-shaped value comes here without a reservation. bcrypt
		// comparisons cost CPU, so it takes a slot now; when its address is
		// throttled the comparison is skipped and the value is rejected like
		// any unknown credential, which keeps a client that holds an expired
		// token able to refresh it.
		skipComparison := false
		if s.apiKeys != nil && !expiredToken && !revokedUser && !slot.reserved && s.apiKeys.NeedsComparison() {
			skipComparison = s.reserveBearerSlot(r, slot) != nil
		}
		if s.apiKeys != nil && !expiredToken && !revokedUser && !skipComparison {
			entry, err := s.apiKeys.Verify(r.Context(), bearer)
			switch {
			case err != nil:
				unchecked = err
				s.compareDeferred(r, loginMethodAPIKey, err)
			case entry != nil:
				return s.apiKeyCaller(entry), nil
			}
		}
	}

	// Nothing accepted the request. That includes a server without any
	// credential configured: it is not open, it rejects every request.
	switch {
	case bearer == "":
		// No credential at all: not a failed login of any method, but a
		// request that was turned away, and counted as that.
		s.metrics.RecordLogin(loginMethodAnonymous, "failure")
	case unchecked != nil:
		return nil, fmt.Errorf("credential could not be checked: %w", unchecked)
	default:
		// A credential was presented and nothing accepted it.
		s.bearerRejected(r, bearer, checkedAPIKey, checkedOAuth, expiredToken)
	}

	return &userctx.UserContext{
		UserID:        userAnonymous,
		Authenticated: false,
		CallerID:      userAnonymous,
		CallerClass:   "untrusted",
	}, nil
}

// apiKeyCaller counts an accepted API key from apikeys.yaml and returns the
// caller it stands for.
func (s *Server) apiKeyCaller(entry *auth.APIKeyEntry) *userctx.UserContext {
	callerID := entry.CallerID
	var grantKey string
	if callerID == "" {
		callerID = entry.UserID
		// Two keys of one user without caller_id share the caller id, so
		// grants of kits are bound to the key instead.
		grantKey = entry.GrantKey()
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
		GrantKey:      grantKey,
	}
}

// compareDeferred logs a credential that was not checked because no bcrypt
// comparison could be started for it (see auth.CompareLimiter). That is not a
// failed login, so nothing is counted.
func (s *Server) compareDeferred(r *http.Request, method string, err error) {
	s.logger.WarnContext(r.Context(), "authentication deferred: no password hash comparison could be started",
		"method", method, logKeyRemote, auth.ClientIP(r), outcomeError, err)
}

// writeMCPUnauthorized answers an MCP request without a valid credential: 401
// with a Bearer challenge that names the protected resource metadata of this
// endpoint. That is what the MCP authorization specification asks of a server
// (RFC 9728, section 5.1) and what clients act on; they start or refresh an
// authorization on the status code, not on the JSON-RPC error in the body,
// which is kept as it was. presented says whether the request carried a
// bearer credential: only then does the challenge name an error (RFC 6750,
// section 3).
func (s *Server) writeMCPUnauthorized(w http.ResponseWriter, presented bool) {
	challenge := authSchemeBearer + ` realm="toolmesh"`
	if presented {
		challenge += `, error="invalid_token"`
	}
	challenge += `, resource_metadata="` + s.issuerBase() + pathProtectedResource + pathMCP + `"`
	w.Header().Set("WWW-Authenticate", challenge)
	writeJSON(w, http.StatusUnauthorized, jsonRPCErrorEnvelope(nil, -32001, "Unauthorized"))
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
		"method", method, logKeyRemote, auth.ClientIP(r), logKeyReason, reason)
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
		"username", truncateForLog(username), logKeyRemote, auth.ClientIP(r), logKeyReason, reason)
}

// tokenGrantRefused records a token request on a server that has no password
// login, where no grant can be valid: one WARN line and one failure for the
// grant's method.
func (s *Server) tokenGrantRefused(r *http.Request, method string) {
	s.metrics.RecordLogin(method, "failure")
	s.logger.WarnContext(r.Context(), "token grant refused",
		"method", method, logKeyRemote, auth.ClientIP(r), logKeyReason, loginReasonPasswordLoginDisabled)
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

// OAuth 2.1 Endpoints

func (s *Server) handleOAuthMetadata(w http.ResponseWriter, _ *http.Request) {
	iss := strings.TrimRight(s.cfg.Issuer, "/")
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 iss + "/",
		"authorization_endpoint": iss + "/authorize",
		"token_endpoint":         iss + "/token",
		"registration_endpoint":  iss + "/register",
		"revocation_endpoint":    iss + pathRevoke,
		"revocation_endpoint_auth_methods_supported": []string{tokenAuthMethodNone},
		"response_types_supported":                   []string{oauthCode},
		"grant_types_supported":                      []string{oauthGrantAuthCode, oauthRefreshToken},
		"code_challenge_methods_supported":           []string{"S256"},
		"token_endpoint_auth_methods_supported":      []string{"none"},
		"scopes_supported":                           []string{clientClaudeAI},
	})
}

func (s *Server) handleProtectedResource(w http.ResponseWriter, _ *http.Request) {
	s.writeProtectedResource(w, s.issuerBase()+"/")
}

// handleProtectedResourceMCP serves the protected resource metadata of the
// MCP endpoint itself, at the well-known URI RFC 9728 derives for a resource
// with a path. This is the document the 401 challenge of the endpoint points
// to. Its resource is the URL of the endpoint, because a client compares that
// value with the URL it connects to.
func (s *Server) handleProtectedResourceMCP(w http.ResponseWriter, _ *http.Request) {
	s.writeProtectedResource(w, s.issuerBase()+pathMCP)
}

func (s *Server) writeProtectedResource(w http.ResponseWriter, resource string) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.issuerBase() + "/"},
		"bearer_methods_supported": []string{"header"},
	})
}

// issuerBase returns the public URL of this server without a trailing slash.
func (s *Server) issuerBase() string {
	return strings.TrimRight(s.cfg.Issuer, "/")
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// DCR Rate Limiting. Fails open: an outage of Redis must not take
	// registration, and with it every new connection, down with it.
	if s.rateLimiter != nil {
		ip := auth.ClientIP(r)
		allowed, err := s.rateLimiter.Allow(ctx, ip)
		if err != nil {
			s.logger.WarnContext(ctx, "dcr rate limit unavailable, registration allowed without limit (fail-open)",
				outcomeError, err, "remote", ip)
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
		if isLoopbackRedirect(parsed) {
			continue // http://localhost is allowed for development
		}
		if parsed.Scheme != schemeHTTPS {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: fmt.Sprintf("redirect_uri must use https scheme: %s", uri)})
			return
		}
		if !redirectHostAllowed(uri, s.cfg.OAuthRedirectHosts) {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: fmt.Sprintf("redirect_uri host is not allowed on this server: %s", parsed.Host)})
			return
		}
	}

	clientID := generateID()
	clientSecret := generateID()

	now := time.Now()
	client := &auth.OAuthClient{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		ClientName:   req.ClientName,
		RedirectURIs: req.RedirectURIs,
		CreatedAt:    now,
	}
	// A client that never obtains a token goes after DCRClientTTL; the first
	// token extends it (extendClient).
	if s.cfg.DCRClientTTL > 0 {
		client.ExpiresAt = now.Add(time.Duration(s.cfg.DCRClientTTL) * time.Second)
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
		"token_endpoint_auth_method": tokenAuthMethodNone,
	})
}

// extendClient keeps a client that just obtained a token for
// DCRClientIdleTTL from now, or forever when that is 0. The token is issued
// either way: a client that cannot be extended only has to register again
// once it expires.
func (s *Server) extendClient(ctx context.Context, clientID string) {
	var until time.Time
	if s.cfg.DCRClientIdleTTL > 0 {
		// Never shorter than a refresh token lives, whatever the config.
		idle := max(s.cfg.DCRClientIdleTTL, config.MinDCRClientIdleTTL)
		until = time.Now().Add(time.Duration(idle) * time.Second)
	}
	if err := auth.ExtendClient(ctx, s.tokenStore, clientID, until); err != nil {
		level := slog.LevelWarn
		if errors.Is(err, auth.ErrNotFound) {
			level = slog.LevelInfo
		}
		s.logger.Log(ctx, level, "could not extend oauth client lifetime", "clientId", clientID, outcomeError, err)
	}
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

// clientForRedirect checks that clientID is a registered client, that
// redirectURI is one of its redirect URIs, and that the redirect host passes
// the TOOLMESH_OAUTH_REDIRECT_HOSTS allowlist (which also covers clients
// registered before the allowlist was set). It returns the client (nil
// without a token store) and the reason for a rejection, or "" when the pair
// is valid.
func (s *Server) clientForRedirect(ctx context.Context, clientID, redirectURI string) (client *auth.OAuthClient, reason string) {
	if !redirectHostAllowed(redirectURI, s.cfg.OAuthRedirectHosts) {
		return nil, loginReasonRedirectHostDenied
	}
	if s.tokenStore == nil {
		return nil, ""
	}
	registered, err := s.tokenStore.GetClient(ctx, clientID)
	if err != nil {
		return nil, loginReasonUnknownClient
	}
	for _, uri := range registered.RedirectURIs {
		if uri == redirectURI {
			return registered, ""
		}
	}
	return nil, loginReasonInvalidRedirectURI
}

// isLoopbackRedirect reports whether u is an http redirect URI on a loopback
// host, as native clients use them (RFC 8252 section 7.3).
func isLoopbackRedirect(u *url.URL) bool {
	if u.Scheme != schemeHTTP {
		return false
	}
	switch u.Hostname() {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// redirectHostAllowed reports whether redirectURI may be used under the
// configured host allowlist. An empty allowlist allows every host; loopback
// redirect URIs are always allowed. Entries match the host name exactly, or
// any subdomain when written as "*.example.com".
func redirectHostAllowed(redirectURI string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	u, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	if isLoopbackRedirect(u) {
		return true
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return false
	}
	for _, entry := range allowed {
		if suffix, ok := strings.CutPrefix(entry, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
			continue
		}
		if host == entry {
			return true
		}
	}
	return false
}

// redirectDisplayHost returns the host (with a non-default port) the login
// page names as the destination of the authorization: the party that will
// receive the code and, through it, access on the user's behalf.
func redirectDisplayHost(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Host == "" {
		return redirectURI
	}
	return strings.ToLower(u.Host)
}

// rejectClientRedirect answers a /authorize request whose client or
// redirect_uri check failed and reports whether it did.
func rejectClientRedirect(w http.ResponseWriter, reason string) bool {
	switch reason {
	case "":
		return false
	case loginReasonUnknownClient:
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: descUnknownClient})
	case loginReasonRedirectHostDenied:
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: "redirect_uri host is not allowed on this server"})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI})
	}
	return true
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
		client, reason := s.clientForRedirect(r.Context(), clientID, redirectURI)
		if rejectClientRedirect(w, reason) {
			return
		}
		if !s.passwordLoginConfigured() {
			writeJSON(w, http.StatusForbidden, map[string]string{outcomeError: oauthErrAccessDenied, oauthErrorDescription: descPasswordLoginDisabled})
			return
		}

		s.renderLoginForm(w, http.StatusOK, loginForm{
			ClientID: clientID, RedirectURI: redirectURI, State: state, CodeChallenge: codeChallenge, Scope: scope,
			ClientName: clientDisplayName(client), RedirectHost: redirectDisplayHost(redirectURI),
		})
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
	client, reason := s.clientForRedirect(r.Context(), form.ClientID, form.RedirectURI)
	if reason != "" {
		s.loginRejected(r, username, reason)
		if reason == loginReasonUnknownClient {
			writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidRedURI, oauthErrorDescription: descUnknownClient})
			return
		}
		rejectClientRedirect(w, reason)
		return
	}
	if !s.passwordLoginConfigured() {
		s.loginRejected(r, username, loginReasonPasswordLoginDisabled)
		writeJSON(w, http.StatusForbidden, map[string]string{outcomeError: oauthErrAccessDenied, oauthErrorDescription: descPasswordLoginDisabled})
		return
	}

	// The user must confirm the destination of the authorization. The page
	// names the redirect host, and the confirmation carries it back, so a
	// login started from a link the user did not expect is not completed by
	// typing the password alone.
	form.ClientName = clientDisplayName(client)
	form.RedirectHost = redirectDisplayHost(form.RedirectURI)
	if !strings.EqualFold(r.FormValue(oauthConfirmHost), form.RedirectHost) {
		s.loginRejected(r, username, loginReasonConsentMissing)
		form.Error = "Confirm that you trust " + form.RedirectHost + " before you sign in."
		s.renderLoginForm(w, http.StatusBadRequest, form)
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
	attempt := s.loginThrottle.Acquire(r.Context(), account, auth.ClientIP(r))
	if !attempt.Allowed {
		s.loginFailed(r, username, loginReasonThrottledPrefix+attempt.Scope)
		wait := retryAfterSeconds(attempt.RetryAfter)
		w.Header().Set("Retry-After", strconv.Itoa(wait))
		form.Error = fmt.Sprintf("Too many failed login attempts. Try again in %s.", humanWait(wait))
		s.renderLoginForm(w, http.StatusTooManyRequests, form)
		return
	}

	// Authenticate user
	var userID, companyID, plan, credentialFP string
	var roles []string

	if s.userStore != nil {
		// Multi-user mode (users.yaml)
		user, err := s.userStore.Authenticate(r.Context(), username, password)
		if err != nil {
			// The password was not checked. The attempt is neither a failed
			// login nor a successful one, so its slot goes back unused.
			s.loginThrottle.Cancel(r.Context(), attempt)
			s.compareDeferred(r, loginMethodPassword, err)
			w.Header().Set("Retry-After", authUnavailableRetryAfter)
			form.Error = msgLoginBusy
			s.renderLoginForm(w, http.StatusServiceUnavailable, form)
			return
		}
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
		credentialFP = hashFingerprint(user.PasswordHash)
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
		credentialFP = s.ownerFingerprint()
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
		CredentialFP:  credentialFP,
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
	code := r.FormValue("code")                    //nolint:gosec // G120: body size limited in handleToken
	codeVerifier := r.FormValue(oauthCodeVerifier) //nolint:gosec // G120: body size limited in handleToken
	clientID := r.FormValue(oauthClientID)         //nolint:gosec // G120: body size limited in handleToken

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
		CredentialFP:     ac.CredentialFP,
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

	s.extendClient(ctx, ti.ClientID)
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
		// The refresh token was consumed; its access token goes with it,
		// so the pair ends as a whole.
		_ = s.tokenStore.DeleteToken(ctx, oldTI.AccessToken)
		s.metrics.RecordLogin(loginMethodOAuthRefresh, "failure")
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	// Delete old access token
	_ = s.tokenStore.DeleteToken(ctx, oldTI.AccessToken)

	// Renewal re-checks the user against the configuration in force now and
	// takes the current company, plan and roles; a user removed or disabled
	// since the login gets no new token.
	id, ok := s.currentIdentity(oldTI.UserID)
	if !ok || !id.matches(oldTI.CredentialFP) {
		s.metrics.RecordLogin(loginMethodOAuthRefresh, "failure")
		s.logger.WarnContext(ctx, "refresh refused: user is no longer configured",
			"user", truncateForLog(oldTI.UserID), "clientId", oldTI.ClientID, logKeyRemote, auth.ClientIP(r))
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: invalidGrantError})
		return
	}

	newAccessToken := generateID()
	newRefreshToken := generateID()

	now := time.Now()
	ti := &auth.TokenInfo{
		AccessToken:      newAccessToken,
		RefreshToken:     newRefreshToken,
		ClientID:         oldTI.ClientID,
		UserID:           oldTI.UserID,
		CompanyID:        id.companyID,
		Plan:             id.plan,
		Roles:            id.roles,
		CredentialFP:     id.fp,
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

	s.extendClient(ctx, ti.ClientID)
	s.metrics.RecordLogin(loginMethodOAuthRefresh, "success")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":    newAccessToken,
		"token_type":      authSchemeBearer,
		"expires_in":      3600,
		oauthRefreshToken: newRefreshToken,
		oauthScope:        oldTI.Scope,
	})
}

// tokenIdentity is what an OAuth token grants under the configuration in
// force now.
type tokenIdentity struct {
	companyID string
	plan      string
	roles     []string
	// fp fingerprints the user's current credential; a token carrying
	// another fingerprint was issued for a credential that has changed.
	fp string
}

// matches reports whether a token carrying credentialFP may stand for this
// identity. Tokens from before fingerprints existed carry none and match.
func (id tokenIdentity) matches(credentialFP string) bool {
	return credentialFP == "" || credentialFP == id.fp
}

// credentialFPLen is the length in bytes of a credential fingerprint.
const credentialFPLen = 8

// hashFingerprint fingerprints a users.yaml password_hash. The bcrypt hash
// already contains a salt and costs bcrypt to test a guess against, so a
// short SHA-256 of it reveals nothing useful about the password.
func hashFingerprint(passwordHash string) string {
	sum := sha256.Sum256([]byte("toolmesh/credential-fp/v1\x00" + passwordHash))
	return hex.EncodeToString(sum[:credentialFPLen])
}

// ownerFingerprint fingerprints TOOLMESH_AUTH_PASSWORD. The password is
// plain text, so the fingerprint comes from scrypt rather than a fast hash:
// a copy of the token store must not make guessing the password cheap. It is
// derived once per password value.
func (s *Server) ownerFingerprint() string {
	s.ownerFPMu.Lock()
	defer s.ownerFPMu.Unlock()
	if s.ownerFP != "" && s.ownerFPFor == s.cfg.AuthPassword {
		return s.ownerFP
	}
	key, err := scrypt.Key([]byte(s.cfg.AuthPassword), []byte("toolmesh/credential-fp/v1"), 1<<15, 8, 1, credentialFPLen)
	if err != nil {
		// Only invalid parameters fail, and these are constant.
		s.logger.Error("credential fingerprint could not be derived", outcomeError, err)
		return ""
	}
	s.ownerFP, s.ownerFPFor = hex.EncodeToString(key), s.cfg.AuthPassword
	return s.ownerFP
}

// currentIdentity resolves userID against the configuration in force now:
// users.yaml when it is loaded, the single-password owner otherwise. ok is
// false when the user no longer exists or can no longer log in, so tokens
// issued to it are neither renewed nor honored.
func (s *Server) currentIdentity(userID string) (id tokenIdentity, ok bool) {
	if s.userStore != nil {
		u := s.userStore.Lookup(userID)
		if u == nil {
			return tokenIdentity{}, false
		}
		return tokenIdentity{companyID: u.Company, plan: u.Plan, roles: u.Roles, fp: hashFingerprint(u.PasswordHash)}, true
	}
	if s.cfg.AuthPassword == "" || userID != s.cfg.AuthUser {
		return tokenIdentity{}, false
	}
	return tokenIdentity{companyID: userDefault, plan: s.cfg.AuthPlan, roles: s.cfg.AuthRolesList(), fp: s.ownerFingerprint()}, true
}

// handleRevoke implements OAuth 2.0 token revocation (RFC 7009) for the
// access and refresh tokens issued here. Holding a token is enough to revoke
// it: the clients are public (token_endpoint_auth_method none), and revoking
// only takes access away. Revoking either token of a pair revokes both. The
// answer is 200 whether or not the token was known (RFC 7009 section 2.2).
func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq})
		return
	}
	token := r.PostFormValue(oauthRevokeToken)
	if token == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{outcomeError: oauthErrInvalidReq, oauthErrorDescription: "token is required"})
		return
	}
	if s.tokenStore != nil {
		s.revokeToken(r, token)
	}
	w.WriteHeader(http.StatusOK)
}

// revokeToken removes token, as access or refresh token, together with the
// other token of its pair.
func (s *Server) revokeToken(r *http.Request, token string) {
	ctx := r.Context()
	if ti, err := s.tokenStore.GetToken(ctx, token); err == nil {
		_ = s.tokenStore.DeleteToken(ctx, ti.AccessToken)
		if ti.RefreshToken != "" {
			_, _ = s.tokenStore.ConsumeRefreshToken(ctx, ti.RefreshToken)
		}
		s.logger.InfoContext(ctx, "oauth token revoked", "kind", "access_token", "clientId", ti.ClientID, logKeyRemote, auth.ClientIP(r))
		return
	}
	if ti, err := s.tokenStore.ConsumeRefreshToken(ctx, token); err == nil {
		if ti.AccessToken != "" {
			_ = s.tokenStore.DeleteToken(ctx, ti.AccessToken)
		}
		s.logger.InfoContext(ctx, "oauth token revoked", "kind", "refresh_token", "clientId", ti.ClientID, logKeyRemote, auth.ClientIP(r))
		return
	}
	// An access token that expired may be gone from the store while its
	// refresh token still lives; find the pair through the refresh token.
	if pl, ok := s.tokenStore.(auth.PairLookup); ok {
		if rt, err := pl.RefreshTokenOf(ctx, token); err == nil {
			if ti, err := s.tokenStore.ConsumeRefreshToken(ctx, rt); err == nil {
				_ = s.tokenStore.DeleteToken(ctx, token)
				s.logger.InfoContext(ctx, "oauth token revoked", "kind", "expired_access_token", "clientId", ti.ClientID, logKeyRemote, auth.ClientIP(r))
			}
		}
	}
}

// handleHealth reports liveness plus the aggregate backend health. The
// status code is 200 even when a backend is degraded: the endpoint also
// serves container liveness probes, and a failing upstream credential is no
// reason to restart ToolMesh. Monitors match on the status field instead.
func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	if s.health == nil {
		writeJSON(w, http.StatusOK, health.Report{Status: health.StatusOK})
		return
	}
	writeJSON(w, http.StatusOK, s.health.Report())
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html>
<head><title>ToolMesh Login</title>
<style>body{font-family:system-ui;max-width:400px;margin:80px auto;padding:20px}
input{width:100%;padding:8px;margin:8px 0;box-sizing:border-box}
button{width:100%;padding:10px;background:#2563eb;color:white;border:none;border-radius:4px;cursor:pointer}
button:hover{background:#1d4ed8}
.error{color:#b91c1c}
.consent{border:1px solid #d1d5db;border-radius:6px;padding:12px;margin:12px 0}
.host{font-size:1.4em;font-weight:bold;word-break:break-all;margin:4px 0}
.note{color:#6b7280;font-size:.9em}
.confirm{display:block;margin:12px 0}
.confirm input{width:auto;margin-right:6px}</style></head>
<body>
<h2>ToolMesh</h2>
<div class="consent">
<p>An application asks for access to your ToolMesh tools.</p>
<p>After you sign in, access is handed to:</p>
<p class="host">{{.RedirectHost}}</p>
<p class="name">Name given by the application: &ldquo;{{if .ClientName}}{{.ClientName}}{{else}}none{{end}}&rdquo;<br>
<span class="note">The application chose this name itself; ToolMesh has not verified it.</span></p>
</div>
<p>Continue only if you started this connection yourself and trust <strong>{{.RedirectHost}}</strong>.</p>
{{if .Error}}<p class="error" role="alert">{{.Error}}</p>
{{end}}<form method="POST" action="/authorize">
<input type="hidden" name="client_id" value="{{.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
<input type="hidden" name="state" value="{{.State}}">
<input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
<input type="hidden" name="scope" value="{{.Scope}}">
<label class="confirm"><input type="checkbox" name="confirm_host" value="{{.RedirectHost}}" required> I trust {{.RedirectHost}} with access to my ToolMesh tools</label>
<input type="text" name="username" placeholder="Username" autofocus>
<input type="password" name="password" placeholder="Password">
<button type="submit">Authorize {{.RedirectHost}}</button>
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
	// ClientName is the client_name from registration: self-declared by the
	// client and shown as such, never trusted.
	ClientName string
	// RedirectHost is the host of the redirect_uri, the party that receives
	// the authorization; the user confirms it explicitly.
	RedirectHost string
}

// clientDisplayName returns the self-declared client_name of client, cut to
// a length that fits the login page, or "" when there is none.
func clientDisplayName(client *auth.OAuthClient) string {
	if client == nil {
		return ""
	}
	name := strings.TrimSpace(client.ClientName)
	if r := []rune(name); len(r) > 80 {
		name = string(r[:80]) + "…"
	}
	return name
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
