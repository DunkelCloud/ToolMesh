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

package backend

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/blob"
	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// defaultAllowedUploadDir is the directory under which file uploads must reside.
const defaultAllowedUploadDir = "/tmp/toolmesh-uploads"

// maxResponseBytes is the maximum number of bytes to read from a backend response.
const maxResponseBytes = 10 * 1024 * 1024 // 10 MB

// maxStreamingBytes is the maximum number of bytes for streaming binary responses.
const maxStreamingBytes = 100 * 1024 * 1024 // 100 MB

// defaultHTTPTimeout is the default timeout for non-streaming REST API requests.
const defaultHTTPTimeout = 30 * time.Second

// defaultStreamingHTTPTimeout is the default timeout for streaming REST API requests
// (e.g., SSE, chunked responses from LLM APIs). Streaming responses may take minutes
// for complex prompts, so the overall timeout is much longer and read progress is
// governed by the context deadline from the executor.
const defaultStreamingHTTPTimeout = 10 * time.Minute

// RESTAdapter implements ToolBackend for REST APIs described by DADL files.
type RESTAdapter struct {
	spec                *dadl.Spec
	httpClient          *http.Client
	streamingHTTPClient *http.Client // separate client with longer timeout for streaming responses
	fileFetchClient     *http.Client // dedicated client for file_url input fetches (no backend cookies/auth)
	auth                *dadl.RestAuth
	creds               credentials.CredentialStore
	logger              *slog.Logger
	allowedUploadDir    string
	fileBroker          *FileBrokerClient // nil = use blob store or error
	blobStore           *blob.Store       // embedded blob store for binary responses
	blobTTL             time.Duration     // TTL for blob URLs (from backends.yaml options.blob_ttl)
	exposeTools         []string          // bare tool names to promote as direct MCP tools (from backends.yaml expose_tools)
	includeTools        map[string]bool   // when non-nil, the only tools/composites this backend exposes (from backends.yaml include_tools)
	fileURLAllowedHosts map[string]bool   // optional allowlist of lowercase hostnames for caller file_url fetches; nil/empty = no restriction
	childGuard          ChildGuard        // authorizes composite child api.* calls; nil = no per-child checks (e.g. standalone/tests)
	hint                string            // operator guidance from backends.yaml hint:; empty = none configured
}

// SetChildGuard installs the guard used to authorize composite child api.*
// calls. It is wired after construction because the guard (the executor) is
// built after the adapters. A nil guard leaves child calls unchecked, which
// preserves behavior for standalone use and tests.
func (a *RESTAdapter) SetChildGuard(g ChildGuard) {
	a.childGuard = g
}

// RESTAdapterOptions controls per-backend security settings.
type RESTAdapterOptions struct {
	// AllowPrivateURL skips SSRF base_url validation, permitting private/loopback
	// addresses. This is the default for admin-configured backends.
	AllowPrivateURL bool
	// AllowPrivateFileURL permits caller-supplied file_url parameters to resolve
	// to private/loopback/link-local/metadata addresses. It is deliberately
	// separate from AllowPrivateURL: base_url is admin-configured and trusted,
	// whereas file_url values come from the tool caller. Default false (fail
	// closed) so a caller cannot turn the file fetch into an SSRF primitive
	// against internal services unless an operator opts in per backend.
	AllowPrivateFileURL bool
	// FileURLAllowedHosts, when non-empty, restricts caller file_url fetches to
	// this exact set of hostnames (matched case-insensitively). This is the
	// recommended control for backends that must fetch from a known internal
	// host: combine it with AllowPrivateFileURL so only those hosts are
	// reachable, rather than the whole private range.
	FileURLAllowedHosts []string
	// TLSSkipVerify accepts invalid or self-signed TLS certificates.
	TLSSkipVerify bool
	// ExposeTools lists bare tool names from this backend that should be
	// promoted to direct top-level MCP tools (in addition to discover_tools).
	// Names are bare (no backend prefix); the public MCP name is built as
	// "<backend>_<tool>" by the adapter. Names that do not match a known
	// tool or composite are dropped with a warning at construction time.
	ExposeTools []string
	// IncludeTools, when non-empty, restricts the backend's exposed surface to
	// exactly these tool/composite names — everything else in the DADL becomes
	// invisible to discover_tools, execute_code, and direct calls. This lets a
	// broad shared DADL (e.g. openai.dadl) be pointed at a chat-only endpoint
	// (Ollama, vLLM) while advertising only chat/embeddings. Empty means expose
	// every tool (the default). Unknown names are dropped with a warning.
	IncludeTools []string
	// Hint is the operator guidance configured for this backend in
	// backends.yaml (`hint:`). It is deployment-specific — what an admin wants
	// agents to know before using this particular instance — and is delivered
	// on a caller's first tool call into the backend. Distinct from the DADL's
	// backend.description, which says what the API is; empty means the
	// operator configured no hint.
	Hint string
}

// NewRESTAdapter creates a RESTAdapter from a parsed DADL spec.
// The spec.Backend.BaseURL must be set (either from the .dadl file or overridden via backends.yaml).
func NewRESTAdapter(spec *dadl.Spec, creds credentials.CredentialStore, logger *slog.Logger, opts RESTAdapterOptions) (*RESTAdapter, error) {
	if spec.Backend.BaseURL == "" {
		return nil, fmt.Errorf("REST backend %q: base_url is required (set in .dadl file or via backends.yaml url field)", spec.Backend.Name)
	}

	// SSRF protection: validate base_url does not point to private/internal addresses.
	// Skipped when the admin explicitly allows private URLs (default for local config).
	if !opts.AllowPrivateURL {
		if err := ValidateBaseURL(spec.Backend.BaseURL); err != nil {
			return nil, fmt.Errorf("SSRF: base_url validation failed for backend %q (%s): %w", spec.Backend.Name, spec.Backend.BaseURL, err)
		}
	}

	auth := dadl.NewRestAuth(spec.Backend.Auth, spec.Backend.BaseURL, creds, logger)

	// Each adapter gets its own transport with SSRF-safe dial hooks (H-4, M-19)
	// and redirect validation (H-3). When AllowPrivateURL is set, IP checks are
	// skipped in both the dialer and redirect handler.
	transport := SSRFSafeTransport(defaultHTTPTimeout, opts.AllowPrivateURL, opts.TLSSkipVerify)
	streamTransport := SSRFSafeTransport(defaultStreamingHTTPTimeout, opts.AllowPrivateURL, opts.TLSSkipVerify)
	redirectCheck := newRedirectChecker(opts.AllowPrivateURL)

	httpClient := &http.Client{
		Timeout:       defaultHTTPTimeout,
		Transport:     transport,
		CheckRedirect: redirectCheck,
	}
	streamingClient := &http.Client{
		Timeout:       defaultStreamingHTTPTimeout,
		Transport:     streamTransport,
		CheckRedirect: redirectCheck,
	}

	// Dedicated client for fetching caller-provided file_url inputs. Caller URLs
	// are a separate trust domain from the configured backend, so the fetch
	// policy is governed by AllowPrivateFileURL (default false) — NOT the
	// backend's AllowPrivateURL — and the client never carries the cookie jar
	// (set below), credential injection, or relaxed TLS settings. The long
	// timeout accommodates large files; per-call deadlines come from the request
	// context.
	fileRedirectCheck := newRedirectChecker(opts.AllowPrivateFileURL)
	fileFetchClient := &http.Client{
		Timeout:       defaultStreamingHTTPTimeout,
		Transport:     SSRFSafeTransport(defaultHTTPTimeout, opts.AllowPrivateFileURL, false),
		CheckRedirect: fileRedirectCheck,
	}

	// Share cookie jar from auth so cookies set during login (e.g. UniFi
	// session cookies) are forwarded to subsequent tool requests.
	if jar := auth.CookieJar(); jar != nil {
		httpClient.Jar = jar
		streamingClient.Jar = jar
	}

	includeTools := buildIncludeSet(spec, opts.IncludeTools, logger)
	exposeTools := filterExposeTools(spec, opts.ExposeTools, logger)
	// An expose_tools entry outside the include_tools allow-list would promote a
	// tool that discover_tools/execute_code cannot see — contradictory config.
	// Drop such entries (with a warning) so the promoted surface never exceeds
	// the included surface.
	if includeTools != nil {
		kept := exposeTools[:0]
		for _, name := range exposeTools {
			if includeTools[name] {
				kept = append(kept, name)
				continue
			}
			logger.Warn("expose_tools entry is not in include_tools, dropping promotion",
				"backend", spec.Backend.Name,
				"tool", name,
			)
		}
		exposeTools = kept
	}

	var fileURLAllowedHosts map[string]bool
	if len(opts.FileURLAllowedHosts) > 0 {
		fileURLAllowedHosts = make(map[string]bool, len(opts.FileURLAllowedHosts))
		for _, h := range opts.FileURLAllowedHosts {
			if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
				fileURLAllowedHosts[h] = true
			}
		}
	}

	return &RESTAdapter{
		spec:                spec,
		httpClient:          httpClient,
		streamingHTTPClient: streamingClient,
		fileFetchClient:     fileFetchClient,
		auth:                auth,
		creds:               creds,
		logger:              logger,
		allowedUploadDir:    defaultAllowedUploadDir,
		blobTTL:             time.Hour,
		exposeTools:         exposeTools,
		includeTools:        includeTools,
		fileURLAllowedHosts: fileURLAllowedHosts,
		hint:                opts.Hint,
	}, nil
}

// buildIncludeSet validates an include_tools list against the spec and returns
// the allow-set, or nil when no restriction is configured (expose everything).
// Names that match no tool or composite are dropped with a warning. If every
// name is invalid the result is an empty (non-nil) set, which hides all tools —
// surfacing the misconfiguration loudly rather than silently exposing the full
// API.
func buildIncludeSet(spec *dadl.Spec, names []string, logger *slog.Logger) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		_, hasTool := spec.Backend.Tools[name]
		_, hasComposite := spec.Backend.Composites[name]
		if !hasTool && !hasComposite {
			logger.Warn("include_tools entry does not match any tool or composite, skipping",
				"backend", spec.Backend.Name,
				"tool", name,
			)
			continue
		}
		set[name] = true
	}
	return set
}

// filterExposeTools drops names that do not match any tool or composite in
// the spec, logging a warning per drop. The returned slice preserves the
// caller's order and contains only names that resolve at construction time —
// hot-reload of the spec is not in scope here, so a one-shot validation is
// sufficient for the REST path. MCP backends apply the same shape after
// upstream tool discovery.
func filterExposeTools(spec *dadl.Spec, names []string, logger *slog.Logger) []string {
	if len(names) == 0 {
		return nil
	}
	filtered := make([]string, 0, len(names))
	for _, name := range names {
		_, hasTool := spec.Backend.Tools[name]
		_, hasComposite := spec.Backend.Composites[name]
		if !hasTool && !hasComposite {
			logger.Warn("expose_tools entry does not match any tool or composite, skipping",
				"backend", spec.Backend.Name,
				"tool", name,
			)
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

// SetFileBroker configures an external file broker client for binary response uploads.
func (a *RESTAdapter) SetFileBroker(fb *FileBrokerClient) {
	a.fileBroker = fb
}

// SetBlobStore configures the embedded blob store for binary responses.
func (a *RESTAdapter) SetBlobStore(bs *blob.Store) {
	a.blobStore = bs
}

// SetBlobTTL overrides the default blob TTL (1h).
func (a *RESTAdapter) SetBlobTTL(ttl time.Duration) {
	a.blobTTL = ttl
}

// SetHTTPTimeout overrides the default HTTP client timeout for non-streaming requests.
func (a *RESTAdapter) SetHTTPTimeout(d time.Duration) {
	a.httpClient.Timeout = d
}

// SetStreamingHTTPTimeout overrides the default HTTP client timeout for streaming requests.
func (a *RESTAdapter) SetStreamingHTTPTimeout(d time.Duration) {
	a.streamingHTTPClient.Timeout = d
}

// ListTools returns all tools available from this REST backend,
// including composites which appear identically to primitive tools.
func (a *RESTAdapter) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	tools := make([]ToolDescriptor, 0, len(a.spec.Backend.Tools)+len(a.spec.Backend.Composites))

	for name, tool := range a.spec.Backend.Tools {
		if !a.included(name) {
			continue
		}
		schema := buildInputSchema(tool)
		tools = append(tools, ToolDescriptor{
			Name:        name,
			Description: tool.Description,
			InputSchema: schema,
			Backend:     "rest:" + a.spec.Backend.Name,
			Access:      tool.Access,
		})
	}

	// Composites appear identically to primitive tools
	for name, comp := range a.spec.Backend.Composites {
		if !a.included(name) {
			continue
		}
		schema := buildCompositeInputSchema(comp)
		tools = append(tools, ToolDescriptor{
			Name:        name,
			Description: comp.Description,
			InputSchema: schema,
			Backend:     "rest:" + a.spec.Backend.Name,
			Access:      comp.Access,
		})
	}

	// Sort for deterministic output
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

// included reports whether a tool/composite name is exposed by this backend.
// With no include_tools restriction configured (includeTools == nil) every
// name is included; otherwise only names in the allow-set are.
func (a *RESTAdapter) included(name string) bool {
	if a.includeTools == nil {
		return true
	}
	return a.includeTools[name]
}

// Execute runs a tool by name with the given parameters.
// If the tool is a composite, it is executed in a sandboxed goja runtime.
func (a *RESTAdapter) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	// Enforce the include_tools allow-list at the execution boundary too, so a
	// hidden tool cannot be invoked by guessing its name even though it never
	// appears in discover_tools/execute_code.
	if !a.included(toolName) {
		return nil, fmt.Errorf("tool %q not found in REST backend %q", toolName, a.spec.Backend.Name)
	}

	// Check if it's a composite tool
	if comp, ok := a.spec.Backend.Composites[toolName]; ok {
		return a.executeComposite(ctx, toolName, &comp, params)
	}

	tool, ok := a.spec.Backend.Tools[toolName]
	if !ok {
		return nil, fmt.Errorf("tool %q not found in REST backend %q", toolName, a.spec.Backend.Name)
	}

	// Materialize tm-blob:// handles in string parameters before any request
	// building (DADL spec §6.2.4). file_url parameters keep their bare
	// handles — the file_url pipeline streams those directly from the store.
	params, err := a.substituteBlobHandles(&tool, params)
	if err != nil {
		return &ToolResult{
			Content: []any{textContent(fmt.Sprintf("Error: %s", err))},
			IsError: true,
		}, nil
	}

	a.logger.InfoContext(ctx, "executing REST tool",
		"backend", a.spec.Backend.Name,
		"tool", toolName,
		"method", tool.Method,
	)
	a.logger.DebugContext(ctx, "REST tool params",
		"tool", toolName,
		"params", params,
	)

	// Streaming binary path: stream directly to file broker without buffering
	rc := a.effectiveResponseConfig(&tool)
	if isBinaryResponse(rc) && rc.Streaming && rc.StreamHandling == "collect" && a.fileBroker != nil {
		return a.executeStreamingBinary(ctx, &tool, params, rc)
	}

	// Build and execute request (doRequest reads and closes the response body)
	resp, body, err := a.doRequest(ctx, &tool, params) //nolint:bodyclose // closed inside doRequest
	if err != nil {
		return nil, fmt.Errorf("execute REST tool %q: %w", toolName, err)
	}

	// Check for errors
	errConfig := a.effectiveErrorConfig(&tool)
	if errConfig != nil {
		mapper := dadl.NewErrorMapper(*errConfig)
		apiErr, retryable := mapper.CheckResponse(resp.StatusCode, body)
		if apiErr != nil {
			if retryable {
				// Retry with backoff
				if errConfig.RetryStrategy != nil {
					retryer := dadl.NewRetryer(*errConfig.RetryStrategy, a.logger)
					retryResp, retryErr := retryer.Do(ctx, func() (*http.Response, error) { //nolint:bodyclose // closed inside doRequest
						r, b, e := a.doRequest(ctx, &tool, params) //nolint:bodyclose // closed inside doRequest
						if e != nil {
							return nil, e
						}
						retryApiErr, retryRetryable := mapper.CheckResponse(r.StatusCode, b)
						if retryApiErr != nil {
							if retryRetryable {
								return nil, retryApiErr
							}
							// Terminal error during retry
							return r, nil
						}
						body = b
						return r, nil
					})
					if retryErr != nil {
						return a.apiErrorResult(retryErr), nil
					}
					resp = retryResp
				}
			}

			// Re-check after retries
			apiErr, _ = mapper.CheckResponse(resp.StatusCode, body)
			if apiErr != nil {
				// Handle 401 for session auth
				if resp.StatusCode == 401 {
					if err := a.auth.HandleUnauthorized(ctx); err == nil {
						// Retry once after re-auth
						resp, body, err = a.doRequest(ctx, &tool, params) //nolint:bodyclose // closed inside doRequest
						if err != nil {
							return &ToolResult{
								Content: []any{textContent(fmt.Sprintf("Error after re-auth: %s", err))},
								IsError: true,
							}, nil
						}
						apiErr, _ = mapper.CheckResponse(resp.StatusCode, body)
					}
				}
				if apiErr != nil {
					return a.apiErrorResult(apiErr), nil
				}
			}
		}
	} else if resp.StatusCode >= 400 {
		// No errors config: no retry semantics, but the §8.2 semantic code
		// still applies so error-handling code can branch uniformly.
		code := dadl.DefaultSemanticCode(resp.StatusCode)
		return &ToolResult{
			Content: []any{textContent(fmt.Sprintf("[%s] HTTP %d: %s", code, resp.StatusCode, string(body)))},
			IsError: true,
			Metadata: map[string]any{
				metadataKeyErrorCode:  code,
				metadataKeyStatusCode: resp.StatusCode,
			},
		}, nil
	}

	// Check for binary/file_url response — skip pagination/transform, route
	// through the binary handler which stores the bytes and returns a URL
	respConfig := a.effectiveResponseConfig(&tool)
	if isBinaryResponse(respConfig) {
		return a.handleBinaryResponse(ctx, &tool, resp, body, respConfig)
	}

	// Handle pagination
	pagConfig := a.effectivePaginationConfig(&tool)
	if pagConfig != nil && pagConfig.Behavior == "auto" {
		body, err = a.paginateResults(ctx, &tool, params, resp, body, pagConfig)
		if err != nil {
			a.logger.Warn("pagination error, returning partial results", "error", err)
		}
	}

	// Transform response, then redact (DADL spec §9.3 pipeline order:
	// result_path → transform → redact). Redaction is fail-closed: with a
	// redact list declared, neither a transform error (paths are relative
	// to the transformed result — positions would be unverifiable) nor a
	// redact error may leak the unredacted body.
	body, err = a.transformResponse(&tool, body)
	redactPaths := a.effectiveRedactPaths(&tool)
	if len(redactPaths) > 0 {
		if err != nil {
			return &ToolResult{
				Content: []any{textContent(fmt.Sprintf("Error: response transformation failed on a tool with response.redact; refusing unredacted output: %s", err))},
				IsError: true,
			}, nil
		}
		body, err = dadl.RedactResult(body, redactPaths)
		if err != nil {
			return &ToolResult{
				Content: []any{textContent(fmt.Sprintf("Error: response redaction failed: %s", err))},
				IsError: true,
			}, nil
		}
	} else if err != nil {
		a.logger.Warn("response transformation error", "error", err)
	}

	a.logger.DebugContext(ctx, "REST tool response",
		"backend", a.spec.Backend.Name,
		"tool", toolName,
		"status", resp.StatusCode,
		"bodyLen", len(body),
		"body", string(body),
	)

	return &ToolResult{
		Content: []any{textContent(string(body))},
		Metadata: map[string]any{
			metadataKeyBackend:    a.spec.Backend.Name,
			metadataKeyTransport:  transportTypeREST,
			metadataKeyStatusCode: resp.StatusCode,
		},
	}, nil
}

// Healthy checks if the backend is reachable.
func (a *RESTAdapter) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", a.spec.Backend.BaseURL, http.NoBody)
	if err != nil {
		return fmt.Errorf("create health check request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("health check returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// LookupTool returns the descriptor for a tool owned by this REST backend.
// The lookup runs against the parsed DADL spec held in memory, so it is
// O(1) and safe to call on the hot path of every tool execution.
func (a *RESTAdapter) LookupTool(toolName string) (ToolDescriptor, bool) {
	if tool, ok := a.spec.Backend.Tools[toolName]; ok {
		return ToolDescriptor{
			Name:        toolName,
			Description: tool.Description,
			InputSchema: buildInputSchema(tool),
			Backend:     "rest:" + a.spec.Backend.Name,
			Access:      tool.Access,
		}, true
	}
	if comp, ok := a.spec.Backend.Composites[toolName]; ok {
		return ToolDescriptor{
			Name:        toolName,
			Description: comp.Description,
			InputSchema: buildCompositeInputSchema(comp),
			Backend:     "rest:" + a.spec.Backend.Name,
			Access:      comp.Access,
		}, true
	}
	return ToolDescriptor{}, false
}

// BackendSummaries returns metadata for this REST backend. SpecID is set to
// the parsed spec's ContentHash so that the description builder can collapse
// multiple instances of the same DADL spec into one line.
func (a *RESTAdapter) BackendSummaries() []BackendInfo {
	return []BackendInfo{{
		Name:        a.spec.Backend.Name,
		Description: a.spec.Backend.Description,
		Hint:        a.hint,
		SpecID:      a.spec.ContentHash,
	}}
}

// PromotedTools returns one Promotion per tool this backend opted to expose
// as a direct top-level MCP tool (via backends.yaml expose_tools). The
// Descriptor.Name is the bare tool name (no backend prefix) — the natural
// public form like "web_search" or "fetch_url"; Canonical carries the
// "<backend>_<tool>" routing form. The composite backend resolves bare
// names back to Canonical at dispatch time and falls back to Canonical as
// the public name only when two backends would advertise the same bare
// name (cross-backend conflict).
func (a *RESTAdapter) PromotedTools() []Promotion {
	if len(a.exposeTools) == 0 {
		return nil
	}
	out := make([]Promotion, 0, len(a.exposeTools))
	for _, name := range a.exposeTools {
		desc, ok := a.LookupTool(name)
		if !ok {
			// Spec was validated at construction; if it disappeared after that
			// we silently skip rather than emit an error tool.
			continue
		}
		desc.Name = name
		out = append(out, Promotion{
			Descriptor: desc,
			Canonical:  a.spec.Backend.Name + "_" + name,
		})
	}
	return out
}

func (a *RESTAdapter) doRequest(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (*http.Response, []byte, error) {
	req, err := a.buildHTTPRequest(ctx, tool, params)
	if err != nil {
		return nil, nil, err
	}

	// Debug-level request trace. Header-based auth is not in the URL, but a
	// query-injected API key (auth.inject_into: query) is — so this line can
	// contain a credential at debug level. That is intentional for diagnosing
	// auth problems; the default LOG_LEVEL is "info" so it is not emitted unless
	// an operator explicitly opts into debug logging.
	a.logger.DebugContext(ctx, "REST request",
		"backend", a.spec.Backend.Name,
		"method", req.Method,
		"url", req.URL.String(),
	)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Binary/file_url responses get the streaming ceiling, and exceeding it is
	// an error rather than silent truncation — a truncated archive stored in
	// the blob store would be served as a corrupt download.
	limit := int64(maxResponseBytes)
	binaryResp := isBinaryResponse(a.effectiveResponseConfig(tool))
	if binaryResp {
		limit = maxStreamingBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > limit {
		if binaryResp {
			return nil, nil, fmt.Errorf("binary response exceeds the %d byte limit — enable response.streaming to pipe it to the file broker", limit)
		}
		body = body[:limit]
		a.logger.Warn("response body truncated at max size", "backend", a.spec.Backend.Name, "maxBytes", limit)
	}

	return resp, body, nil
}

// buildHTTPRequest assembles the full HTTP request for a tool invocation:
// URL, query string, body (JSON, form-encoded, multipart, or a fetched
// file_url stream), headers, content type, and auth. On any error a streaming
// body is closed before returning; once the request reaches an http.Client,
// the transport owns closing the body.
func (a *RESTAdapter) buildHTTPRequest(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (*http.Request, error) {
	toolPath, err := a.buildPath(tool, params)
	if err != nil {
		return nil, err
	}
	urlStr, err := joinURL(a.spec.Backend.BaseURL, toolPath)
	if err != nil {
		return nil, err
	}

	query := a.buildQuery(tool, params)
	if query != "" {
		urlStr += "?" + query
	}

	bodyReader, contentTypeOverride, contentLen, err := a.buildRequestBody(ctx, tool, params)
	if err != nil {
		return nil, err
	}
	closeBody := func() {
		if c, ok := bodyReader.(io.Closer); ok {
			_ = c.Close()
		}
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(tool.Method), urlStr, bodyReader)
	if err != nil {
		closeBody()
		return nil, fmt.Errorf("create request: %w", err)
	}
	if contentLen >= 0 {
		req.ContentLength = contentLen
	}

	// Set default headers
	for k, v := range a.spec.Backend.Defaults.Headers {
		req.Header.Set(k, v)
	}

	// Apply per-tool `in: header` params (overrides defaults, but Content-Type
	// and auth are reasserted below so they cannot be clobbered).
	if err := a.applyHeaderParams(req, tool, params); err != nil {
		closeBody()
		return nil, err
	}

	// Resolve the request Content-Type. A multipart boundary / fetched file type
	// (contentTypeOverride) always wins. Otherwise the effective content type
	// (tool.content_type, then backend defaults.content_type) applies, but only
	// when the request actually carries a body — a Content-Type on a bodyless
	// GET/DELETE is meaningless and would wrongly tag those requests. When a body
	// is present but no content type is resolved, fall back to application/json
	// unless a defaults.headers Content-Type is already set: a POST/PUT/PATCH body
	// with no Content-Type is invisible to strict JSON parsers and PHP $_POST
	// backends.
	switch {
	case contentTypeOverride != "":
		req.Header.Set("Content-Type", contentTypeOverride)
	case req.Body != nil:
		if ct := a.effectiveContentType(tool); ct != "" {
			req.Header.Set("Content-Type", ct)
		} else if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", contentTypeJSON)
		}
	}

	// Inject auth
	if err := a.auth.InjectAuth(ctx, req); err != nil {
		closeBody()
		return nil, fmt.Errorf("inject auth: %w", err)
	}

	return req, nil
}

// buildRequestBody assembles the request body for a tool invocation and
// returns the reader, a Content-Type override (empty = tool/default applies),
// and the body length in bytes (-1 = unknown or inferred from the reader).
//
// Body modes, in precedence order:
//   - file_url param with non-multipart content_type → fetched bytes streamed
//     as the raw body (DADL spec §6.2.1, e.g. Tika PUT /tika)
//   - file_url params with content_type multipart/form-data, or legacy local
//     "file" params → multipart/form-data (e.g. DeepL POST /v2/document)
//   - effective content_type application/x-www-form-urlencoded (tool, else
//     backend defaults.content_type) → form encoding
//   - otherwise → JSON
func (a *RESTAdapter) buildRequestBody(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (body io.Reader, contentType string, size int64, err error) {
	switch {
	case a.hasFileURLParams(tool) && tool.ContentType != dadl.ContentTypeMultipartForm:
		return a.buildRawFileBody(ctx, tool, params)
	case a.hasFileURLParams(tool) || a.hasFileParams(tool):
		mr, ct, err := a.buildMultipartBody(ctx, tool, params)
		if err != nil {
			return nil, "", -1, fmt.Errorf("build multipart body: %w", err)
		}
		return mr, ct, -1, nil
	case a.effectiveContentType(tool) == "application/x-www-form-urlencoded":
		bodyData := a.buildBody(tool, params)
		if bodyData == nil {
			return nil, "", -1, nil
		}
		return strings.NewReader(a.buildFormEncoded(bodyData)), "", -1, nil
	default:
		bodyData := a.buildBody(tool, params)
		if bodyData == nil {
			return nil, "", -1, nil
		}
		bodyJSON, err := json.Marshal(bodyData)
		if err != nil {
			return nil, "", -1, fmt.Errorf("marshal body: %w", err)
		}
		return bytes.NewReader(bodyJSON), "", -1, nil
	}
}

// joinURL combines a backend base URL with a tool path using RFC 3986
// reference resolution. If toolPath is itself an absolute URL (e.g. a tool
// hosted on a different host than the base, like Google Maps vs. Places API),
// it is returned as-is. Otherwise the base is treated as a directory and the
// tool path as relative to it, so a base with a path prefix
// (e.g. "https://gitlab.example.com/api/v4") is preserved when combined with
// a tool path like "/projects".
func joinURL(baseURL, toolPath string) (string, error) {
	ref, err := url.Parse(toolPath)
	if err != nil {
		return "", fmt.Errorf("parse tool path %q: %w", toolPath, err)
	}
	if ref.IsAbs() {
		return ref.String(), nil
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL %q: %w", baseURL, err)
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
		if base.RawPath != "" {
			base.RawPath += "/"
		}
	}
	relRef, err := url.Parse(strings.TrimPrefix(toolPath, "/"))
	if err != nil {
		return "", fmt.Errorf("parse tool path %q: %w", toolPath, err)
	}
	return base.ResolveReference(relRef).String(), nil
}

// formatScalarParam converts a primitive parameter value to its string form
// for use in URL paths, query strings, request headers, and form fields.
//
// JSON unmarshalling decodes every numeric value into float64. Formatting that
// float64 with fmt.Sprintf("%v", ...) routes through %g, which switches to
// scientific notation once the value reaches ~1e6 — so an integer ID like
// 1234567 becomes "1.234567e+06" and the request URL ends up at
// /networking/firewalls/1.234567e%2B06, which backends correctly reject as
// 404. strconv.FormatFloat with verb 'f' and precision -1 always produces the
// shortest exact decimal representation without exponents.
func formatScalarParam(v any) string {
	switch val := v.(type) {
	case string:
		return val
	case bool:
		if val {
			return boolTrue
		}
		return boolFalse
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(val), 'f', -1, 32)
	case int:
		return strconv.Itoa(val)
	case int32:
		return strconv.FormatInt(int64(val), 10)
	case int64:
		return strconv.FormatInt(val, 10)
	case uint:
		return strconv.FormatUint(uint64(val), 10)
	case uint32:
		return strconv.FormatUint(uint64(val), 10)
	case uint64:
		return strconv.FormatUint(val, 10)
	case json.Number:
		return string(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// buildPath substitutes path parameters into the tool's URL template. Every
// parameter declared with `in: path` is treated as required: a missing or nil
// value returns an error instead of leaving the literal `{name}` placeholder
// in the URL. Sending a request with an unsubstituted placeholder produces
// confusing backend-specific errors (400 "could not route", 401 auth errors,
// etc.) that look unrelated to the real cause.
func (a *RESTAdapter) buildPath(tool *dadl.ToolDef, params map[string]any) (string, error) {
	path := tool.Path
	for name, def := range tool.Params {
		if def.In != paramInPath {
			continue
		}
		val, ok := params[name]
		if !ok || val == nil {
			return "", fmt.Errorf("missing required path parameter %q", name)
		}
		str := formatScalarParam(val)
		if str == "" {
			return "", fmt.Errorf("path parameter %q cannot be empty", name)
		}
		path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(str))
	}
	return path, nil
}

func (a *RESTAdapter) buildQuery(tool *dadl.ToolDef, params map[string]any) string {
	var parts []string
	for name, def := range tool.Params {
		if def.In != paramInQuery {
			continue
		}
		val, ok := params[name]
		if !ok || val == nil {
			if def.Default != nil {
				val = def.Default
			} else {
				continue
			}
		}
		parts = append(parts, url.QueryEscape(name)+"="+url.QueryEscape(formatScalarParam(val)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// buildBody collects all `in: body` parameters into a map for JSON marshaling.
//
// An explicit nil value is preserved (the key is kept in the body so json.Marshal
// emits `"field":null`) because JSON null is semantically distinct from a missing
// key: on PATCH, many APIs (NetBox, GitLab, etc.) treat `field:null` as "clear
// this nullable field" while a missing key means "leave unchanged". Stripping
// nil here would silently change a clear request into a no-op.
//
// A key that is not present in params is skipped (no entry written), which
// correctly conveys "field omitted" — unless the param declares a `default`, in
// which case the default value is emitted, matching path params (buildPath) and
// header params. The form-encoded path handles nil separately in
// flattenFormValues (where `field=null` would be a meaningless string), so this
// change is JSON-only.
func (a *RESTAdapter) buildBody(tool *dadl.ToolDef, params map[string]any) map[string]any {
	body := make(map[string]any)
	for name, def := range tool.Params {
		if def.In != paramInBody {
			continue
		}
		if val, ok := params[name]; ok {
			body[name] = val
		} else if def.Default != nil {
			// An omitted body param falls back to its declared default, the same
			// way path and header params do. This lets DADL authors declare
			// constant body fields — e.g. a JSON-RPC envelope's "jsonrpc": "2.0"
			// and "method": "<name>" — via `default:` instead of forcing every
			// caller to repeat them.
			body[name] = def.Default
		}
	}
	if len(body) == 0 {
		return nil
	}
	if a.effectiveNestBodyKeys(tool) {
		body = nestDottedKeys(body)
	}
	return body
}

// effectiveNestBodyKeys reports whether dotted `in: body` param names should be
// nested into objects for this tool. A per-tool `nest_body_keys` (ToolDef) wins
// when set; otherwise the backend default (DefaultsConfig) applies. Default
// false preserves literal flat keys, which is what most JSON APIs — and notably
// RouterOS/MikroTik REST, whose property names legitimately contain dots —
// expect.
func (a *RESTAdapter) effectiveNestBodyKeys(tool *dadl.ToolDef) bool {
	if tool.NestBodyKeys != nil {
		return *tool.NestBodyKeys
	}
	return a.spec.Backend.Defaults.NestBodyKeys
}

// effectiveContentType returns the request-body Content-Type for a tool: the
// per-tool `content_type` when set, otherwise the backend `defaults.content_type`.
// It is consulted both to select the body encoding (buildRequestBody) and to set
// the Content-Type header (buildHTTPRequest), so a backend with a uniform
// encoding can declare it once in defaults instead of on every tool.
func (a *RESTAdapter) effectiveContentType(tool *dadl.ToolDef) string {
	if tool.ContentType != "" {
		return tool.ContentType
	}
	return a.spec.Backend.Defaults.ContentType
}

// nestDottedKeys rewrites a flat body map so that any key containing a dot is
// split into nested objects: {"gateway.monitor": x} becomes
// {"gateway": {"monitor": x}}. Both the JSON marshaler and the form-urlencoded
// flattener (which renders nested maps as gateway[monitor]) then emit the shape
// PHP/Phalcon model backends expect from a node.field convention.
//
// It is deliberately collision-safe: if a dotted key cannot be nested without
// overwriting an existing value (an intermediate segment already holds a
// non-object, or the leaf is already populated), the original literal key is
// kept so no data is silently dropped. Non-dotted keys are copied verbatim.
func nestDottedKeys(flat map[string]any) map[string]any {
	out := make(map[string]any, len(flat))
	// Copy plain keys first so dotted insertions can detect collisions against
	// an explicitly provided sibling (e.g. both "gateway" and "gateway.monitor").
	for k, v := range flat {
		if !strings.Contains(k, ".") {
			out[k] = v
		}
	}
	for k, v := range flat {
		if !strings.Contains(k, ".") {
			continue
		}
		if !insertNested(out, strings.Split(k, "."), v) {
			out[k] = v // collision — preserve the literal dotted key
		}
	}
	return out
}

// insertNested walks/creates the map chain described by parts and sets the leaf
// value. It returns false without mutating the leaf when an intermediate
// segment already holds a non-map value or the leaf key is already set, letting
// the caller fall back to keeping the literal key.
func insertNested(root map[string]any, parts []string, val any) bool {
	cur := root
	for _, p := range parts[:len(parts)-1] {
		existing, ok := cur[p]
		if !ok {
			child := make(map[string]any)
			cur[p] = child
			cur = child
			continue
		}
		child, ok := existing.(map[string]any)
		if !ok {
			return false // intermediate segment is not an object
		}
		cur = child
	}
	leaf := parts[len(parts)-1]
	if _, exists := cur[leaf]; exists {
		return false // leaf already populated
	}
	cur[leaf] = val
	return true
}

// reservedHeaderParams are HTTP headers that a DADL `in: header` param MUST
// NOT override. Content-Type is decided by multipart boundary / tool.ContentType
// / backend defaults; Authorization is owned by auth.InjectAuth. Allowing a
// tool param to set either one creates silent security and transport bugs.
var reservedHeaderParams = map[string]struct{}{
	"content-type":  {},
	"authorization": {},
}

// applyHeaderParams sets HTTP headers for every tool parameter declared with
// `in: header`. Caller-supplied values take precedence over parameter defaults;
// missing-and-no-default means the header is not emitted. Required params
// without a value return an error so the caller sees a clean 4xx-style failure
// instead of the upstream returning an opaque 400 for a silently dropped
// required header (e.g. Places API's X-Goog-FieldMask).
//
// This runs AFTER backend.defaults.headers (so per-tool header params can
// override a generic default like Accept) and BEFORE Content-Type resolution
// and auth injection (which are reasserted on the request anyway). Param names
// matching reservedHeaderParams are skipped case-insensitively.
func (a *RESTAdapter) applyHeaderParams(req *http.Request, tool *dadl.ToolDef, params map[string]any) error {
	for name, def := range tool.Params {
		if def.In != paramInHeader {
			continue
		}
		if _, reserved := reservedHeaderParams[strings.ToLower(name)]; reserved {
			continue
		}
		val, ok := params[name]
		if !ok || val == nil {
			if def.Default != nil {
				val = def.Default
			} else if def.Required {
				return fmt.Errorf("missing required header parameter %q", name)
			} else {
				continue
			}
		}
		str := formatScalarParam(val)
		if str == "" {
			if def.Required {
				return fmt.Errorf("header parameter %q cannot be empty", name)
			}
			continue
		}
		req.Header.Set(name, str)
	}
	return nil
}

// buildFormEncoded encodes body params as application/x-www-form-urlencoded.
// Nested objects are flattened using bracket notation (e.g. recurring[interval]=month),
// which is required by APIs like Stripe that use PHP-style form encoding.
// Arrays are encoded as key[0]=val&key[1]=val.
func (a *RESTAdapter) buildFormEncoded(body map[string]any) string {
	vals := url.Values{}
	flattenFormValues(vals, "", body)
	return vals.Encode()
}

// flattenFormValues recursively flattens a nested map into url.Values using bracket notation.
func flattenFormValues(vals url.Values, prefix string, v any) {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			key := k
			if prefix != "" {
				key = prefix + "[" + k + "]"
			}
			flattenFormValues(vals, key, child)
		}
	case []any:
		for i, child := range val {
			key := fmt.Sprintf("%s[%d]", prefix, i)
			flattenFormValues(vals, key, child)
		}
	case nil:
		// skip nil values
	default:
		vals.Set(prefix, formatScalarParam(val))
	}
}

// hasFileParams returns true if the tool has any parameters with type "file".
func (a *RESTAdapter) hasFileParams(tool *dadl.ToolDef) bool {
	for _, def := range tool.Params {
		if def.Type == paramTypeFile {
			return true
		}
	}
	return false
}

// buildMultipartBody creates a multipart/form-data request body with file uploads.
// File params are attached as file parts: type file_url is fetched from the
// caller-provided URL (DADL spec §6.2.1), the legacy type "file" is read from
// the local allowed upload directory. Non-file body params are added as form
// fields, falling back to their declared default when omitted (matching
// buildBody). Returns the body reader and the Content-Type header (with boundary).
func (a *RESTAdapter) buildMultipartBody(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (io.Reader, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for name, def := range tool.Params {
		if def.In != paramInBody {
			continue
		}
		val, ok := params[name]
		if !ok {
			if def.Default == nil {
				continue
			}
			val = def.Default
		}
		if val == nil {
			// Multipart has no null representation — an explicit nil means
			// "omit the field" here, unlike the JSON body path.
			continue
		}

		switch def.Type {
		case dadl.ParamTypeFileURL:
			rawURL, ok := val.(string)
			if !ok {
				return nil, "", fmt.Errorf("file parameter %q: expected URL string, got %T", name, val)
			}
			if err := a.writeFileURLPart(ctx, writer, name, rawURL); err != nil {
				return nil, "", err
			}
		case paramTypeFile:
			filePath, ok := val.(string)
			if !ok {
				return nil, "", fmt.Errorf("file param %q: expected string path, got %T", name, val)
			}
			cleanPath, err := a.validateUploadPath(name, filePath)
			if err != nil {
				return nil, "", err
			}
			f, err := os.Open(cleanPath) //nolint:gosec // validated against allowedUploadDir above
			if err != nil {
				return nil, "", fmt.Errorf("open file %q for param %q: %w", filePath, name, err)
			}
			part, err := writer.CreateFormFile(name, filepath.Base(filePath))
			if err != nil {
				_ = f.Close()
				return nil, "", fmt.Errorf("create form file %q: %w", name, err)
			}
			if _, err := io.Copy(part, f); err != nil {
				_ = f.Close()
				return nil, "", fmt.Errorf("copy file %q: %w", name, err)
			}
			_ = f.Close()
		default:
			if err := writer.WriteField(name, formatScalarParam(val)); err != nil {
				return nil, "", fmt.Errorf("write field %q: %w", name, err)
			}
		}
	}

	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart writer: %w", err)
	}

	return &buf, writer.FormDataContentType(), nil
}

func (a *RESTAdapter) effectiveErrorConfig(tool *dadl.ToolDef) *dadl.ErrorConfig {
	if tool.Errors != nil {
		return tool.Errors
	}
	return a.spec.Backend.Defaults.Errors
}

// apiErrorResult builds the error ToolResult for a failed call. When the
// error is a dadl.APIError, its §8.2 fields travel in the metadata so
// downstream consumers can branch on the semantic code without re-parsing
// the text form.
func (a *RESTAdapter) apiErrorResult(err error) *ToolResult {
	result := &ToolResult{
		Content: []any{textContent(fmt.Sprintf("Error: %s", err))},
		IsError: true,
	}
	var apiErr *dadl.APIError
	if errors.As(err, &apiErr) {
		result.Metadata = map[string]any{
			metadataKeyErrorCode:    apiErr.Code,
			metadataKeyStatusCode:   apiErr.HTTPStatus,
			metadataKeyErrorMessage: apiErr.Message,
		}
		if apiErr.ProviderCode != "" {
			result.Metadata[metadataKeyProviderCode] = apiErr.ProviderCode
		}
	}
	return result
}

// apiErrorFromMetadata reconstructs the structured §8.2 error from an
// IsError ToolResult, or nil when the result carries no semantic code.
func apiErrorFromMetadata(result *ToolResult) *dadl.APIError {
	if result == nil || result.Metadata == nil {
		return nil
	}
	code, _ := result.Metadata[metadataKeyErrorCode].(string)
	if code == "" {
		return nil
	}
	status, _ := result.Metadata[metadataKeyStatusCode].(int)
	msg, _ := result.Metadata[metadataKeyErrorMessage].(string)
	provider, _ := result.Metadata[metadataKeyProviderCode].(string)
	return &dadl.APIError{Code: code, HTTPStatus: status, Message: msg, ProviderCode: provider}
}

func (a *RESTAdapter) effectivePaginationConfig(tool *dadl.ToolDef) *dadl.PaginationConfig {
	// Check if tool explicitly disables pagination
	if tool.Pagination != nil {
		if s, ok := tool.Pagination.(string); ok && s == "none" {
			return nil
		}
	}
	return a.spec.Backend.Defaults.Pagination
}

func (a *RESTAdapter) effectiveResponseConfig(tool *dadl.ToolDef) *dadl.ResponseConfig {
	if tool.Response != nil {
		return tool.Response
	}
	return a.spec.Backend.Defaults.Response
}

// effectiveRedactPaths merges redact lists additively across defaults and
// tool level (DADL spec §9.3): unlike the rest of the response config — where
// a tool-level block replaces the defaults wholesale — a tool can extend the
// default redactions but never remove them. Duplicates are dropped.
func (a *RESTAdapter) effectiveRedactPaths(tool *dadl.ToolDef) []string {
	var paths []string
	seen := make(map[string]bool)
	add := func(rc *dadl.ResponseConfig) {
		if rc == nil {
			return
		}
		for _, p := range rc.Redact {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	add(a.spec.Backend.Defaults.Response)
	add(tool.Response)
	return paths
}

// isBinaryResponse reports whether the response config routes the body
// through the binary handler — either the explicit binary flag (DADL spec
// §6.3) or a file_url response type (§6.2.2).
func isBinaryResponse(rc *dadl.ResponseConfig) bool {
	return rc != nil && (rc.Binary || rc.IsFileURL())
}

// effectiveBlobTTL returns the per-tool response TTL when declared
// (response.ttl, DADL spec §6.2.2), falling back to the adapter-wide blob TTL.
func (a *RESTAdapter) effectiveBlobTTL(rc *dadl.ResponseConfig) time.Duration {
	if ttl := rc.FileURLTTL(); ttl > 0 {
		return ttl
	}
	return a.blobTTL
}

// handleBinaryResponse processes a binary backend response by either uploading
// to the file broker (if configured) or encoding as a base64 data URL.
func (a *RESTAdapter) handleBinaryResponse(ctx context.Context, _ *dadl.ToolDef, resp *http.Response, body []byte, respConfig *dadl.ResponseConfig) (*ToolResult, error) {
	// Determine content type: HTTP response header takes precedence, DADL config as fallback
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = respConfig.ContentType
	}
	if contentType == "" {
		contentType = contentTypeOctetStream
	}

	sizeBytes := int64(len(body))

	a.logger.InfoContext(ctx, "binary response detected",
		"content_type", contentType,
		"size_bytes", sizeBytes,
	)

	metadata := map[string]any{
		metadataKeyBackend:    a.spec.Backend.Name,
		metadataKeyTransport:  transportTypeREST,
		metadataKeyStatusCode: resp.StatusCode,
		"binary":              true,
	}

	// An empty body (e.g. HTTP 204, or Tika /unpack on a document without
	// embedded files) stores nothing — a download URL to a zero-byte blob
	// would only confuse the caller.
	if sizeBytes == 0 {
		resultJSON, _ := json.Marshal(map[string]any{
			fileKeyURL:       nil,
			fileKeySizeBytes: 0,
			"note":           "backend returned an empty body — no file stored",
		})
		return &ToolResult{
			Content:  []any{textContent(string(resultJSON))},
			Metadata: metadata,
		}, nil
	}

	// Try file broker first
	if a.fileBroker != nil {
		filename := filenameFromHeaders(resp, contentType)
		ttl := a.effectiveBlobTTL(respConfig)

		result, err := a.fileBroker.Upload(ctx, filename, contentType, bytes.NewReader(body), ttl)
		if err != nil {
			a.logger.WarnContext(ctx, "file broker upload failed, falling back to disk",
				"error", err,
			)
			// Fall through to base64
		} else {
			resultJSON, _ := json.Marshal(map[string]any{
				fileKeyID:          result.FileID,
				fileKeyURL:         result.URL,
				fileKeyExpires:     result.Expires.Format(time.RFC3339),
				fileKeyContentType: contentType,
				fileKeySizeBytes:   sizeBytes,
			})
			return &ToolResult{
				Content:  []any{textContent(string(resultJSON))},
				Metadata: metadata,
			}, nil
		}
	}

	// Fallback: embedded blob store
	if a.blobStore != nil {
		ttl := a.effectiveBlobTTL(respConfig)
		blobID, _, err := a.blobStore.Put(bytes.NewReader(body), contentType, ttl)
		if err != nil {
			return &ToolResult{
				Content: []any{textContent(fmt.Sprintf("Error: failed to store binary response: %s", err))},
				IsError: true,
			}, nil
		}

		blobURL := a.blobStore.URL(blobID)
		a.logger.InfoContext(ctx, "binary response stored as blob",
			"blob_id", blobID,
			"url", blobURL,
			"size_bytes", sizeBytes,
		)

		expires := time.Now().Add(ttl)
		resultJSON, _ := json.Marshal(map[string]any{
			fileKeyURL:         blobURL,
			fileKeyContentType: contentType,
			fileKeySizeBytes:   sizeBytes,
			fileKeyExpires:     expires.Format(time.RFC3339),
		})
		return &ToolResult{
			Content:  []any{textContent(string(resultJSON))},
			Metadata: metadata,
		}, nil
	}

	return &ToolResult{
		Content: []any{textContent(fmt.Sprintf("Error: binary response (%d bytes, %s) cannot be returned inline. Configure a blob store or file broker.", sizeBytes, contentType))},
		IsError: true,
	}, nil
}

// executeStreamingBinary handles streaming binary responses by piping the HTTP
// response body directly to the file broker without buffering in memory.
func (a *RESTAdapter) executeStreamingBinary(ctx context.Context, tool *dadl.ToolDef, params map[string]any, respConfig *dadl.ResponseConfig) (*ToolResult, error) {
	resp, err := a.doRequestRaw(ctx, tool, params)
	if err != nil {
		return nil, fmt.Errorf("streaming binary request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &ToolResult{
			Content: []any{textContent(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)))},
			IsError: true,
		}, nil
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = respConfig.ContentType
	}
	if contentType == "" {
		contentType = contentTypeOctetStream
	}

	filename := filenameFromHeaders(resp, contentType)
	ttl := a.effectiveBlobTTL(respConfig)

	// Limit streaming size to prevent unbounded memory/disk usage (H-5).
	limited := io.LimitReader(resp.Body, maxStreamingBytes)
	counter := &byteCounter{Reader: limited}

	a.logger.InfoContext(ctx, "streaming binary response to file broker",
		"content_type", contentType,
	)

	result, err := a.fileBroker.Upload(ctx, filename, contentType, counter, ttl)
	if err != nil {
		return nil, fmt.Errorf("file broker streaming upload: %w", err)
	}

	a.logger.InfoContext(ctx, "binary response detected",
		"content_type", contentType,
		"size_bytes", counter.N,
	)

	resultJSON, _ := json.Marshal(map[string]any{
		fileKeyID:          result.FileID,
		fileKeyURL:         result.URL,
		fileKeyExpires:     result.Expires.Format(time.RFC3339),
		fileKeyContentType: contentType,
		fileKeySizeBytes:   counter.N,
	})
	return &ToolResult{
		Content: []any{textContent(string(resultJSON))},
		Metadata: map[string]any{
			metadataKeyBackend:    a.spec.Backend.Name,
			metadataKeyTransport:  transportTypeREST,
			metadataKeyStatusCode: resp.StatusCode,
			"binary":              true,
			"streaming":           true,
		},
	}, nil
}

// doRequestRaw performs the HTTP request but returns the raw response without
// reading the body. The caller is responsible for closing resp.Body.
func (a *RESTAdapter) doRequestRaw(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (*http.Response, error) {
	req, err := a.buildHTTPRequest(ctx, tool, params)
	if err != nil {
		return nil, err
	}

	a.logger.DebugContext(ctx, "REST streaming request",
		"backend", a.spec.Backend.Name,
		"method", req.Method,
		"url", req.URL.String(),
	)

	resp, err := a.streamingHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	return resp, nil
}

// byteCounter wraps an io.Reader and counts bytes read through it.
type byteCounter struct {
	Reader io.Reader
	N      int64
}

func (c *byteCounter) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	c.N += int64(n)
	return n, err
}

func (a *RESTAdapter) paginateResults(ctx context.Context, tool *dadl.ToolDef, params map[string]any, firstResp *http.Response, firstBody []byte, config *dadl.PaginationConfig) ([]byte, error) {
	paginator := dadl.NewPaginator(*config)

	// Build current query params
	currentParams := make(map[string]string)
	for name, def := range tool.Params {
		if def.In == paramInQuery {
			if val, ok := params[name]; ok {
				currentParams[name] = formatScalarParam(val)
			}
		}
	}

	// Collect all results
	var allResults []json.RawMessage
	if err := collectPageResults(firstBody, &allResults); err != nil {
		return firstBody, nil // not an array, return as-is
	}

	maxPages := config.MaxPages
	if maxPages == 0 {
		maxPages = 20
	}
	// M-15: Hard upper limit on pagination to prevent excessive requests.
	const hardMaxPages = 50
	if maxPages > hardMaxPages {
		maxPages = hardMaxPages
	}

	for page := 1; page < maxPages; page++ {
		nextParams := paginator.NextPageParams(firstResp.StatusCode, firstResp.Header, firstBody, currentParams)
		if nextParams == nil {
			break
		}

		// Apply next page params
		nextToolParams := make(map[string]any, len(params))
		for k, v := range params {
			nextToolParams[k] = v
		}
		for k, v := range nextParams {
			if k == "_url" {
				continue // link_header special case — not implemented for full URL override yet
			}
			nextToolParams[k] = v
		}

		resp, body, err := a.doRequest(ctx, tool, nextToolParams) //nolint:bodyclose // closed inside doRequest
		if err != nil {
			return marshallResults(allResults), fmt.Errorf("pagination page %d: %w", page+1, err)
		}

		if resp.StatusCode >= 400 {
			break
		}

		if err := collectPageResults(body, &allResults); err != nil {
			break
		}

		firstResp = resp
		firstBody = body
		currentParams = nextParams
	}

	return marshallResults(allResults), nil
}

func collectPageResults(body []byte, results *[]json.RawMessage) error {
	var arr []json.RawMessage
	if err := json.Unmarshal(body, &arr); err != nil {
		return err
	}
	*results = append(*results, arr...)
	return nil
}

func marshallResults(results []json.RawMessage) []byte {
	data, err := json.Marshal(results)
	if err != nil {
		return []byte("[]")
	}
	return data
}

func (a *RESTAdapter) transformResponse(tool *dadl.ToolDef, body []byte) ([]byte, error) {
	respConfig := tool.Response
	if respConfig == nil {
		respConfig = a.spec.Backend.Defaults.Response
	}
	if respConfig == nil {
		return body, nil
	}

	// Extract via result_path
	if respConfig.ResultPath != "" {
		extracted, err := dadl.ExtractResult(body, respConfig.ResultPath)
		if err != nil {
			return body, fmt.Errorf("extract result_path: %w", err)
		}
		body = extracted
	}

	// Apply jq transform
	if respConfig.Transform != "" {
		transformed, err := dadl.ApplyTransform(body, respConfig.Transform)
		if err != nil {
			return body, fmt.Errorf("apply transform: %w", err)
		}
		body = transformed
	}

	return body, nil
}

// buildInputSchema generates a JSON Schema from the tool's ParamDef map.
func buildInputSchema(tool dadl.ToolDef) map[string]any {
	properties := make(map[string]any)
	var required []string

	// Sort param names for deterministic output
	names := make([]string, 0, len(tool.Params))
	for name := range tool.Params {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		def := tool.Params[name]
		prop := map[string]any{
			schemaKeyType: jsonSchemaType(def.Type),
		}
		properties[name] = prop

		if def.Required || def.In == paramInPath {
			required = append(required, name)
		}
	}

	schema := map[string]any{
		schemaKeyType:       schemaTypeObject,
		schemaKeyProperties: properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func jsonSchemaType(t string) string {
	switch t {
	case schemaTypeInteger, schemaTypeNumber, schemaTypeBoolean, "array", schemaTypeObject:
		return t
	default:
		return schemaTypeString
	}
}

func textContent(text string) map[string]any {
	return map[string]any{
		schemaKeyType:   contentTypeText,
		contentTypeText: text,
	}
}

// executeComposite runs a composite tool in the goja sandbox.
// Each api.* call within the composite delegates to Execute for primitive tools.
func (a *RESTAdapter) executeComposite(ctx context.Context, name string, comp *dadl.CompositeDef, params map[string]any) (*ToolResult, error) {
	a.logger.InfoContext(ctx, "executing composite tool",
		"backend", a.spec.Backend.Name,
		"composite", name,
	)

	// Collect all primitive tool names for the sandbox api object
	toolNames := make([]string, 0, len(a.spec.Backend.Tools))
	for tn := range a.spec.Backend.Tools {
		toolNames = append(toolNames, tn)
	}

	// The executor delegates api.* calls to the RESTAdapter's own Execute,
	// converting ToolResult to a plain value for the sandbox.
	executor := func(ctx context.Context, toolName string, toolParams map[string]any) (any, error) {
		// A child api.* call bypasses the top-level executor pipeline, so apply
		// the same authorization and pre-execution gate here, keyed on the
		// canonical "<backend>_<tool>" name. Fail closed: a guard error aborts
		// the child (and the composite).
		if a.childGuard != nil {
			canonical := a.spec.Backend.Name + "_" + toolName
			if err := a.childGuard.CheckChild(ctx, canonical, toolParams); err != nil {
				return nil, err
			}
		}
		result, err := a.Execute(ctx, toolName, toolParams)
		if err != nil {
			return nil, err
		}
		if result.IsError {
			// Surface the §8.2 structured error so the sandbox can expose
			// e.code / e.http_status / e.provider_code to composite code.
			if apiErr := apiErrorFromMetadata(result); apiErr != nil {
				return nil, apiErr
			}
			return nil, fmt.Errorf("tool %s returned error: %v", toolName, result.Content)
		}
		return extractToolResultContent(result), nil
	}

	result, err := composite.Execute(ctx, comp, name, toolNames, executor, params)
	if err != nil {
		a.logger.WarnContext(ctx, "composite execution failed",
			"backend", a.spec.Backend.Name,
			"composite", name,
			"error", err,
		)
		return &ToolResult{
			Content: []any{textContent(fmt.Sprintf("Error: %s", err))},
			IsError: true,
			Metadata: map[string]any{
				"backend":       a.spec.Backend.Name,
				"transport":     "composite",
				"consoleOutput": result.ConsoleOutput,
				"auditEvents":   result.AuditEvents,
			},
		}, nil
	}

	// Marshal the result value to JSON for the MCP content block
	resultJSON, marshalErr := json.Marshal(result.Value)
	if marshalErr != nil {
		resultJSON = []byte(fmt.Sprintf("%v", result.Value))
	}

	return &ToolResult{
		Content: []any{textContent(string(resultJSON))},
		Metadata: map[string]any{
			"backend":       a.spec.Backend.Name,
			"transport":     "composite",
			"consoleOutput": result.ConsoleOutput,
			"auditEvents":   result.AuditEvents,
		},
	}, nil
}

// extractToolResultContent converts a ToolResult into a value suitable for the JS sandbox.
// It extracts text content and tries to parse it as JSON.
func extractToolResultContent(result *ToolResult) any {
	if result == nil || len(result.Content) == 0 {
		return nil
	}
	for _, block := range result.Content {
		if m, ok := block.(map[string]any); ok {
			if text, ok := m["text"].(string); ok {
				var parsed any
				if err := json.Unmarshal([]byte(text), &parsed); err == nil {
					return parsed
				}
				return text
			}
		}
	}
	return nil
}

// buildCompositeInputSchema generates a JSON Schema from the composite's ParamDef map.
func buildCompositeInputSchema(comp dadl.CompositeDef) map[string]any {
	properties := make(map[string]any)
	var required []string

	names := make([]string, 0, len(comp.Params))
	for name := range comp.Params {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		def := comp.Params[name]
		prop := map[string]any{
			schemaKeyType: jsonSchemaType(def.Type),
		}
		if def.Default != nil {
			prop["default"] = def.Default
		}
		properties[name] = prop

		if def.Required {
			required = append(required, name)
		}
	}

	schema := map[string]any{
		schemaKeyType:       schemaTypeObject,
		schemaKeyProperties: properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}
