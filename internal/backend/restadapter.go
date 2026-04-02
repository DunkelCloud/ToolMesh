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
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
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

// RESTAdapter implements ToolBackend for REST APIs described by DADL files.
type RESTAdapter struct {
	spec             *dadl.Spec
	httpClient       *http.Client
	auth             *dadl.RestAuth
	creds            credentials.CredentialStore
	logger           *slog.Logger
	allowedUploadDir string
	fileBroker       *FileBrokerClient // nil = use blob store or error
	blobStore        *blob.Store       // embedded blob store for binary responses
	blobTTL          time.Duration     // TTL for blob URLs (from backends.yaml options.blob_ttl)
}

// NewRESTAdapter creates a RESTAdapter from a parsed DADL spec.
// The spec.Backend.BaseURL must be set (either from the .dadl file or overridden via backends.yaml).
func NewRESTAdapter(spec *dadl.Spec, creds credentials.CredentialStore, logger *slog.Logger) (*RESTAdapter, error) {
	if spec.Backend.BaseURL == "" {
		return nil, fmt.Errorf("REST backend %q: base_url is required (set in .dadl file or via backends.yaml url field)", spec.Backend.Name)
	}
	auth := dadl.NewRestAuth(spec.Backend.Auth, spec.Backend.BaseURL, creds, logger)

	return &RESTAdapter{
		spec:             spec,
		httpClient:       &http.Client{Timeout: 30 * time.Second},
		auth:             auth,
		creds:            creds,
		logger:           logger,
		allowedUploadDir: defaultAllowedUploadDir,
		blobTTL:          time.Hour,
	}, nil
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

// ListTools returns all tools available from this REST backend,
// including composites which appear identically to primitive tools.
func (a *RESTAdapter) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	tools := make([]ToolDescriptor, 0, len(a.spec.Backend.Tools)+len(a.spec.Backend.Composites))

	for name, tool := range a.spec.Backend.Tools {
		schema := buildInputSchema(tool)
		tools = append(tools, ToolDescriptor{
			Name:        name,
			Description: tool.Description,
			InputSchema: schema,
			Backend:     "rest:" + a.spec.Backend.Name,
		})
	}

	// Composites appear identically to primitive tools
	for name, comp := range a.spec.Backend.Composites {
		schema := buildCompositeInputSchema(comp)
		tools = append(tools, ToolDescriptor{
			Name:        name,
			Description: comp.Description,
			InputSchema: schema,
			Backend:     "rest:" + a.spec.Backend.Name,
		})
	}

	// Sort for deterministic output
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return tools, nil
}

// Execute runs a tool by name with the given parameters.
// If the tool is a composite, it is executed in a sandboxed goja runtime.
func (a *RESTAdapter) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	// Check if it's a composite tool
	if comp, ok := a.spec.Backend.Composites[toolName]; ok {
		return a.executeComposite(ctx, toolName, &comp, params)
	}

	tool, ok := a.spec.Backend.Tools[toolName]
	if !ok {
		return nil, fmt.Errorf("tool %q not found in REST backend %q", toolName, a.spec.Backend.Name)
	}

	a.logger.InfoContext(ctx, "executing REST tool",
		"backend", a.spec.Backend.Name,
		"tool", toolName,
		"method", tool.Method,
		"params", params,
	)

	// Streaming binary path: stream directly to file broker without buffering
	rc := a.effectiveResponseConfig(&tool)
	if rc != nil && rc.Binary && rc.Streaming && rc.StreamHandling == "collect" && a.fileBroker != nil {
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
						return &ToolResult{
							Content: []any{textContent(fmt.Sprintf("Error: %s", retryErr))},
							IsError: true,
						}, nil
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
					return &ToolResult{
						Content: []any{textContent(fmt.Sprintf("Error: %s", apiErr))},
						IsError: true,
					}, nil
				}
			}
		}
	} else if resp.StatusCode >= 400 {
		return &ToolResult{
			Content: []any{textContent(fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body)))},
			IsError: true,
		}, nil
	}

	// Check for binary response — skip pagination/transform, route through binary handler
	respConfig := a.effectiveResponseConfig(&tool)
	if respConfig != nil && respConfig.Binary {
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

	// Transform response
	body, err = a.transformResponse(&tool, body)
	if err != nil {
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
			"backend":    a.spec.Backend.Name,
			"transport":  "rest",
			"statusCode": resp.StatusCode,
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

// BackendSummaries returns metadata for this REST backend.
func (a *RESTAdapter) BackendSummaries() []BackendInfo {
	return []BackendInfo{{
		Name: a.spec.Backend.Name,
		Hint: a.spec.Backend.Description,
	}}
}

func (a *RESTAdapter) doRequest(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (*http.Response, []byte, error) {
	// Build URL
	urlStr := a.spec.Backend.BaseURL + a.buildPath(tool, params)

	// Build query string
	query := a.buildQuery(tool, params)
	if query != "" {
		urlStr += "?" + query
	}

	// Build body — multipart/form-data for file uploads, form-encoded or JSON otherwise
	var bodyReader io.Reader
	var contentTypeOverride string

	if a.hasFileParams(tool) {
		mr, ct, err := a.buildMultipartBody(tool, params)
		if err != nil {
			return nil, nil, fmt.Errorf("build multipart body: %w", err)
		}
		bodyReader = mr
		contentTypeOverride = ct
	} else if tool.ContentType == "application/x-www-form-urlencoded" {
		bodyData := a.buildBody(tool, params)
		if bodyData != nil {
			bodyReader = strings.NewReader(a.buildFormEncoded(bodyData))
		}
	} else {
		bodyData := a.buildBody(tool, params)
		if bodyData != nil {
			bodyJSON, err := json.Marshal(bodyData)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal body: %w", err)
			}
			bodyReader = bytes.NewReader(bodyJSON)
		}
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(tool.Method), urlStr, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("create request: %w", err)
	}

	// Set default headers
	for k, v := range a.spec.Backend.Defaults.Headers {
		req.Header.Set(k, v)
	}

	// Override content type: multipart boundary takes precedence, then tool-level override
	if contentTypeOverride != "" {
		req.Header.Set("Content-Type", contentTypeOverride)
	} else if tool.ContentType != "" {
		req.Header.Set("Content-Type", tool.ContentType)
	}

	// Inject auth
	if err := a.auth.InjectAuth(ctx, req); err != nil {
		return nil, nil, fmt.Errorf("inject auth: %w", err)
	}

	// Log full request details (URL without auth headers)
	a.logger.DebugContext(ctx, "REST request",
		"backend", a.spec.Backend.Name,
		"method", req.Method,
		"url", urlStr,
	)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) == maxResponseBytes {
		a.logger.Warn("response body truncated at max size", "backend", a.spec.Backend.Name, "maxBytes", maxResponseBytes)
	}

	return resp, body, nil
}

func (a *RESTAdapter) buildPath(tool *dadl.ToolDef, params map[string]any) string {
	path := tool.Path
	for name, def := range tool.Params {
		if def.In == "path" {
			if val, ok := params[name]; ok {
				path = strings.ReplaceAll(path, "{"+name+"}", url.PathEscape(fmt.Sprintf("%v", val)))
			}
		}
	}
	return path
}

func (a *RESTAdapter) buildQuery(tool *dadl.ToolDef, params map[string]any) string {
	var parts []string
	for name, def := range tool.Params {
		if def.In != "query" {
			continue
		}
		val, ok := params[name]
		if !ok {
			if def.Default != nil {
				val = def.Default
			} else {
				continue
			}
		}
		parts = append(parts, url.QueryEscape(name)+"="+url.QueryEscape(fmt.Sprintf("%v", val)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func (a *RESTAdapter) buildBody(tool *dadl.ToolDef, params map[string]any) map[string]any {
	body := make(map[string]any)
	for name, def := range tool.Params {
		if def.In != "body" {
			continue
		}
		if val, ok := params[name]; ok {
			body[name] = val
		}
	}
	if len(body) == 0 {
		return nil
	}
	return body
}

// buildFormEncoded encodes body params as application/x-www-form-urlencoded.
// Objects and arrays are JSON-encoded as their field value (Stripe-compatible).
func (a *RESTAdapter) buildFormEncoded(body map[string]any) string {
	vals := url.Values{}
	for k, v := range body {
		switch val := v.(type) {
		case string:
			vals.Set(k, val)
		case bool:
			if val {
				vals.Set(k, "true")
			} else {
				vals.Set(k, "false")
			}
		default:
			// For objects, arrays, and numbers: JSON-encode the value
			b, err := json.Marshal(v)
			if err == nil {
				vals.Set(k, string(b))
			}
		}
	}
	return vals.Encode()
}

// hasFileParams returns true if the tool has any parameters with type "file".
func (a *RESTAdapter) hasFileParams(tool *dadl.ToolDef) bool {
	for _, def := range tool.Params {
		if def.Type == "file" {
			return true
		}
	}
	return false
}

// buildMultipartBody creates a multipart/form-data request body with file uploads.
// File params (type: file) are read from the filesystem and attached as file parts.
// Non-file body params are added as form fields.
// Returns the body reader and the Content-Type header (with boundary).
func (a *RESTAdapter) buildMultipartBody(tool *dadl.ToolDef, params map[string]any) (io.Reader, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	for name, def := range tool.Params {
		if def.In != "body" {
			continue
		}
		val, ok := params[name]
		if !ok {
			continue
		}

		if def.Type == "file" {
			filePath, ok := val.(string)
			if !ok {
				return nil, "", fmt.Errorf("file param %q: expected string path, got %T", name, val)
			}
			absPath, err := filepath.Abs(filePath)
			if err != nil {
				return nil, "", fmt.Errorf("file param %q: resolve path: %w", name, err)
			}
			cleanPath := filepath.Clean(absPath)
			if strings.Contains(cleanPath, "..") {
				return nil, "", fmt.Errorf("file param %q: path traversal not allowed", name)
			}
			allowedAbs, _ := filepath.Abs(a.allowedUploadDir)
			allowedClean := filepath.Clean(allowedAbs)
			if !strings.HasPrefix(cleanPath, allowedClean+string(filepath.Separator)) && cleanPath != allowedClean {
				return nil, "", fmt.Errorf("file param %q: path %q is outside allowed upload directory", name, cleanPath)
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
		} else {
			if err := writer.WriteField(name, fmt.Sprintf("%v", val)); err != nil {
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

// handleBinaryResponse processes a binary backend response by either uploading
// to the file broker (if configured) or encoding as a base64 data URL.
func (a *RESTAdapter) handleBinaryResponse(ctx context.Context, _ *dadl.ToolDef, resp *http.Response, body []byte, respConfig *dadl.ResponseConfig) (*ToolResult, error) {
	// Determine content type: HTTP response header takes precedence, DADL config as fallback
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = respConfig.ContentType
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	sizeBytes := int64(len(body))

	a.logger.InfoContext(ctx, "binary response detected",
		"content_type", contentType,
		"size_bytes", sizeBytes,
	)

	metadata := map[string]any{
		"backend":    a.spec.Backend.Name,
		"transport":  "rest",
		"statusCode": resp.StatusCode,
		"binary":     true,
	}

	// Try file broker first
	if a.fileBroker != nil {
		filename := filenameFromHeaders(resp, contentType)
		ttl := a.blobTTL

		result, err := a.fileBroker.Upload(ctx, filename, contentType, bytes.NewReader(body), ttl)
		if err != nil {
			a.logger.WarnContext(ctx, "file broker upload failed, falling back to disk",
				"error", err,
			)
			// Fall through to base64
		} else {
			resultJSON, _ := json.Marshal(map[string]any{
				"file_id":      result.FileID,
				"url":          result.URL,
				"expires":      result.Expires.Format(time.RFC3339),
				"content_type": contentType,
				"size_bytes":   sizeBytes,
			})
			return &ToolResult{
				Content:  []any{textContent(string(resultJSON))},
				Metadata: metadata,
			}, nil
		}
	}

	// Fallback: embedded blob store
	if a.blobStore != nil {
		ttl := a.blobTTL
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
			"url":          blobURL,
			"content_type": contentType,
			"size_bytes":   sizeBytes,
			"expires":      expires.Format(time.RFC3339),
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
		contentType = "application/octet-stream"
	}

	filename := filenameFromHeaders(resp, contentType)
	ttl := a.blobTTL

	// Count bytes while streaming through to file broker
	counter := &byteCounter{Reader: resp.Body}

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
		"file_id":      result.FileID,
		"url":          result.URL,
		"expires":      result.Expires.Format(time.RFC3339),
		"content_type": contentType,
		"size_bytes":   counter.N,
	})
	return &ToolResult{
		Content: []any{textContent(string(resultJSON))},
		Metadata: map[string]any{
			"backend":    a.spec.Backend.Name,
			"transport":  "rest",
			"statusCode": resp.StatusCode,
			"binary":     true,
			"streaming":  true,
		},
	}, nil
}

// doRequestRaw performs the HTTP request but returns the raw response without
// reading the body. The caller is responsible for closing resp.Body.
func (a *RESTAdapter) doRequestRaw(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (*http.Response, error) {
	urlStr := a.spec.Backend.BaseURL + a.buildPath(tool, params)

	query := a.buildQuery(tool, params)
	if query != "" {
		urlStr += "?" + query
	}

	var bodyReader io.Reader
	var contentTypeOverride string

	if a.hasFileParams(tool) {
		mr, ct, err := a.buildMultipartBody(tool, params)
		if err != nil {
			return nil, fmt.Errorf("build multipart body: %w", err)
		}
		bodyReader = mr
		contentTypeOverride = ct
	} else if tool.ContentType == "application/x-www-form-urlencoded" {
		bodyData := a.buildBody(tool, params)
		if bodyData != nil {
			bodyReader = strings.NewReader(a.buildFormEncoded(bodyData))
		}
	} else {
		bodyData := a.buildBody(tool, params)
		if bodyData != nil {
			bodyJSON, err := json.Marshal(bodyData)
			if err != nil {
				return nil, fmt.Errorf("marshal body: %w", err)
			}
			bodyReader = bytes.NewReader(bodyJSON)
		}
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(tool.Method), urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	for k, v := range a.spec.Backend.Defaults.Headers {
		req.Header.Set(k, v)
	}

	if contentTypeOverride != "" {
		req.Header.Set("Content-Type", contentTypeOverride)
	} else if tool.ContentType != "" {
		req.Header.Set("Content-Type", tool.ContentType)
	}

	if err := a.auth.InjectAuth(ctx, req); err != nil {
		return nil, fmt.Errorf("inject auth: %w", err)
	}

	a.logger.DebugContext(ctx, "REST streaming request",
		"backend", a.spec.Backend.Name,
		"method", req.Method,
		"url", urlStr,
	)

	resp, err := a.httpClient.Do(req)
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
		if def.In == "query" {
			if val, ok := params[name]; ok {
				currentParams[name] = fmt.Sprintf("%v", val)
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
			"type": jsonSchemaType(def.Type),
		}
		properties[name] = prop

		if def.Required || def.In == "path" {
			required = append(required, name)
		}
	}

	schema := map[string]any{
		"type":       schemaTypeObject,
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// JSON Schema type constants used in buildInputSchema.
const (
	schemaTypeInteger = "integer"
	schemaTypeObject  = "object"
)

func jsonSchemaType(t string) string {
	switch t {
	case schemaTypeInteger, "number", "boolean", "array", schemaTypeObject:
		return t
	default:
		return "string"
	}
}

func textContent(text string) map[string]any {
	return map[string]any{
		"type": "text",
		"text": text,
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
		result, err := a.Execute(ctx, toolName, toolParams)
		if err != nil {
			return nil, err
		}
		if result.IsError {
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
			"type": jsonSchemaType(def.Type),
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
		"type":       schemaTypeObject,
		"properties": properties,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}
