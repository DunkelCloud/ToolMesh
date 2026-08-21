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
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
)

// toolUploadFile is the built-in tool that fetches a URL server-side and
// stores the content in the file broker (DADL spec §6.2.3). The bytes never
// pass through the model context — the caller only handles the returned
// tm-blob:// handle.
const toolUploadFile = "upload_file"

// Parameter names of the upload_file built-in.
const (
	argNameURL      = "url"
	argNameTTL      = "ttl"
	argNameFilename = "filename"
)

// uploadFetchTimeout bounds a single server-side fetch for upload_file.
const uploadFetchTimeout = 60 * time.Second

// SetBlobStore enables the upload_file built-in tool. The fetch client is
// SSRF-safe and public-only: private, loopback, and link-local destinations
// are rejected at dial time. Callers on private networks upload directly via
// POST /files/upload instead.
func (h *Handler) SetBlobStore(store *blob.Store, limits blob.UploadLimits) {
	h.blobStore = store
	h.uploadLimits = limits
	h.uploadFetchClient = &http.Client{
		Timeout:   uploadFetchTimeout,
		Transport: backend.SSRFSafeTransport(uploadFetchTimeout, false, false),
	}
}

// handleUploadFile implements the upload_file built-in: fetch the given URL
// server-side, store the body as a blob, and return the handle plus download
// URL as JSON text content.
func (h *Handler) handleUploadFile(ctx context.Context, params map[string]any) (*backend.ToolResult, error) {
	if h.blobStore == nil {
		return uploadFileError("file broker is not configured on this server"), nil
	}

	rawURL, _ := params[argNameURL].(string)
	if rawURL == "" {
		return uploadFileError(`parameter "url" is required`), nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != schemeHTTP && u.Scheme != schemeHTTPS) {
		return uploadFileError(fmt.Sprintf("invalid url %q: only http(s) URLs can be fetched; for local or private sources POST the file to /files/upload directly", rawURL)), nil
	}

	ttl := h.uploadLimits.DefaultTTL
	if v, _ := params[argNameTTL].(string); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return uploadFileError(fmt.Sprintf("invalid ttl %q: expected a positive Go duration like 24h", v)), nil
		}
		if d > h.uploadLimits.MaxTTL {
			d = h.uploadLimits.MaxTTL
		}
		ttl = d
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return uploadFileError(fmt.Sprintf("create fetch request: %s", err)), nil
	}
	resp, err := h.uploadFetchClient.Do(req)
	if err != nil {
		return uploadFileError(fmt.Sprintf("fetch %s: %s", rawURL, err)), nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not echo the upstream body — for a caller-controlled URL that
		// would be an SSRF read channel. The status code is enough.
		return uploadFileError(fmt.Sprintf("fetch %s returned HTTP %d", rawURL, resp.StatusCode)), nil
	}
	if resp.ContentLength > h.uploadLimits.MaxBytes {
		return uploadFileError(fmt.Sprintf("file is %d bytes, exceeding the %d byte limit", resp.ContentLength, h.uploadLimits.MaxBytes)), nil
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	filename, _ := params[argNameFilename].(string)
	if filename == "" {
		filename = uploadFetchFilename(resp, u)
	}

	// Stream at most MaxBytes+1 into the store; one extra byte distinguishes
	// "exactly at the limit" from "over it" for chunked responses without a
	// Content-Length header.
	id, size, err := h.blobStore.PutNamed(io.LimitReader(resp.Body, h.uploadLimits.MaxBytes+1), contentType, filename, ttl)
	if err != nil {
		return uploadFileError(fmt.Sprintf("store fetched file: %s", err)), nil
	}
	if size > h.uploadLimits.MaxBytes {
		_ = h.blobStore.Delete(id)
		return uploadFileError(fmt.Sprintf("file exceeds the %d byte limit", h.uploadLimits.MaxBytes)), nil
	}
	info, err := h.blobStore.Stat(id)
	if err != nil {
		return uploadFileError(fmt.Sprintf("stat stored blob: %s", err)), nil
	}

	payload, err := json.Marshal(blob.UploadResult{
		FileID:      id,
		Handle:      blob.Handle(id),
		URL:         h.blobStore.URL(id),
		Expires:     info.ExpiresAt,
		Size:        size,
		ContentType: contentType,
	})
	if err != nil {
		return uploadFileError(fmt.Sprintf("encode result: %s", err)), nil
	}

	h.logger.InfoContext(ctx, "upload_file stored blob",
		"blob_id", id,
		"source_url", rawURL,
		"size_bytes", size,
		"content_type", contentType,
	)

	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: string(payload),
		}},
	}, nil
}

// uploadFetchFilename derives a filename from the response headers or the URL
// path, falling back to a content-type-based generated name.
func uploadFetchFilename(resp *http.Response, u *url.URL) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn, ok := params["filename"]; ok && fn != "" {
				return path.Base(fn)
			}
		}
	}
	if base := path.Base(u.Path); base != "" && base != "/" && base != "." {
		return base
	}
	exts, _ := mime.ExtensionsByType(resp.Header.Get("Content-Type"))
	if len(exts) > 0 {
		return "download" + exts[0]
	}
	return "download.bin"
}

func uploadFileError(msg string) *backend.ToolResult {
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: "upload_file: " + msg,
		}},
	}
}

// uploadFileToolDefinition is the MCP tool definition advertised when the
// blob store is configured.
func uploadFileToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name:        toolUploadFile,
		Description: "Store a file in the ToolMesh file broker by URL and get back a tm-blob:// handle. ToolMesh fetches the URL server-side — the file content never enters the conversation. Use the returned handle in any tool parameter: bare in file_url parameters, or with an explicit format fragment in string parameters — #base64 (raw Base64), #dataurl (data: URL, e.g. for vision/image inputs), #url (HTTP download URL). Fetches are public-only; from private networks POST the file to /files/upload instead.",
		InputSchema: map[string]any{
			contentKeyType: jsonTypeObject,
			schemaKeyProperties: map[string]any{
				argNameURL: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "HTTP(S) URL of the file to fetch and store.",
				},
				argNameTTL: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "How long to keep the blob, as a Go duration (e.g. \"24h\"). Default 1h, capped by the server.",
				},
				argNameFilename: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "Filename to record for downstream multipart uploads. Derived from the URL or response headers when omitted.",
				},
			},
			schemaKeyRequired: []string{argNameURL},
		},
	}
}
