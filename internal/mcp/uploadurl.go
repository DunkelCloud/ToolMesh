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
	"math"
	"net/http"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/blob"
)

// toolCreateUploadURL is the built-in tool that hands out a one-time upload
// URL of the file broker: the caller sends a file it holds locally there with
// a plain HTTP PUT, for example with curl, and passes the returned handle on.
// The bytes never pass through the model context, and the PUT needs no MCP
// credential.
const toolCreateUploadURL = "create_upload_url"

// Parameter names of create_upload_url, besides argNameFilename and
// argNameTTL (shared with upload_file).
const (
	argNameContentType = "content_type"
	argNameSize        = "size"
)

// handleUploadURL serves the upload URLs create_upload_url hands out. The
// token in the path is the only credential.
func (s *Server) handleUploadURL(w http.ResponseWriter, r *http.Request) {
	s.blobStore.HandleUploadURL(w, r, s.uploadLimits)
}

// handleCreateUploadURL implements create_upload_url.
func (h *Handler) handleCreateUploadURL(ctx context.Context, params map[string]any) *backend.ToolResult {
	if h.blobStore == nil {
		return createUploadURLError("file broker is not configured on this server")
	}
	ttl, err := h.blobTTL(params)
	if err != nil {
		return createUploadURLError(err.Error())
	}
	size, err := sizeParam(params[argNameSize])
	if err != nil {
		return createUploadURLError(err.Error())
	}
	filename, _ := params[argNameFilename].(string)
	contentType, _ := params[argNameContentType].(string)

	u, err := h.blobStore.NewUploadURL(blob.UploadURLRequest{
		Owner:       blobOwner(ctx),
		Filename:    filename,
		ContentType: contentType,
		Size:        size,
		TTL:         ttl,
	}, h.uploadLimits)
	if err != nil {
		return createUploadURLError(err.Error())
	}

	payload, err := json.Marshal(map[string]any{
		"upload_url":         u.URL,
		"method":             http.MethodPut,
		"handle":             blob.Handle(u.BlobID),
		"upload_url_expires": u.ExpiresAt,
		"max_bytes":          u.MaxBytes,
		"part_bytes":         blob.UploadURLPartBytes,
		"how": fmt.Sprintf("PUT the file to upload_url, for example: curl -fsS -T FILE -H 'Content-Type: TYPE' 'UPLOAD_URL'. "+
			"No credential is needed. Where a proxy caps a request below the file's size, send it in parts of part_bytes (%d): "+
			"one PUT per part, in order, each with Content-Range: bytes FIRST-LAST/TOTAL; a part is stored completely or not at all. GET upload_url shows how many "+
			"bytes are stored (received), so an interrupted upload continues there. Once complete, use handle like a handle "+
			"from upload_file; the answers of upload_url do not repeat it.", blob.UploadURLPartBytes),
	})
	if err != nil {
		return createUploadURLError(fmt.Sprintf("encode result: %s", err))
	}

	// The URL carries the token, the only credential of the upload: log the
	// blob it leads to, never the URL itself.
	h.logger.InfoContext(ctx, "upload URL created",
		"owner", blobOwner(ctx),
		"blob_id", u.BlobID,
		"size_bytes", size,
		"content_type", contentType,
		"expires", u.ExpiresAt,
	)
	return &backend.ToolResult{
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: string(payload),
		}},
	}
}

// blobTTL reads the ttl argument of upload_file and create_upload_url: a Go
// duration, the default when absent, capped at the maximum.
func (h *Handler) blobTTL(params map[string]any) (time.Duration, error) {
	v, _ := params[argNameTTL].(string)
	if v == "" {
		return h.uploadLimits.DefaultTTL, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid ttl %q: expected a positive Go duration like 24h", v)
	}
	return min(d, h.uploadLimits.MaxTTL), nil
}

// sizeParam reads the size argument: a whole number of bytes, 0 or absent
// when unknown.
func sizeParam(v any) (int64, error) {
	switch n := v.(type) {
	case nil:
		return 0, nil
	case float64:
		if n < 0 || n != math.Trunc(n) || n > math.MaxInt64/2 {
			return 0, fmt.Errorf("invalid size %v: expected a whole number of bytes", v)
		}
		return int64(n), nil
	case int:
		if n < 0 {
			return 0, fmt.Errorf("invalid size %d: expected a whole number of bytes", n)
		}
		return int64(n), nil
	case int64:
		if n < 0 {
			return 0, fmt.Errorf("invalid size %d: expected a whole number of bytes", n)
		}
		return n, nil
	case json.Number:
		i, err := n.Int64()
		if err != nil || i < 0 {
			return 0, fmt.Errorf("invalid size %q: expected a whole number of bytes", n.String())
		}
		return i, nil
	}
	return 0, fmt.Errorf("invalid size %v: expected a whole number of bytes", v)
}

func createUploadURLError(msg string) *backend.ToolResult {
	return &backend.ToolResult{
		IsError: true,
		Content: []any{map[string]any{
			contentKeyType: contentKeyText,
			contentKeyText: toolCreateUploadURL + ": " + msg,
		}},
	}
}

// createUploadURLToolDefinition is the MCP tool definition advertised when
// the blob store is configured.
func createUploadURLToolDefinition() ToolDefinition {
	return ToolDefinition{
		Name: toolCreateUploadURL,
		Description: "Get a one-time URL to put a file into the ToolMesh file broker from where you run, for a file that is not on the web: " +
			"for example one you rendered or downloaded with a local shell. PUT the file to the URL (curl -fsS -T FILE -H 'Content-Type: TYPE' 'URL'); " +
			"the PUT needs no credential, the file counts against your quota, and the bytes never enter the conversation. " +
			"Then use the returned tm-blob:// handle in any tool parameter, as with upload_file. The URL takes one file of up to max_bytes " +
			"(the file broker's limit for one file) and is valid for one hour. A proxy in front of ToolMesh may cap a request below that " +
			"(Cloudflare at 100 MB): then send the file in parts of part_bytes, one PUT per part in order with " +
			"Content-Range: bytes FIRST-LAST/TOTAL; GET on the URL shows how many bytes are stored, so an interrupted upload continues " +
			"from there. Keep the URL to yourself until the file is complete: whoever holds it can put one file into your quota. " +
			"It does not let anyone read the file.",
		InputSchema: map[string]any{
			contentKeyType: jsonTypeObject,
			schemaKeyProperties: map[string]any{
				argNameFilename: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "Filename to record for downstream multipart uploads.",
				},
				argNameContentType: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "Media type of the file, e.g. \"video/mp4\". Taken from the Content-Type of the first PUT when omitted.",
				},
				argNameSize: map[string]any{
					contentKeyType:       jsonTypeInteger,
					schemaKeyDescription: "Size of the file in bytes, if known. Checked against the size limit and your quota now, and the file must then have exactly this size.",
				},
				argNameTTL: map[string]any{
					contentKeyType:       jsonTypeString,
					schemaKeyDescription: "How long to keep the file once it is complete, as a Go duration (e.g. \"24h\"). Default 1h, capped by the server.",
				},
			},
		},
	}
}
