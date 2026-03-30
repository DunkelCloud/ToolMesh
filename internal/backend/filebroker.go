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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"time"
)

// maxBase64Bytes is the maximum response size for inline base64 encoding (5 MB).
const maxBase64Bytes = 5 * 1024 * 1024

// FileBrokerClient uploads binary content and returns a download URL.
type FileBrokerClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// FileBrokerUploadResult holds the response from a file broker upload.
type FileBrokerUploadResult struct {
	FileID  string    `json:"file_id"`
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
}

// Upload streams content to the file broker and returns a download URL.
func (c *FileBrokerClient) Upload(ctx context.Context, filename string, contentType string, body io.Reader, ttl time.Duration) (*FileBrokerUploadResult, error) {
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)

	go func() {
		defer pw.Close()
		defer writer.Close()

		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, filename))
		h.Set("Content-Type", contentType)
		part, err := writer.CreatePart(h)
		if err != nil {
			pw.CloseWithError(fmt.Errorf("create multipart part: %w", err))
			return
		}
		if _, err := io.Copy(part, body); err != nil {
			pw.CloseWithError(fmt.Errorf("copy body to multipart: %w", err))
			return
		}
		if err := writer.WriteField("ttl", ttl.String()); err != nil {
			pw.CloseWithError(fmt.Errorf("write ttl field: %w", err))
			return
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/files/upload", pr)
	if err != nil {
		return nil, fmt.Errorf("create upload request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("file broker upload: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("file broker upload failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result FileBrokerUploadResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode file broker response: %w", err)
	}
	return &result, nil
}

// filenameFromHeaders extracts a filename from the Content-Disposition header.
// Falls back to a generated name using the content type extension.
func filenameFromHeaders(resp *http.Response, contentType string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		_, params, err := mime.ParseMediaType(cd)
		if err == nil {
			if fn, ok := params["filename"]; ok && fn != "" {
				return fn
			}
		}
	}

	// Generate a filename from content type
	exts, _ := mime.ExtensionsByType(contentType)
	ext := ""
	if len(exts) > 0 {
		ext = exts[0]
	}
	if ext == "" {
		ext = ".bin"
	}
	return "output" + ext
}

// encodeBinaryAsDataURL reads up to maxBase64Bytes from body and returns a data URL.
// Returns an error if the body exceeds the limit.
func encodeBinaryAsDataURL(body io.Reader, contentType string, limit int64) (string, int64, error) {
	lr := io.LimitReader(body, limit+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return "", 0, fmt.Errorf("read binary body: %w", err)
	}
	if int64(len(data)) > limit {
		return "", int64(len(data)), fmt.Errorf("binary response too large for base64 encoding (%d bytes > %d byte limit)", len(data), limit)
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	dataURL := fmt.Sprintf("data:%s;base64,%s", contentType, encoded)
	return dataURL, int64(len(data)), nil
}
