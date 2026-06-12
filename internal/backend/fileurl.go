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
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// maxFileFetchBytes caps the size of a single file_url input fetch. It matches
// the streaming-response limit so uploads and downloads share one ceiling.
const maxFileFetchBytes = maxStreamingBytes

// fetchedFile is the result of resolving a file_url parameter: a readable
// byte stream plus the metadata needed to build the backend request.
type fetchedFile struct {
	Body        io.ReadCloser
	ContentType string
	Filename    string
	Size        int64 // -1 when unknown (e.g. chunked HTTP response)
}

// hasFileURLParams reports whether the tool declares any file_url body
// parameters (DADL spec §6.2.1).
func (a *RESTAdapter) hasFileURLParams(tool *dadl.ToolDef) bool {
	for _, def := range tool.Params {
		if def.Type == dadl.ParamTypeFileURL && def.In == paramInBody {
			return true
		}
	}
	return false
}

// singleFileURLParam returns the name and definition of the tool's only
// file_url body parameter. Parse-time validation (validateFileURLParams)
// guarantees exactly one exists for tools in raw-body mode.
func singleFileURLParam(tool *dadl.ToolDef) (string, dadl.ParamDef) {
	for name, def := range tool.Params {
		if def.Type == dadl.ParamTypeFileURL && def.In == paramInBody {
			return name, def
		}
	}
	return "", dadl.ParamDef{}
}

// buildRawFileBody resolves the tool's single file_url parameter and returns
// the fetched stream as the raw request body (DADL spec §6.2.1, non-multipart
// mode — e.g. Tika's PUT /tika with content_type: application/octet-stream).
// The returned content type is the tool's declared content_type, falling back
// to the fetched file's type. Size is -1 when the length is unknown.
func (a *RESTAdapter) buildRawFileBody(ctx context.Context, tool *dadl.ToolDef, params map[string]any) (body io.Reader, contentType string, size int64, err error) {
	name, def := singleFileURLParam(tool)
	val, ok := params[name]
	if !ok || val == nil {
		if def.Required {
			return nil, "", -1, fmt.Errorf("missing required file parameter %q", name)
		}
		return nil, "", -1, nil
	}
	rawURL, ok := val.(string)
	if !ok {
		return nil, "", -1, fmt.Errorf("file parameter %q: expected URL string, got %T", name, val)
	}

	fetched, err := a.fetchFileURL(ctx, name, rawURL)
	if err != nil {
		return nil, "", -1, err
	}

	contentType = tool.ContentType
	if contentType == "" {
		contentType = fetched.ContentType
	}
	return fetched.Body, contentType, fetched.Size, nil
}

// writeFileURLPart fetches a file_url parameter and writes it as a
// multipart/form-data file part (DADL spec §6.2.1, multipart mode — e.g.
// DeepL's POST /v2/document).
func (a *RESTAdapter) writeFileURLPart(ctx context.Context, writer *multipart.Writer, name, rawURL string) error {
	fetched, err := a.fetchFileURL(ctx, name, rawURL)
	if err != nil {
		return err
	}
	defer func() { _ = fetched.Body.Close() }()

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name=%q; filename=%q`, name, fetched.Filename))
	h.Set("Content-Type", fetched.ContentType)
	part, err := writer.CreatePart(h)
	if err != nil {
		return fmt.Errorf("create multipart part for %q: %w", name, err)
	}
	if _, err := io.Copy(part, fetched.Body); err != nil {
		return fmt.Errorf("copy file for parameter %q: %w", name, err)
	}
	return nil
}

// fetchFileURL resolves a caller-provided file URL into a byte stream.
// Supported schemes (DADL spec §6.2.1): http(s) for any web location including
// the ToolMesh file broker / blob store, and file for same-host paths inside
// the allowed upload directory.
func (a *RESTAdapter) fetchFileURL(ctx context.Context, paramName, rawURL string) (*fetchedFile, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: invalid URL %q: %w", paramName, rawURL, err)
	}
	switch u.Scheme {
	case urlSchemeHTTP, "https":
		return a.fetchHTTPFile(ctx, paramName, rawURL)
	case "file":
		return a.openLocalFileURL(paramName, u)
	default:
		return nil, fmt.Errorf("file parameter %q: unsupported URL scheme %q (use http, https, or file)", paramName, u.Scheme)
	}
}

// fetchHTTPFile downloads a file over HTTP(S) using the adapter's dedicated
// fetch client. Caller-provided URLs are a separate trust domain from the
// configured backend: the client never carries the backend's cookie jar,
// credentials, or relaxed TLS settings, its address-class policy is governed by
// AllowPrivateFileURL (default deny), and an optional per-backend host
// allowlist further restricts which destinations are reachable.
func (a *RESTAdapter) fetchHTTPFile(ctx context.Context, paramName, rawURL string) (*fetchedFile, error) {
	if err := a.checkFileURLHostAllowed(paramName, rawURL); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: create fetch request: %w", paramName, err)
	}

	resp, err := a.fileFetchClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: fetch %s: %w", paramName, rawURL, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not echo the upstream response body back to the caller — for a
		// caller-controlled URL that body would be an SSRF read channel. The
		// status code is enough to diagnose the failure.
		_ = resp.Body.Close()
		return nil, fmt.Errorf("file parameter %q: fetch %s returned HTTP %d", paramName, rawURL, resp.StatusCode)
	}
	if resp.ContentLength > maxFileFetchBytes {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("file parameter %q: file is %d bytes, exceeding the %d byte limit", paramName, resp.ContentLength, maxFileFetchBytes)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = contentTypeOctetStream
	}

	return &fetchedFile{
		Body:        &cappedReadCloser{src: resp.Body, remaining: maxFileFetchBytes, max: maxFileFetchBytes},
		ContentType: contentType,
		Filename:    fetchedFilename(resp, rawURL),
		Size:        resp.ContentLength,
	}, nil
}

// checkFileURLHostAllowed enforces the optional per-backend file_url host
// allowlist. When the allowlist is empty the call is permitted (only the
// transport-level address-class policy applies); otherwise the URL's hostname
// must appear in the allowlist (case-insensitive).
func (a *RESTAdapter) checkFileURLHostAllowed(paramName, rawURL string) error {
	if len(a.fileURLAllowedHosts) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("file parameter %q: invalid URL %q: %w", paramName, rawURL, err)
	}
	host := strings.ToLower(u.Hostname())
	if !a.fileURLAllowedHosts[host] {
		return fmt.Errorf("file parameter %q: host %q is not in the allowed file_url hosts for this backend", paramName, u.Hostname())
	}
	return nil
}

// openLocalFileURL opens a file:// URL. Like the legacy local "file" parameter
// type, the path must reside inside the allowed upload directory — file URLs
// must not turn into an arbitrary filesystem read primitive.
func (a *RESTAdapter) openLocalFileURL(paramName string, u *url.URL) (*fetchedFile, error) {
	if u.Host != "" && u.Host != hostnameLocalhost {
		return nil, fmt.Errorf("file parameter %q: remote file URL host %q not supported", paramName, u.Host)
	}

	p := u.Path
	// Windows drive-letter URLs arrive as /C:/dir/file — strip the leading slash.
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	p = filepath.FromSlash(p)

	cleanPath, err := a.validateUploadPath(paramName, p)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(cleanPath) //nolint:gosec // validated against allowedUploadDir above
	if err != nil {
		return nil, fmt.Errorf("file parameter %q: open %s: %w", paramName, cleanPath, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("file parameter %q: stat %s: %w", paramName, cleanPath, err)
	}
	if fi.Size() > maxFileFetchBytes {
		_ = f.Close()
		return nil, fmt.Errorf("file parameter %q: file is %d bytes, exceeding the %d byte limit", paramName, fi.Size(), maxFileFetchBytes)
	}

	contentType := mime.TypeByExtension(filepath.Ext(cleanPath))
	if contentType == "" {
		contentType = contentTypeOctetStream
	}

	return &fetchedFile{
		Body:        f,
		ContentType: contentType,
		Filename:    filepath.Base(cleanPath),
		Size:        fi.Size(),
	}, nil
}

// validateUploadPath resolves filePath and verifies it lies inside the
// adapter's allowed upload directory. Shared by the legacy local "file"
// parameter type and file:// URLs.
func (a *RESTAdapter) validateUploadPath(paramName, filePath string) (string, error) {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", fmt.Errorf("file parameter %q: resolve path: %w", paramName, err)
	}
	cleanPath := filepath.Clean(absPath)
	allowedAbs, _ := filepath.Abs(a.allowedUploadDir)
	allowedClean := filepath.Clean(allowedAbs)
	if !isPathWithin(cleanPath, allowedClean) {
		return "", fmt.Errorf("file parameter %q: path %q is outside allowed upload directory", paramName, cleanPath)
	}
	return cleanPath, nil
}

// isPathWithin reports whether p equals dir or lies beneath it.
func isPathWithin(p, dir string) bool {
	if p == dir {
		return true
	}
	prefix := dir + string(filepath.Separator)
	return len(p) > len(prefix) && p[:len(prefix)] == prefix
}

// fetchedFilename derives an upload filename from the fetch response's
// Content-Disposition header, then the URL path, then the content type.
func fetchedFilename(resp *http.Response, rawURL string) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		if _, params, err := mime.ParseMediaType(cd); err == nil {
			if fn, ok := params["filename"]; ok && fn != "" {
				return path.Base(fn)
			}
		}
	}
	if u, err := url.Parse(rawURL); err == nil {
		if base := path.Base(u.Path); base != "" && base != "/" && base != "." {
			return base
		}
	}
	return filenameFromHeaders(resp, resp.Header.Get("Content-Type"))
}

// cappedReadCloser limits reads to max bytes and fails with an error — not a
// silent EOF — once the cap is exceeded. io.LimitReader would truncate an
// oversized file and quietly upload corrupt bytes to the backend instead.
type cappedReadCloser struct {
	src       io.ReadCloser
	remaining int64
	max       int64
}

// Read passes reads through until the cap is consumed, then probes the source
// to distinguish "exactly at the limit" (EOF) from "over the limit" (error).
func (c *cappedReadCloser) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		var probe [1]byte
		n, err := c.src.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("file exceeds the %d byte limit", c.max)
		}
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.src.Read(p)
	c.remaining -= int64(n)
	return n, err
}

// Close closes the underlying source.
func (c *cappedReadCloser) Close() error {
	return c.src.Close()
}
