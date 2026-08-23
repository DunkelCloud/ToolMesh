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
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Fixture literals for file_url tests.
const (
	testContentTypePDF  = "application/pdf"
	testContentTypeZip  = "application/zip"
	testPathTika        = "/tika"
	testPathUnpack      = "/unpack"
	testToolExtractText = "extract_text"
	testToolUnpack      = "unpack_embedded"
	testTextPlain       = "text/plain"
	testTikaToken       = "tika_token"
)

// TestFileURL_SSRFPolicy verifies the caller-controlled file_url fetch policy:
// private/loopback targets are blocked unless AllowPrivateFileURL is set, and
// the optional FileURLAllowedHosts allowlist restricts which hosts are reachable.
func TestFileURL_SSRFPolicy(t *testing.T) {
	pdf := []byte("%PDF-1.4 minimal")
	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypePDF)
		_, _ = w.Write(pdf)
	}))
	defer fileSrv.Close()
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte("parsed"))
	}))
	defer backendSrv.Close()

	fileURL := fileSrv.URL + "/doc.pdf"
	fileHost := mustHostname(t, fileSrv.URL)

	newAdapter := func(t *testing.T, opts RESTAdapterOptions) *RESTAdapter {
		t.Helper()
		a, err := NewRESTAdapter(tikaLikeSpec(backendSrv.URL),
			&testCredStore{creds: map[string]string{testTikaToken: testTokenValue}}, slog.Default(), opts)
		if err != nil {
			t.Fatalf("create adapter: %v", err)
		}
		return a
	}

	t.Run("private file fetch blocked by default", func(t *testing.T) {
		a := newAdapter(t, RESTAdapterOptions{AllowPrivateURL: true}) // AllowPrivateFileURL defaults false
		if _, err := a.Execute(context.Background(), testToolExtractText, map[string]any{paramTypeFile: fileURL}); err == nil {
			t.Fatal("expected loopback file_url fetch to be blocked, got nil error")
		}
	})

	t.Run("allowlist rejects non-listed host", func(t *testing.T) {
		a := newAdapter(t, RESTAdapterOptions{
			AllowPrivateURL:     true,
			AllowPrivateFileURL: true,
			FileURLAllowedHosts: []string{"allowed.example"},
		})
		_, err := a.Execute(context.Background(), testToolExtractText, map[string]any{paramTypeFile: fileURL})
		if err == nil || !strings.Contains(err.Error(), "allowed file_url hosts") {
			t.Fatalf("expected allowlist rejection, got %v", err)
		}
	})

	t.Run("allowlist permits listed host", func(t *testing.T) {
		a := newAdapter(t, RESTAdapterOptions{
			AllowPrivateURL:     true,
			AllowPrivateFileURL: true,
			FileURLAllowedHosts: []string{fileHost},
		})
		if _, err := a.Execute(context.Background(), testToolExtractText, map[string]any{paramTypeFile: fileURL}); err != nil {
			t.Fatalf("expected allowed host fetch to succeed, got %v", err)
		}
	})
}

func mustHostname(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u.Hostname()
}

// tikaLikeSpec builds a spec with a single raw-body file_url upload tool,
// shaped like the Tika DADL's extract_text (PUT /tika, octet-stream).
func tikaLikeSpec(baseURL string) *dadl.Spec {
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "tika",
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Auth:    dadl.AuthConfig{Type: testTokenBearer, Credential: testTikaToken},
			Tools: map[string]dadl.ToolDef{
				testToolExtractText: {
					Method:      http.MethodPut,
					Path:        testPathTika,
					ContentType: contentTypeOctetStream,
					Params: map[string]dadl.ParamDef{
						paramTypeFile:    {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
						testHeaderAccept: {Type: schemaTypeString, In: paramInHeader, Default: testTextPlain},
					},
				},
			},
		},
	}
}

func newFileURLAdapter(t *testing.T, spec *dadl.Spec) *RESTAdapter {
	t.Helper()
	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{testTikaToken: testTokenValue}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	return adapter
}

// TestFileURLInput_RawBody covers DADL spec §6.2.1 raw-body mode: the fetched
// bytes become the request body, the tool's content_type is sent on the wire,
// and the backend's credentials are NOT leaked to the file source.
func TestFileURLInput_RawBody(t *testing.T) {
	fileData := []byte("%PDF-1.7 fake pdf payload for the raw upload test")

	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get(testHeaderAuth); got != "" {
			t.Errorf("file fetch leaked backend Authorization header: %q", got)
		}
		w.Header().Set(testHeaderContentType, testContentTypePDF)
		_, _ = w.Write(fileData)
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("backend method = %q, want PUT", r.Method)
		}
		if r.URL.Path != testPathTika {
			t.Errorf("backend path = %q, want %s", r.URL.Path, testPathTika)
		}
		if got := r.Header.Get(testHeaderContentType); got != contentTypeOctetStream {
			t.Errorf("backend Content-Type = %q, want %s", got, contentTypeOctetStream)
		}
		if got := r.Header.Get(testHeaderAccept); got != testTextPlain {
			t.Errorf("backend Accept = %q, want %s (header param default)", got, testTextPlain)
		}
		if got := r.Header.Get(testHeaderAuth); got != "Bearer "+testTokenValue {
			t.Errorf("backend Authorization = %q, want bearer token", got)
		}
		if r.ContentLength != int64(len(fileData)) {
			t.Errorf("backend ContentLength = %d, want %d", r.ContentLength, len(fileData))
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, fileData) {
			t.Errorf("backend received %d bytes, want the %d raw file bytes", len(body), len(fileData))
		}
		w.Header().Set(testHeaderContentType, testTextPlain)
		_, _ = w.Write([]byte("Extracted text content."))
	}))
	defer backendSrv.Close()

	adapter := newFileURLAdapter(t, tikaLikeSpec(backendSrv.URL))

	result, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{
		paramTypeFile: fileSrv.URL + "/docs/report.pdf",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if got := extractText(t, result); got != "Extracted text content." {
		t.Errorf("result = %q, want extracted text", got)
	}
}

// TestFileURLInput_RawBody_UnknownLength covers sources that stream without a
// Content-Length (chunked) — the body must still arrive intact.
func TestFileURLInput_RawBody_UnknownLength(t *testing.T) {
	fileData := bytes.Repeat([]byte("chunked-data-"), 1000)

	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, contentTypeOctetStream)
		flusher := w.(http.Flusher)
		_, _ = w.Write(fileData[:100])
		flusher.Flush() // force chunked transfer: no Content-Length on the fetch
		_, _ = w.Write(fileData[100:])
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, fileData) {
			t.Errorf("backend received %d bytes, want %d", len(body), len(fileData))
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendSrv.Close()

	adapter := newFileURLAdapter(t, tikaLikeSpec(backendSrv.URL))

	result, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{
		paramTypeFile: fileSrv.URL + "/big.bin",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
}

// TestFileURLInput_Multipart covers DADL spec §6.2.1 multipart mode (DeepL
// document upload shape): file_url params become file parts with filename and
// content type from the fetch, scalar body params become form fields, and
// omitted optional file params are skipped.
func TestFileURLInput_Multipart(t *testing.T) {
	docData := []byte("fake document bytes for multipart upload")

	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypePDF)
		_, _ = w.Write(docData)
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(32 << 20); err != nil { //nolint:gosec // test
			t.Errorf("parse multipart: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
		file, header, err := r.FormFile(paramTypeFile)
		if err != nil {
			t.Errorf("missing file part: %v", err)
			http.Error(w, err.Error(), 400)
			return
		}
		defer func() { _ = file.Close() }()
		data, _ := io.ReadAll(file)
		if !bytes.Equal(data, docData) {
			t.Errorf("file part has %d bytes, want %d", len(data), len(docData))
		}
		if header.Filename != "report.pdf" {
			t.Errorf("file part filename = %q, want report.pdf (URL basename)", header.Filename)
		}
		if got := header.Header.Get(testHeaderContentType); got != testContentTypePDF {
			t.Errorf("file part Content-Type = %q, want %s", got, testContentTypePDF)
		}
		if got := r.FormValue("target_lang"); got != "DE" {
			t.Errorf("target_lang field = %q, want DE", got)
		}
		if _, ok := r.MultipartForm.File["glossary"]; ok {
			t.Error("omitted optional file_url param produced a part")
		}
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"document_id":"doc-1"}`))
	}))
	defer backendSrv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    "deepl",
			Type:    transportTypeREST,
			BaseURL: backendSrv.URL,
			Tools: map[string]dadl.ToolDef{
				"upload_document": {
					Method:      testMethodPOST,
					Path:        "/v2/document",
					ContentType: dadl.ContentTypeMultipartForm,
					Params: map[string]dadl.ParamDef{
						paramTypeFile: {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
						"glossary":    {Type: dadl.ParamTypeFileURL, In: paramInBody},
						"target_lang": {Type: schemaTypeString, In: paramInBody, Required: true},
					},
				},
			},
		},
	}
	adapter := newFileURLAdapter(t, spec)

	result, err := adapter.Execute(context.Background(), "upload_document", map[string]any{
		paramTypeFile: fileSrv.URL + "/docs/report.pdf",
		"target_lang": "DE",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}
	if got := extractText(t, result); !strings.Contains(got, "doc-1") {
		t.Errorf("result = %q, want document_id passthrough", got)
	}
}

// localFileURL converts an absolute path into a file:// URL that works on
// both Windows (drive letters) and Unix.
func localFileURL(absPath string) string {
	u := &url.URL{Scheme: "file", Path: "/" + strings.TrimPrefix(filepath.ToSlash(absPath), "/")}
	return u.String()
}

// TestFileURLInput_LocalFile covers file:// URLs: allowed inside the upload
// directory, rejected outside it.
func TestFileURLInput_LocalFile(t *testing.T) {
	content := []byte("local file content")
	uploadDir := t.TempDir()
	localPath := filepath.Join(uploadDir, "doc.txt")
	if err := os.WriteFile(localPath, content, 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, content) {
			t.Errorf("backend received %q, want local file content", body)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer backendSrv.Close()

	adapter := newFileURLAdapter(t, tikaLikeSpec(backendSrv.URL))
	adapter.allowedUploadDir = uploadDir

	result, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{
		paramTypeFile: localFileURL(localPath),
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	t.Run("outside allowed dir", func(t *testing.T) {
		outsidePath := filepath.Join(t.TempDir(), "secret.txt")
		if err := os.WriteFile(outsidePath, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write fixture: %v", err)
		}
		_, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{
			paramTypeFile: localFileURL(outsidePath),
		})
		if err == nil || !strings.Contains(err.Error(), "outside allowed upload directory") {
			t.Errorf("err = %v, want outside-allowed-upload-directory error", err)
		}
	})
}

// TestFileURLInput_Errors covers fetch failure modes.
func TestFileURLInput_Errors(t *testing.T) {
	notFoundSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such file", http.StatusNotFound)
	}))
	defer notFoundSrv.Close()

	tooLargeSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", int64(maxFileFetchBytes)+1))
		w.WriteHeader(http.StatusOK)
	}))
	defer tooLargeSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("backend must not be called when the file fetch fails")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backendSrv.Close()

	adapter := newFileURLAdapter(t, tikaLikeSpec(backendSrv.URL))

	tests := []struct {
		name    string
		params  map[string]any
		wantErr string
	}{
		{
			name:    "unsupported scheme",
			params:  map[string]any{paramTypeFile: "ftp://example.com/x.pdf"},
			wantErr: "unsupported URL scheme",
		},
		{
			name:    "fetch 404",
			params:  map[string]any{paramTypeFile: notFoundSrv.URL + "/gone.pdf"},
			wantErr: "HTTP 404",
		},
		{
			name:    "non-string value",
			params:  map[string]any{paramTypeFile: 12345},
			wantErr: "expected URL string",
		},
		{
			name:    "content-length over limit",
			params:  map[string]any{paramTypeFile: tooLargeSrv.URL + "/huge.bin"},
			wantErr: "exceeding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := adapter.Execute(context.Background(), testToolExtractText, tt.params)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want substring %q", err, tt.wantErr)
			}
		})
	}

	// An omitted required file_url param is rejected by parameter validation
	// before the fetch pipeline is reached, so it surfaces as an invalid_input
	// tool result rather than the transport error the cases above produce.
	t.Run("missing required file param", func(t *testing.T) {
		result, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{})
		if err != nil {
			t.Fatalf("execute: %v", err)
		}
		if !result.IsError {
			t.Fatalf("result.IsError = false, want a rejected call")
		}
		if got := resultText(t, result); !strings.Contains(got, `missing required parameter "file"`) {
			t.Errorf("content = %q, want the missing-required-parameter complaint", got)
		}
	})
}

// TestCappedReadCloser verifies the over-limit error and the exact-limit EOF.
func TestCappedReadCloser(t *testing.T) {
	t.Run("over the limit errors", func(t *testing.T) {
		c := &cappedReadCloser{src: io.NopCloser(strings.NewReader("hello world")), remaining: 5, max: 5}
		_, err := io.ReadAll(c)
		if err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Errorf("err = %v, want exceeds-limit error", err)
		}
	})

	t.Run("exactly at the limit reads cleanly", func(t *testing.T) {
		c := &cappedReadCloser{src: io.NopCloser(strings.NewReader(testHelloLiteral)), remaining: 5, max: 5}
		data, err := io.ReadAll(c)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(data) != testHelloLiteral {
			t.Errorf("read %q, want %q", data, testHelloLiteral)
		}
		if err := c.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
}

// TestFileURLResponse_BlobStore is the Tika unpack_embedded round trip:
// file_url input fetched and streamed up, binary ZIP response stored in the
// blob store with the tool's TTL, download URL returned, blob retrievable.
func TestFileURLResponse_BlobStore(t *testing.T) {
	docData := []byte("container document with attachments")
	zipData := append([]byte("PK\x03\x04"), bytes.Repeat([]byte("zip-entry-bytes"), 200)...)

	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, contentTypeOctetStream)
		_, _ = w.Write(docData)
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, docData) {
			t.Errorf("backend received %d bytes, want the %d source bytes", len(body), len(docData))
		}
		w.Header().Set(testHeaderContentType, testContentTypeZip)
		_, _ = w.Write(zipData)
	}))
	defer backendSrv.Close()

	spec := tikaLikeSpec(backendSrv.URL)
	spec.Backend.Tools[testToolUnpack] = dadl.ToolDef{
		Method:      http.MethodPut,
		Path:        testPathUnpack,
		ContentType: contentTypeOctetStream,
		Params: map[string]dadl.ParamDef{
			paramTypeFile: {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
		},
		Response: &dadl.ResponseConfig{Type: dadl.ResponseTypeFileURL, TTL: "30m"},
	}

	adapter := newFileURLAdapter(t, spec)
	bs := testBlobStore(t)
	adapter.SetBlobStore(bs)

	before := time.Now()
	result, err := adapter.Execute(context.Background(), testToolUnpack, map[string]any{
		paramTypeFile: fileSrv.URL + "/mail.eml",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(extractText(t, result)), &parsed); err != nil {
		t.Fatalf("parse result JSON: %v", err)
	}

	blobURL, _ := parsed[fileKeyURL].(string)
	if !strings.HasPrefix(blobURL, "http://localhost:8080/blobs/") {
		t.Fatalf("url = %q, want blob store download URL", blobURL)
	}
	if parsed[fileKeyContentType] != testContentTypeZip {
		t.Errorf("content_type = %v, want %s", parsed[fileKeyContentType], testContentTypeZip)
	}
	if size, _ := parsed[fileKeySizeBytes].(float64); int(size) != len(zipData) {
		t.Errorf("size_bytes = %v, want %d", parsed[fileKeySizeBytes], len(zipData))
	}

	// The per-tool 30m TTL must override the adapter default (1h).
	expires, err := time.Parse(time.RFC3339, parsed[fileKeyExpires].(string))
	if err != nil {
		t.Fatalf("parse expires %v: %v", parsed[fileKeyExpires], err)
	}
	ttl := expires.Sub(before)
	if ttl < 25*time.Minute || ttl > 35*time.Minute {
		t.Errorf("expires implies TTL %v, want ~30m from response.ttl", ttl)
	}

	// The download URL must serve the original bytes.
	blobID := strings.TrimPrefix(blobURL, "http://localhost:8080/blobs/")
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/blobs/"+blobID, nil)
	bs.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("blob download HTTP %d, want 200", rec.Code)
	}
	if !bytes.Equal(rec.Body.Bytes(), zipData) {
		t.Errorf("blob download has %d bytes, want %d", rec.Body.Len(), len(zipData))
	}
}

// TestFileURLResponse_EmptyBody: an empty backend body (e.g. Tika /unpack on
// a document with no embedded files) must not store a zero-byte blob.
func TestFileURLResponse_EmptyBody(t *testing.T) {
	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plain document"))
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backendSrv.Close()

	spec := tikaLikeSpec(backendSrv.URL)
	spec.Backend.Tools[testToolUnpack] = dadl.ToolDef{
		Method:      http.MethodPut,
		Path:        testPathUnpack,
		ContentType: contentTypeOctetStream,
		Params: map[string]dadl.ParamDef{
			paramTypeFile: {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
		},
		Response: &dadl.ResponseConfig{Type: dadl.ResponseTypeFileURL, TTL: "1h"},
	}

	adapter := newFileURLAdapter(t, spec)
	adapter.SetBlobStore(testBlobStore(t))

	result, err := adapter.Execute(context.Background(), testToolUnpack, map[string]any{
		paramTypeFile: fileSrv.URL + "/empty.txt",
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %v", result.Content)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(extractText(t, result)), &parsed); err != nil {
		t.Fatalf("parse result JSON: %v", err)
	}
	if parsed[fileKeyURL] != nil {
		t.Errorf("url = %v, want null for empty body", parsed[fileKeyURL])
	}
	if note, _ := parsed["note"].(string); !strings.Contains(note, "empty body") {
		t.Errorf("note = %q, want empty-body explanation", note)
	}
}

// TestFileURL_EndToEnd_ParsedDADL drives the full path from DADL YAML through
// the parser into the adapter, mirroring the registry tika.dadl: a raw-body
// file_url upload tool and a file_url-response unpack tool.
func TestFileURL_EndToEnd_ParsedDADL(t *testing.T) {
	docData := []byte("end to end document bytes")
	zipData := []byte("PK\x03\x04 end to end zip")

	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(docData)
	}))
	defer fileSrv.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !bytes.Equal(body, docData) {
			t.Errorf("backend received %d bytes, want %d", len(body), len(docData))
		}
		switch r.URL.Path {
		case testPathTika:
			w.Header().Set(testHeaderContentType, testTextPlain)
			_, _ = w.Write([]byte("parsed text"))
		case testPathUnpack:
			w.Header().Set(testHeaderContentType, testContentTypeZip)
			_, _ = w.Write(zipData)
		default:
			http.Error(w, "unexpected path "+r.URL.Path, 404)
		}
	}))
	defer backendSrv.Close()

	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: tika
  type: rest
  base_url: ` + backendSrv.URL + `
  tools:
    extract_text:
      method: PUT
      path: /tika
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
        Accept: { type: string, in: header, default: "text/plain" }
    unpack_embedded:
      method: PUT
      path: /unpack
      content_type: application/octet-stream
      params:
        file: { type: file_url, in: body, required: true }
      response:
        type: file_url
        ttl: 1h
`
	spec, err := dadl.ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("parse DADL: %v", err)
	}

	adapter, err := NewRESTAdapter(spec, &testCredStore{creds: map[string]string{}}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.SetBlobStore(testBlobStore(t))

	// The MCP input schema must expose file_url params as strings.
	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	for _, tool := range tools {
		if tool.Name != testToolExtractText {
			continue
		}
		props := tool.InputSchema[schemaKeyProperties].(map[string]any)
		fileProp := props[paramTypeFile].(map[string]any)
		if fileProp[schemaKeyType] != schemaTypeString {
			t.Errorf("file param schema type = %v, want string", fileProp[schemaKeyType])
		}
	}

	fileURL := fileSrv.URL + "/doc.pdf"

	result, err := adapter.Execute(context.Background(), testToolExtractText, map[string]any{paramTypeFile: fileURL})
	if err != nil {
		t.Fatalf("execute extract_text: %v", err)
	}
	if got := extractText(t, result); got != "parsed text" {
		t.Errorf("extract_text result = %q, want parsed text", got)
	}

	result, err = adapter.Execute(context.Background(), testToolUnpack, map[string]any{paramTypeFile: fileURL})
	if err != nil {
		t.Fatalf("execute unpack_embedded: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(extractText(t, result)), &parsed); err != nil {
		t.Fatalf("parse unpack result JSON: %v", err)
	}
	if blobURL, _ := parsed[fileKeyURL].(string); !strings.Contains(blobURL, "/blobs/") {
		t.Errorf("unpack url = %v, want blob download URL", parsed[fileKeyURL])
	}
	if parsed[fileKeyContentType] != testContentTypeZip {
		t.Errorf("unpack content_type = %v, want %s", parsed[fileKeyContentType], testContentTypeZip)
	}
}
