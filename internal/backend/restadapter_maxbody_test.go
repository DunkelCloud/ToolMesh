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
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// maxBodySpec builds a backend whose tools declare a deliberately small
// max_body_size, so the limit rather than the runtime ceiling is what the
// tests observe.
func maxBodySpec(baseURL, declared string) *dadl.Spec {
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Tools: map[string]dadl.ToolDef{
				// JSON body.
				"post_json": {
					Method:      testMethodPOST,
					Path:        testPathItems,
					MaxBodySize: declared,
					Params: map[string]dadl.ParamDef{
						testParamPayload: {Type: schemaTypeString, In: paramInBody},
					},
				},
				// Form-encoded body.
				"post_form": {
					Method:      testMethodPOST,
					Path:        testPathItems,
					ContentType: "application/x-www-form-urlencoded",
					MaxBodySize: declared,
					Params: map[string]dadl.ParamDef{
						testParamPayload: {Type: schemaTypeString, In: paramInBody},
					},
				},
				// Raw file body (Tika-style PUT).
				"put_file": {
					Method:      http.MethodPut,
					Path:        testPathItems,
					ContentType: contentTypeOctetStream,
					MaxBodySize: declared,
					Params: map[string]dadl.ParamDef{
						paramTypeFile: {Type: dadl.ParamTypeFileURL, In: paramInBody, Required: true},
					},
				},
				// Multipart upload with two file parts.
				"post_multipart": {
					Method:      testMethodPOST,
					Path:        testPathItems,
					ContentType: dadl.ContentTypeMultipartForm,
					MaxBodySize: declared,
					Params: map[string]dadl.ParamDef{
						"a": {Type: dadl.ParamTypeFileURL, In: paramInBody},
						"b": {Type: dadl.ParamTypeFileURL, In: paramInBody},
					},
				},
				// No declared limit — the runtime ceiling applies.
				"post_unlimited": {
					Method: testMethodPOST,
					Path:   testPathItems,
					Params: map[string]dadl.ParamDef{
						testParamPayload: {Type: schemaTypeString, In: paramInBody},
					},
				},
			},
		},
	}
}

func newMaxBodyAdapter(t *testing.T, baseURL, declared string) *RESTAdapter {
	t.Helper()
	adapter, err := NewRESTAdapter(maxBodySpec(baseURL, declared), &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	return adapter
}

// TestMaxBodySize_LoadTime covers what happens before any call is made: a
// value that cannot be read fails the load, and one larger than the runtime
// ceiling is clamped to it.
func TestMaxBodySize_LoadTime(t *testing.T) {
	t.Run("malformed value fails the load", func(t *testing.T) {
		_, err := NewRESTAdapter(maxBodySpec(testBaseURLExample, "50 bananas"), &testCredStore{}, slog.Default(), testRESTOpts)
		if err == nil {
			t.Fatal("err = nil, want the backend refused")
		}
		for _, want := range []string{"max_body_size", "unknown unit"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want substring %q", err, want)
			}
		}
	})

	t.Run("declared value is honored", func(t *testing.T) {
		adapter := newMaxBodyAdapter(t, testBaseURLExample, testSize1KB)
		tool := adapter.spec.Backend.Tools["post_json"]
		if got := adapter.effectiveMaxBodySize(&tool); got != 1024 {
			t.Errorf("effectiveMaxBodySize = %d, want 1024", got)
		}
	})

	t.Run("a value above the runtime ceiling is clamped", func(t *testing.T) {
		adapter := newMaxBodyAdapter(t, testBaseURLExample, "512MB")
		tool := adapter.spec.Backend.Tools["post_json"]
		if got := adapter.effectiveMaxBodySize(&tool); got != maxUploadBytes {
			t.Errorf("effectiveMaxBodySize = %d, want the ceiling %d", got, maxUploadBytes)
		}
	})

	t.Run("no declaration means the runtime ceiling", func(t *testing.T) {
		adapter := newMaxBodyAdapter(t, testBaseURLExample, testSize1KB)
		tool := adapter.spec.Backend.Tools["post_unlimited"]
		if got := adapter.effectiveMaxBodySize(&tool); got != maxUploadBytes {
			t.Errorf("effectiveMaxBodySize = %d, want the ceiling %d", got, maxUploadBytes)
		}
	})
}

// TestMaxBodySize_AssembledBody covers the buffered branches, where the exact
// byte count is known before the request goes out.
func TestMaxBodySize_AssembledBody(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	adapter := newMaxBodyAdapter(t, srv.URL, testSize1KB)

	for _, tool := range []string{"post_json", "post_form"} {
		t.Run(tool+" over the limit is rejected", func(t *testing.T) {
			called = false
			_, err := adapter.Execute(context.Background(), tool, map[string]any{
				testParamPayload: strings.Repeat("x", 2048),
			})
			if err == nil {
				t.Fatal("err = nil, want the oversized body rejected")
			}
			for _, want := range []string{testWantExceeding, testSize1KB, "max_body_size"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("err = %q, want substring %q", err, want)
				}
			}
			if called {
				t.Error("backend was called; the body should never have gone out")
			}
		})

		t.Run(tool+" under the limit is sent", func(t *testing.T) {
			called = false
			result, err := adapter.Execute(context.Background(), tool, map[string]any{testParamPayload: "small"})
			if err != nil {
				t.Fatalf("execute: %v", err)
			}
			if result.IsError {
				t.Fatalf("unexpected tool error: %v", result.Content)
			}
			if !called {
				t.Error("backend was not called")
			}
		})
	}
}

// TestMaxBodySize_FileURL covers the streaming branch. The limit has to hold
// both when the source declares its length and when it does not — an upstream
// that under-reports is exactly what the stream cap is there for.
func TestMaxBodySize_FileURL(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 4096)

	declaredLen := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		_, _ = w.Write(payload)
	}))
	defer declaredLen.Close()

	// No Content-Length: the response is chunked, so the size is only
	// discoverable while reading.
	chunked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		for range 4 {
			_, _ = w.Write(bytes.Repeat([]byte("x"), 1024))
			w.(http.Flusher).Flush()
		}
	}))
	defer chunked.Close()

	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
		_ = r.Body.Close()
	}))
	defer backendSrv.Close()

	adapter := newMaxBodyAdapter(t, backendSrv.URL, testSize1KB)

	t.Run("declared length over the limit is refused before the fetch completes", func(t *testing.T) {
		_, err := adapter.Execute(context.Background(), "put_file", map[string]any{
			paramTypeFile: declaredLen.URL + "/big.bin",
		})
		if err == nil {
			t.Fatal("err = nil, want the oversized file rejected")
		}
		for _, want := range []string{testWantExceeding, testSize1KB} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want substring %q", err, want)
			}
		}
	})

	t.Run("undeclared length is caught while streaming", func(t *testing.T) {
		_, err := adapter.Execute(context.Background(), "put_file", map[string]any{
			paramTypeFile: chunked.URL + "/big.bin",
		})
		if err == nil {
			t.Fatal("err = nil, want the stream cap to fire")
		}
		for _, want := range []string{"exceeds", testSize1KB} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("err = %q, want substring %q", err, want)
			}
		}
	})
}

// TestMaxBodySize_MultipartTotal pins the whole-body check: two parts each
// comfortably under the limit still exceed it together, and the assembled
// body is what actually goes on the wire.
func TestMaxBodySize_MultipartTotal(t *testing.T) {
	part := bytes.Repeat([]byte("x"), 700)
	fileSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(part)))
		_, _ = w.Write(part)
	}))
	defer fileSrv.Close()

	var called bool
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backendSrv.Close()

	adapter := newMaxBodyAdapter(t, backendSrv.URL, testSize1KB)

	_, err := adapter.Execute(context.Background(), "post_multipart", map[string]any{
		"a": fileSrv.URL + "/a.bin",
		"b": fileSrv.URL + "/b.bin",
	})
	if err == nil {
		t.Fatal("err = nil, want the combined body rejected")
	}
	if !strings.Contains(err.Error(), testWantExceeding) {
		t.Errorf("err = %q, want the limit reported", err)
	}
	if called {
		t.Error("backend was called; the body should never have gone out")
	}
}

// TestMaxBodySize_LocalFileParam covers the legacy `file` parameter, which
// buffers a local file into the multipart writer and — unlike every other
// upload path — carried no size check of its own before this.
func TestMaxBodySize_LocalFileParam(t *testing.T) {
	uploadDir := t.TempDir()
	bigPath := filepath.Join(uploadDir, "big.bin")
	if err := os.WriteFile(bigPath, bytes.Repeat([]byte("x"), 4096), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	var called bool
	backendSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer backendSrv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: backendSrv.URL,
			Tools: map[string]dadl.ToolDef{
				"upload": {
					Method:      testMethodPOST,
					Path:        testPathItems,
					ContentType: dadl.ContentTypeMultipartForm,
					MaxBodySize: testSize1KB,
					Params: map[string]dadl.ParamDef{
						paramTypeFile: {Type: paramTypeFile, In: paramInBody, Required: true},
					},
				},
			},
		},
	}
	adapter, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.allowedUploadDir = uploadDir

	_, err = adapter.Execute(context.Background(), "upload", map[string]any{paramTypeFile: bigPath})
	if err == nil {
		t.Fatal("err = nil, want the oversized local file rejected")
	}
	for _, want := range []string{testWantExceeding, testSize1KB} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, want substring %q", err, want)
		}
	}
	if called {
		t.Error("backend was called; the file should never have been uploaded")
	}
}
