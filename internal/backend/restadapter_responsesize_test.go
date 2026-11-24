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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// Fixture literals of these tests, kept as constants for goconst.
const (
	testPaginationAuto = "auto"
	testTransformIDs   = "[.[] | .id]"
	testJSONNull       = "null"
)

// jsonArrayOfSize returns a valid JSON array of exactly n bytes (n >= 2).
func jsonArrayOfSize(n int) []byte {
	if n < 2 {
		panic("jsonArrayOfSize needs at least 2 bytes")
	}
	b := make([]byte, n)
	b[0] = '['
	for i := 1; i < n-1; i++ {
		b[i] = ' '
	}
	b[n-1] = ']'
	return b
}

// newSizeTestAdapter builds an adapter for one GET tool "t" against url,
// with the response size limit set from limit (empty = default).
func newSizeTestAdapter(t *testing.T, url, limit string, logger *slog.Logger) *RESTAdapter {
	t.Helper()
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: url,
			Tools: map[string]dadl.ToolDef{
				"t": {Method: testMethodGET, Path: "/"},
			},
		},
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, logger, testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	if limit != "" {
		if _, err := a.SetMaxResponseSize(limit); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

// TestRESTAdapter_ResponseOverLimitFails pins that a non-binary body over the
// limit fails the call with response_too_large, the status of the response,
// the limit and the real size, whether the size comes from Content-Length or
// has to be counted from a chunked body. Before, the body was cut at the
// limit and returned as a success.
func TestRESTAdapter_ResponseOverLimitFails(t *testing.T) {
	const size = 3000
	for _, chunked := range []bool{false, true} {
		t.Run("chunked="+strconv.FormatBool(chunked), func(t *testing.T) {
			body := jsonArrayOfSize(size)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set(testHeaderContentType, testContentTypeJSON)
				if chunked {
					_, _ = w.Write(body[:10])
					w.(http.Flusher).Flush() // forces chunked encoding: no Content-Length
					_, _ = w.Write(body[10:])
					return
				}
				w.Header().Set("Content-Length", strconv.Itoa(size))
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
			a := newSizeTestAdapter(t, srv.URL, "1KB", logger)
			result, err := a.Execute(context.Background(), "t", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("over-limit response returned as success: %.80s", resultText(t, result))
			}
			if code := result.Metadata[metadataKeyErrorCode]; code != dadl.ErrCodeResponseTooLarge {
				t.Errorf("error code = %v, want %s", code, dadl.ErrCodeResponseTooLarge)
			}
			if status := result.Metadata[metadataKeyStatusCode]; status != http.StatusOK {
				t.Errorf("status = %v, want 200", status)
			}
			text := resultText(t, result)
			for _, want := range []string{"3000 bytes", "1KB limit", `backend "api"`, "max_response_size"} {
				if !strings.Contains(text, want) {
					t.Errorf("message lacks %q: %s", want, text)
				}
			}
			if !strings.Contains(logBuf.String(), "response body exceeds the size limit") {
				t.Errorf("no warning logged; log:\n%s", logBuf.String())
			}
		})
	}
}

// TestRESTAdapter_ResponseAtLimitPasses pins the boundary: a body of exactly
// the limit is the API's whole answer and goes through unchanged.
func TestRESTAdapter_ResponseAtLimitPasses(t *testing.T) {
	body := jsonArrayOfSize(1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	a := newSizeTestAdapter(t, srv.URL, "1KB", nil)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("body at the limit failed: %s", resultText(t, result))
	}
	if got := resultText(t, result); len(got) != len(body) {
		t.Errorf("result has %d bytes, want %d", len(got), len(body))
	}
}

// TestRESTAdapter_DefaultResponseLimit pins the default of 10 MB without
// sending 10 MB: the adapter reports it, and the option replaces it.
func TestRESTAdapter_DefaultResponseLimit(t *testing.T) {
	a := newSizeTestAdapter(t, testBaseURLExample, "", nil)
	if got := a.responseLimit(); got != 10*1024*1024 {
		t.Errorf("default limit = %d, want 10 MB", got)
	}
}

// TestRESTAdapter_SetMaxResponseSize covers the option's values: a size is
// taken, one above the ceiling is clamped with a warning, and one that does
// not parse is an error that leaves the limit as it was.
func TestRESTAdapter_SetMaxResponseSize(t *testing.T) {
	tests := []struct {
		value     string
		want      int64
		wantErr   bool
		wantClamp bool
	}{
		{value: "50MB", want: 50 * 1024 * 1024},
		{value: "512 KiB", want: 512 * 1024},
		{value: "1GB", want: maxResponseBytesCeiling, wantClamp: true},
		{value: "lots", want: maxResponseBytes, wantErr: true},
		{value: "0", want: maxResponseBytes, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			var logBuf bytes.Buffer
			a := newSizeTestAdapter(t, testBaseURLExample, "", slog.New(slog.NewTextHandler(&logBuf, nil)))
			got, err := a.SetMaxResponseSize(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want || a.responseLimit() != tt.want {
				t.Errorf("limit = %d (in force %d), want %d", got, a.responseLimit(), tt.want)
			}
			if clamped := strings.Contains(logBuf.String(), "clamping"); clamped != tt.wantClamp {
				t.Errorf("clamp warning logged = %v, want %v; log:\n%s", clamped, tt.wantClamp, logBuf.String())
			}
		})
	}
}

// TestBodySize covers how the size of an over-limit body is told: from a
// Content-Length beyond what was read, by counting the rest, and as "not
// exact" once the body goes beyond the ceiling.
func TestBodySize(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		rest          int
		read, ceiling int64
		wantSize      int64
		wantExact     bool
	}{
		{name: "content length", contentLength: 5000, rest: 0, read: 101, ceiling: 1000, wantSize: 5000, wantExact: true},
		{name: "counted", contentLength: -1, rest: 400, read: 101, ceiling: 1000, wantSize: 501, wantExact: true},
		{name: "at ceiling", contentLength: -1, rest: 899, read: 101, ceiling: 1000, wantSize: 1000, wantExact: true},
		{name: "beyond ceiling", contentLength: -1, rest: 5000, read: 101, ceiling: 1000, wantSize: 1001, wantExact: false},
		{name: "read beyond ceiling", contentLength: -1, rest: 10, read: 1001, ceiling: 1000, wantSize: 1001, wantExact: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				ContentLength: tt.contentLength,
				Body:          io.NopCloser(bytes.NewReader(make([]byte, tt.rest))),
			}
			size, exact := bodySize(resp, tt.read, tt.ceiling)
			if size != tt.wantSize || exact != tt.wantExact {
				t.Errorf("bodySize = (%d, %v), want (%d, %v)", size, exact, tt.wantSize, tt.wantExact)
			}
		})
	}
}

// TestRESTAdapter_BinaryResponseTooLargeHasCode pins that the existing
// binary-size refusal carries the same semantic code, so a caller handles
// both alike.
func TestRESTAdapter_BinaryResponseTooLargeHasCode(t *testing.T) {
	a := newSizeTestAdapter(t, testBaseURLExample, "", nil)
	resp := &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Body: http.NoBody}
	err := a.responseTooLarge(context.Background(), &dadl.ToolDef{Method: testMethodGET, Path: "/"}, resp, maxStreamingBytes+1, maxStreamingBytes, true)
	if !isResponseTooLarge(err) {
		t.Fatalf("err = %v, want a response_too_large APIError", err)
	}
	if !strings.Contains(err.Error(), "response.streaming") {
		t.Errorf("binary message lost its remedy: %v", err)
	}
}

// TestRESTAdapter_ResponseTooLargeStopsRetries pins that a retried call whose
// next response is too large fails with response_too_large at once: the same
// request would bring the same body again.
func TestRESTAdapter_ResponseTooLargeStopsRetries(t *testing.T) {
	var calls atomic.Int32
	big := jsonArrayOfSize(3000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message": "temp down"}`))
			return
		}
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {
					Method: testMethodGET, Path: "/",
					Errors: &dadl.ErrorConfig{
						Format: testJSONFormat, MessagePath: testJSONPathMessage,
						RetryOn: []int{503},
						RetryStrategy: &dadl.RetryStrategyConfig{
							MaxRetries: 3, InitialDelay: testDelay1ms, Backoff: testBackoffFixed,
						},
					},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetMaxResponseSize("1KB"); err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.Metadata[metadataKeyErrorCode] != dadl.ErrCodeResponseTooLarge {
		t.Fatalf("result = %v, want a response_too_large error", result.Content)
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("backend saw %d requests, want 2 (no retry after the size error)", got)
	}
}

// TestRESTAdapter_PageTooLargeFailsPagination pins that a page over the limit
// fails the call instead of returning the pages before it as the result.
func TestRESTAdapter_PageTooLargeFailsPagination(t *testing.T) {
	big := []byte(`[{"id": 3, "pad": "` + strings.Repeat("x", 3000) + `"}]`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		switch r.URL.Query().Get(testParamPage) {
		case "", "1":
			_, _ = w.Write([]byte(`[{"id": 1}, {"id": 2}]`))
		case "2":
			_, _ = w.Write(big)
		default:
			_, _ = w.Write([]byte(`[]`))
		}
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Defaults: dadl.DefaultsConfig{
				Pagination: &dadl.PaginationConfig{
					Strategy: testParamPage,
					Request:  dadl.PaginationRequest{PageParam: testParamPage},
					Behavior: testPaginationAuto,
					MaxPages: 5,
				},
			},
			Tools: map[string]dadl.ToolDef{
				"list": {
					Method: testMethodGET, Path: "/",
					Params: map[string]dadl.ParamDef{
						testParamPage: {Type: schemaTypeInteger, In: paramInQuery},
					},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.New(slog.NewTextHandler(io.Discard, nil)), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.SetMaxResponseSize("1KB"); err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "list", map[string]any{testParamPage: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || result.Metadata[metadataKeyErrorCode] != dadl.ErrCodeResponseTooLarge {
		t.Fatalf("result = %s, want a response_too_large error", resultText(t, result))
	}
	if text := resultText(t, result); !strings.Contains(text, "pagination page 2") {
		t.Errorf("message does not name the page: %s", text)
	}
}

// newTransformTestAdapter builds an adapter for one tool "t" whose response
// is answered by body and shaped by rc.
func newTransformTestAdapter(t *testing.T, method string, status int, contentType, body string, rc *dadl.ResponseConfig, logger *slog.Logger) *RESTAdapter {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set(testHeaderContentType, contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {Method: method, Path: "/", Response: rc},
			},
		},
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, logger, testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestRESTAdapter_InvalidTransformFailsVisibly pins that a transform or
// result_path that cannot be parsed or compiled fails the call with
// invalid_transform — it used to fall back to the raw body without a sign —
// that the message says the request was carried out, and that the defect is
// reported when the DADL is loaded.
func TestRESTAdapter_InvalidTransformFailsVisibly(t *testing.T) {
	tests := []struct {
		name   string
		method string
		status int
		rc     *dadl.ResponseConfig
		field  string
	}{
		// "label" is a jq keyword; a helper function of that name does not parse.
		{name: "reserved word", method: testMethodGET, status: http.StatusOK,
			rc: &dadl.ResponseConfig{Transform: "def label: .name; [.[] | label]"}, field: "response.transform"},
		// Parses, but names a function jq does not have: caught by compiling.
		{name: "undefined function", method: testMethodPOST, status: http.StatusCreated,
			rc: &dadl.ResponseConfig{Transform: "[.[] | frobnicate]"}, field: "response.transform"},
		{name: "result_path", method: testMethodGET, status: http.StatusOK,
			rc: &dadl.ResponseConfig{ResultPath: "$.items[0"}, field: "response.result_path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
			a := newTransformTestAdapter(t, tt.method, tt.status, testContentTypeJSON, `[{"name": "a"}]`, tt.rc, logger)
			if !strings.Contains(logBuf.String(), "invalid response expression in DADL") {
				t.Errorf("defect not reported at load; log:\n%s", logBuf.String())
			}

			result, err := a.Execute(context.Background(), "t", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("call succeeded with %q, want an invalid_transform error", resultText(t, result))
			}
			if code := result.Metadata[metadataKeyErrorCode]; code != dadl.ErrCodeInvalidTransform {
				t.Errorf("error code = %v, want %s", code, dadl.ErrCodeInvalidTransform)
			}
			if status := result.Metadata[metadataKeyStatusCode]; status != tt.status {
				t.Errorf("status = %v, want %d", status, tt.status)
			}
			text := resultText(t, result)
			for _, want := range []string{tt.field, `tool "t"`, "request itself was carried out"} {
				if !strings.Contains(text, want) {
					t.Errorf("message lacks %q: %s", want, text)
				}
			}
		})
	}
}

// TestRESTAdapter_PipelineMismatchPassesThrough pins the failures that keep
// passing the body on: they depend on the response, and DADLs rely on them.
// A backend-wide result_path meets a single object without the list
// envelope, a JSON transform meets a text endpoint, and an empty body has
// nothing to shape.
func TestRESTAdapter_PipelineMismatchPassesThrough(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		rc          *dadl.ResponseConfig
		wantWarn    bool
	}{
		{name: "envelope absent", contentType: testContentTypeJSON, body: `{"id": 7, "name": "sw1"}`,
			rc: &dadl.ResponseConfig{ResultPath: "$.results"}, wantWarn: true},
		{name: "text endpoint", contentType: "text/plain", body: "Total: 12 lines",
			rc: &dadl.ResponseConfig{ResultPath: "$.result", Transform: "."}, wantWarn: true},
		{name: "null for an empty list", contentType: testContentTypeJSON, body: testJSONNull,
			rc: &dadl.ResponseConfig{Transform: testTransformIDs}, wantWarn: true},
		{name: "empty body", contentType: "", body: "",
			rc: &dadl.ResponseConfig{Transform: testTransformIDs}, wantWarn: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
			a := newTransformTestAdapter(t, testMethodGET, http.StatusOK, tt.contentType, tt.body, tt.rc, logger)
			result, err := a.Execute(context.Background(), "t", nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError {
				t.Fatalf("got error result: %s", resultText(t, result))
			}
			if got := resultText(t, result); got != tt.body {
				t.Errorf("result = %q, want the body unchanged %q", got, tt.body)
			}
			if warned := strings.Contains(logBuf.String(), "response transformation error"); warned != tt.wantWarn {
				t.Errorf("warning logged = %v, want %v; log:\n%s", warned, tt.wantWarn, logBuf.String())
			}
		})
	}
}

// TestRESTAdapter_NullHandledByTransform pins that a transform that handles
// null itself still gets to: only a failing pipeline passes the body on.
func TestRESTAdapter_NullHandledByTransform(t *testing.T) {
	a := newTransformTestAdapter(t, testMethodGET, http.StatusOK, testContentTypeJSON, testJSONNull,
		&dadl.ResponseConfig{Transform: "(. // []) | map(.id)"}, nil)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := resultText(t, result); got != "[]" {
		t.Errorf("result = %q, want []", got)
	}
}
