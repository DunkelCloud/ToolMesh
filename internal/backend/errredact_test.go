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
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_TransportErrorHidesQueryKey pins that a transport failure
// does not put a query-injected API key into the error text, on the direct
// path (error returned to the executor and audit) and on the retry path
// (tool result shown to the model).
func TestRESTAdapter_TransportErrorHidesQueryKey(t *testing.T) {
	// A port that refuses connections: listen, note the address, close.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	newAdapter := func(t *testing.T, errs *dadl.ErrorConfig) *RESTAdapter {
		t.Helper()
		spec := &dadl.Spec{
			Spec: testDADLSpecURL,
			Backend: dadl.BackendDef{
				Name:    testBackendNameAPI,
				Type:    transportTypeREST,
				BaseURL: "http://" + addr,
				Auth: dadl.AuthConfig{
					Type: redirectTestAuthType, Credential: redirectTestCredential,
					InjectInto: testParamQuery, QueryParam: "api_key",
				},
				Tools: map[string]dadl.ToolDef{
					redirectTestTool: {Method: testMethodGET, Path: redirectTestPath},
				},
			},
		}
		if errs != nil {
			spec.Backend.Defaults.Errors = errs
		}
		creds := &testCredStore{creds: map[string]string{redirectTestCredential: redirectTestSecret}}
		a, err := NewRESTAdapter(spec, creds, slog.Default(), testRESTOpts)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	t.Run("direct error", func(t *testing.T) {
		a := newAdapter(t, nil)
		result, err := a.Execute(context.Background(), redirectTestTool, nil)
		if err == nil {
			t.Fatalf("expected a transport error, got result %v", result)
		}
		if strings.Contains(err.Error(), redirectTestSecret) {
			t.Errorf("error text contains the query-injected key: %v", err)
		}
		if !strings.Contains(err.Error(), addr) {
			t.Errorf("error text should still name the backend host %s: %v", addr, err)
		}
	})

	t.Run("retry path result", func(t *testing.T) {
		// First request: a retryable 503. Every retry: the connection drops,
		// so the retry ends in a transport error that becomes the tool result.
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if hits.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Error("hijacking not supported")
				return
			}
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
		}))
		defer srv.Close()

		a := newAdapter(t, &dadl.ErrorConfig{
			RetryOn:       []int{http.StatusServiceUnavailable},
			RetryStrategy: &dadl.RetryStrategyConfig{MaxRetries: 1, Backoff: testBackoffFixed, InitialDelay: testDelay1ms},
		})
		a.spec.Backend.BaseURL = srv.URL
		result, err := a.Execute(context.Background(), redirectTestTool, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !result.IsError {
			t.Fatal("expected an error result after the failed retry")
		}
		if text := redactResultText(t, result); strings.Contains(text, redirectTestSecret) {
			t.Errorf("tool result contains the query-injected key: %s", text)
		}
	})
}

func TestRedactURLErrors(t *testing.T) {
	inner := &url.Error{Op: "Get", URL: "https://api.example.com/v1/x?api_key=SECRET", Err: context.DeadlineExceeded}
	wrapped := fmt.Errorf("backend execution failed: %w", fmt.Errorf("http request: %w", inner))
	got := RedactURLErrors(wrapped)
	if strings.Contains(got.Error(), "SECRET") || strings.Contains(got.Error(), "/v1/x") {
		t.Errorf("redacted text still has path or query: %v", got)
	}
	if !strings.Contains(got.Error(), "https://api.example.com") {
		t.Errorf("redacted text lost the origin: %v", got)
	}
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Error("redaction must keep the error chain")
	}
	plain := errors.New("no url here")
	if RedactURLErrors(plain) != plain { //nolint:errorlint // identity check: the same value must come back
		t.Error("errors without a url.Error must pass through unchanged")
	}

	joined := errors.Join(errors.New("first"), inner)
	if strings.Contains(RedactURLErrors(joined).Error(), "SECRET") {
		t.Error("joined errors must be redacted too")
	}
}

func TestRedactTransportError(t *testing.T) {
	inner := &url.Error{Op: "Post", URL: "https://u:p@api.example.com/x?key=SECRET", Err: context.DeadlineExceeded} //nolint:gosec // test fixture with fake userinfo
	got := redactTransportError(inner)
	if strings.Contains(got.Error(), "SECRET") || strings.Contains(got.Error(), "u:p") {
		t.Errorf("transport error leaks URL parts: %v", got)
	}
	if !errors.Is(got, context.DeadlineExceeded) {
		t.Error("transport error must unwrap to its cause")
	}
}
