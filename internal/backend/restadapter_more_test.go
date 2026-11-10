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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

func TestRESTAdapter_RetryOnTransientError(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls < 3 {
			w.Header().Set(testHeaderContentType, testContentTypeJSON)
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message": "temp down"}`))
			return
		}
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"ok": true}`))
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
						Format:      testJSONFormat,
						MessagePath: testJSONPathMessage,
						RetryOn:     []int{503},
						RetryStrategy: &dadl.RetryStrategyConfig{
							MaxRetries:   3,
							InitialDelay: "1ms",
							Backoff:      "fixed",
						},
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("expected success after retry, got %v", result.Content)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 calls, got %d", calls)
	}
}

func TestRESTAdapter_RetryExhausted(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"message": "still down"}`))
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
						Format:      testJSONFormat,
						MessagePath: testJSONPathMessage,
						RetryOn:     []int{503},
						RetryStrategy: &dadl.RetryStrategyConfig{
							MaxRetries:   2,
							InitialDelay: "1ms",
							Backoff:      "fixed",
						},
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, _ := a.Execute(context.Background(), "t", nil)
	if !result.IsError {
		t.Error("expected error after retry exhaustion")
	}
}

// TestRESTAdapter_RetryOnlyListedStatuses checks DADL spec §8 end to end: a
// status the DADL lists in neither retry_on nor terminal is terminal, so a
// 5xx left out of retry_on reaches the backend exactly once, while a listed
// one is retried.
func TestRESTAdapter_RetryOnlyListedStatuses(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		retryOn     []int
		wantRetried bool
	}{
		{name: "503 left out of retry_on", status: http.StatusServiceUnavailable, retryOn: []int{429, 502, 504}, wantRetried: false},
		{name: "500 without retry_on", status: http.StatusInternalServerError, retryOn: nil, wantRetried: false},
		{name: "502 in retry_on", status: http.StatusBadGateway, retryOn: []int{429, 502, 504}, wantRetried: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.Header().Set(testHeaderContentType, testContentTypeJSON)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(`{"message": "down"}`))
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
								Format:      testJSONFormat,
								MessagePath: testJSONPathMessage,
								RetryOn:     tt.retryOn,
								RetryStrategy: &dadl.RetryStrategyConfig{
									MaxRetries:   2,
									InitialDelay: testDelay1ms,
									Backoff:      testBackoffFixed,
								},
							},
						},
					},
				},
			}
			a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := a.Execute(context.Background(), "t", nil)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("expected an error result, got %v", result.Content)
			}
			got := calls.Load()
			if tt.wantRetried && got < 2 {
				t.Errorf("backend saw %d request(s), want the status retried", got)
			}
			if !tt.wantRetried && got != 1 {
				t.Errorf("backend saw %d requests, want exactly 1 (no retry)", got)
			}
		})
	}
}

func TestRESTAdapter_JQTransform(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`{"items": [{"id": 1}, {"id": 2}]}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"t": {
					Method: testMethodGET, Path: "/",
					Response: &dadl.ResponseConfig{
						Transform: "[.items[].id]",
					},
				},
			},
		},
	}
	a, _ := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Errorf("got error: %v", result.Content)
	}
}

// TestRESTAdapter_TransformErrorWarnNamesBackendAndTool checks that a jq
// transform failing at runtime (here on an API that answers an empty list
// with null) is logged with the backend and tool it belongs to, and that the
// untransformed body is still returned when no redact list is declared.
func TestRESTAdapter_TransformErrorWarnNamesBackendAndTool(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		_, _ = w.Write([]byte(`null`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				testToolListItems: {
					Method: testMethodGET, Path: "/",
					Response: &dadl.ResponseConfig{
						Transform: "[.[] | .id]",
					},
				},
			},
		},
	}
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	a, err := NewRESTAdapter(spec, &testCredStore{}, logger, testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), testToolListItems, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("got error result: %v", result.Content)
	}

	found := false
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) != nil || rec["msg"] != "response transformation error" {
			continue
		}
		found = true
		if rec["backend"] != testBackendNameAPI || rec["tool"] != testToolListItems {
			t.Errorf("warning names backend %v and tool %v, want %q and %q",
				rec["backend"], rec["tool"], testBackendNameAPI, testToolListItems)
		}
	}
	if !found {
		t.Fatalf("no transform warning logged; log:\n%s", buf.String())
	}
}
