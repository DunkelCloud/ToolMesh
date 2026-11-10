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
	"log/slog"
	"net/http"
	"net/http/httptest"
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
