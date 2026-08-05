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
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/google/uuid"
)

// idemTestServer records the idempotency header of every request and fails
// the first n requests with 503.
type idemTestServer struct {
	mu       sync.Mutex
	keys     []string
	failures int
}

func (s *idemTestServer) handler(headerName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.keys = append(s.keys, r.Header.Get(headerName))
		fail := s.failures > 0
		if fail {
			s.failures--
		}
		s.mu.Unlock()
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		if fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"message": "try later"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ok": true}`))
	}
}

func (s *idemTestServer) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...)
}

func idemSpec(baseURL string, tool dadl.ToolDef) *dadl.Spec {
	return &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: baseURL,
			Tools:   map[string]dadl.ToolDef{"t": tool},
		},
	}
}

var idemRetryErrors = &dadl.ErrorConfig{
	RetryOn: []int{503},
	RetryStrategy: &dadl.RetryStrategyConfig{
		MaxRetries:   3,
		Backoff:      testBackoffFixed,
		InitialDelay: testDelay1ms,
	},
}

func TestRESTAdapter_IdempotencyKeyStableAcrossRetries(t *testing.T) {
	srv := &idemTestServer{failures: 2}
	ts := httptest.NewServer(srv.handler(testIdemHeader))
	defer ts.Close()

	spec := idemSpec(ts.URL, dadl.ToolDef{
		Method: testMethodPOST, Path: "/charges",
		Idempotency: &dadl.IdempotencyConfig{Header: testIdemHeader},
		Errors:      idemRetryErrors,
	})
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.Execute(context.Background(), "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("expected success after retries, got: %v", result.Content)
	}

	keys := srv.recorded()
	if len(keys) != 3 {
		t.Fatalf("got %d requests, want 3 (initial + 2 retries)", len(keys))
	}
	if _, err := uuid.Parse(keys[0]); err != nil {
		t.Errorf("key %q is not a UUID: %v", keys[0], err)
	}
	if keys[0] != keys[1] || keys[1] != keys[2] {
		t.Errorf("all attempts of one logical call must replay the same key, got %v", keys)
	}

	// A second logical call gets a distinct key.
	if _, err := a.Execute(context.Background(), "t", nil); err != nil {
		t.Fatal(err)
	}
	keys = srv.recorded()
	if len(keys) != 4 || keys[3] == keys[0] {
		t.Errorf("distinct logical calls must get distinct keys, got %v", keys)
	}
}

func TestRESTAdapter_RetrySafety(t *testing.T) {
	tests := []struct {
		name         string
		tool         dadl.ToolDef
		wantRequests int
		wantError    bool
		wantNote     bool
	}{
		{
			name:         "bare POST fails on first retryable error",
			tool:         dadl.ToolDef{Method: testMethodPOST, Path: "/x", Errors: idemRetryErrors},
			wantRequests: 1,
			wantError:    true,
			wantNote:     true,
		},
		{
			name:         "retry_unsafe POST retries",
			tool:         dadl.ToolDef{Method: testMethodPOST, Path: "/x", RetryUnsafe: true, Errors: idemRetryErrors},
			wantRequests: 2,
		},
		{
			name:         "GET retries",
			tool:         dadl.ToolDef{Method: "GET", Path: "/x", Errors: idemRetryErrors},
			wantRequests: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := &idemTestServer{failures: 1}
			ts := httptest.NewServer(srv.handler(testIdemHeader))
			defer ts.Close()

			a, err := NewRESTAdapter(idemSpec(ts.URL, tt.tool), &testCredStore{}, slog.Default(), testRESTOpts)
			if err != nil {
				t.Fatal(err)
			}
			result, err := a.Execute(context.Background(), "t", nil)
			if err != nil {
				t.Fatal(err)
			}
			if result.IsError != tt.wantError {
				t.Errorf("IsError = %v, want %v (%v)", result.IsError, tt.wantError, result.Content)
			}
			if got := len(srv.recorded()); got != tt.wantRequests {
				t.Errorf("server saw %d requests, want %d", got, tt.wantRequests)
			}
			if tt.wantNote {
				text := redactResultText(t, result)
				if !strings.Contains(text, "retry suppressed") || !strings.Contains(text, "retry_unsafe") {
					t.Errorf("suppression note missing or unhelpful: %s", text)
				}
				if !strings.Contains(text, "[unavailable] HTTP 503") {
					t.Errorf("semantic code missing in suppressed error: %s", text)
				}
			}
		})
	}
}
