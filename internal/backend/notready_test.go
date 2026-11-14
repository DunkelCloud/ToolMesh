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
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// testToolStats is the fixture tool of the not-ready tests.
const testToolStats = "stats"

// sequenceServer answers one request after the other with the given
// statuses and stays on the last one. A 200 carries a result, a 202 the
// empty object an API sends while it prepares one, anything else an error
// message that names its status.
func sequenceServer(t *testing.T, statuses ...int) (baseURL string, requests *atomic.Int32) {
	t.Helper()
	requests = &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(requests.Add(1))
		status := statuses[min(n, len(statuses))-1]
		w.Header().Set(testHeaderContentType, testContentTypeJSON)
		w.WriteHeader(status)
		switch status {
		case http.StatusOK:
			_, _ = w.Write([]byte(`{"total": 7}`))
		case http.StatusAccepted:
			_, _ = w.Write([]byte(`{}`))
		default:
			_, _ = w.Write([]byte(`{"message": "failed with ` + http.StatusText(status) + `"}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL, requests
}

// statsAdapter builds an adapter with the one GET tool the not-ready tests
// call. notReadyOn and errs are the tool's not_ready_on and errors block.
func statsAdapter(t *testing.T, baseURL string, notReadyOn []int, errs *dadl.ErrorConfig) *RESTAdapter {
	t.Helper()
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name: testBackendNameAPI, Type: transportTypeREST, BaseURL: baseURL,
			Tools: map[string]dadl.ToolDef{
				testToolStats: {Method: testMethodGET, Path: "/", NotReadyOn: notReadyOn, Errors: errs},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fastRetries is an errors block that retries 503 and waits a millisecond
// between attempts.
func fastRetries(maxRetries int) *dadl.ErrorConfig {
	return &dadl.ErrorConfig{
		Format:      testJSONFormat,
		MessagePath: testJSONPathMessage,
		RetryOn:     []int{http.StatusServiceUnavailable},
		RetryStrategy: &dadl.RetryStrategyConfig{
			MaxRetries:   maxRetries,
			InitialDelay: testDelay1ms,
			Backoff:      testBackoffFixed,
		},
	}
}

func TestRESTAdapter_NotReadyOn(t *testing.T) {
	accepted := []int{http.StatusAccepted}

	tests := []struct {
		name         string
		statuses     []int
		notReadyOn   []int
		maxRetries   int
		wantRequests int32
		wantErrCode  string // "" = the call succeeds
		wantStatus   int
		wantText     string
	}{
		{
			name:     "asks again until the result is ready",
			statuses: []int{http.StatusAccepted, http.StatusAccepted, http.StatusOK}, notReadyOn: accepted, maxRetries: 3,
			wantRequests: 3, wantText: `"total"`,
		},
		{
			name:     "fails with not_ready once the retries are used up",
			statuses: accepted, notReadyOn: accepted, maxRetries: 2,
			wantRequests: 3, wantErrCode: dadl.ErrCodeNotReady, wantStatus: http.StatusAccepted, wantText: "max retries (2) exceeded",
		},
		{
			name:     "a 202 the tool does not list stays a result",
			statuses: accepted, maxRetries: 2,
			wantRequests: 1, wantText: "{}",
		},
		{
			name:     "shares max_retries with retry_on",
			statuses: []int{http.StatusServiceUnavailable, http.StatusAccepted, http.StatusOK}, notReadyOn: accepted, maxRetries: 2,
			wantRequests: 3, wantText: `"total"`,
		},
		{
			name:     "an error after a not-ready response ends the call with that error",
			statuses: []int{http.StatusAccepted, http.StatusNotFound}, notReadyOn: accepted, maxRetries: 3,
			wantRequests: 2, wantErrCode: dadl.ErrCodeNotFound, wantStatus: http.StatusNotFound, wantText: "failed with Not Found",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, requests := sequenceServer(t, tt.statuses...)
			a := statsAdapter(t, baseURL, tt.notReadyOn, fastRetries(tt.maxRetries))

			result, err := a.Execute(context.Background(), testToolStats, nil)
			if err != nil {
				t.Fatal(err)
			}
			text := resultText(t, result)
			if got := requests.Load(); got != tt.wantRequests {
				t.Errorf("backend saw %d request(s), want %d", got, tt.wantRequests)
			}
			if !strings.Contains(text, tt.wantText) {
				t.Errorf("result text = %q, want it to contain %q", text, tt.wantText)
			}
			if tt.wantErrCode == "" {
				if result.IsError {
					t.Errorf("expected a result, got the error %q", text)
				}
				return
			}
			if !result.IsError {
				t.Fatalf("expected an error result, got %q", text)
			}
			if got := result.Metadata[metadataKeyErrorCode]; got != tt.wantErrCode {
				t.Errorf("error code = %v, want %q", got, tt.wantErrCode)
			}
			if got := result.Metadata[metadataKeyStatusCode]; got != tt.wantStatus {
				t.Errorf("status = %v, want %d", got, tt.wantStatus)
			}
		})
	}
}

// TestRESTAdapter_RetryCountAndWait pins the shape of a retried call for
// both triggers: max_retries requests follow the first one, and each of
// them waits, the first included.
func TestRESTAdapter_RetryCountAndWait(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		notReadyOn []int
	}{
		{name: "retry_on", status: http.StatusServiceUnavailable},
		{name: "not_ready_on", status: http.StatusAccepted, notReadyOn: []int{http.StatusAccepted}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseURL, requests := sequenceServer(t, tt.status)
			errs := fastRetries(2)
			errs.RetryStrategy.InitialDelay = "20ms"
			a := statsAdapter(t, baseURL, tt.notReadyOn, errs)

			start := time.Now()
			result, err := a.Execute(context.Background(), testToolStats, nil)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("expected an error result, got %q", resultText(t, result))
			}
			if got := requests.Load(); got != 3 {
				t.Errorf("backend saw %d request(s), want the first one and 2 retries", got)
			}
			// Two waits of 20ms; the lower bound leaves room for a coarse clock.
			if elapsed < 30*time.Millisecond {
				t.Errorf("call returned after %v, want a wait before every retry", elapsed)
			}
		})
	}
}

// TestRESTAdapter_TerminalErrorAfterRetry checks that a call which ends on a
// terminal error after a retried one reports that last response, message
// included.
func TestRESTAdapter_TerminalErrorAfterRetry(t *testing.T) {
	baseURL, requests := sequenceServer(t, http.StatusServiceUnavailable, http.StatusNotFound)
	a := statsAdapter(t, baseURL, nil, fastRetries(3))

	result, err := a.Execute(context.Background(), testToolStats, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := resultText(t, result)
	if !result.IsError {
		t.Fatalf("expected an error result, got %q", text)
	}
	if got := requests.Load(); got != 2 {
		t.Errorf("backend saw %d request(s), want 2", got)
	}
	if got := result.Metadata[metadataKeyStatusCode]; got != http.StatusNotFound {
		t.Errorf("status = %v, want 404", got)
	}
	if !strings.Contains(text, http.StatusText(http.StatusNotFound)) || strings.Contains(text, http.StatusText(http.StatusServiceUnavailable)) {
		t.Errorf("result text = %q, want the message of the 404 response", text)
	}
}

func TestRetryStrategyFor(t *testing.T) {
	declared := &dadl.RetryStrategyConfig{MaxRetries: 5, InitialDelay: "2s", Backoff: testBackoffFixed}

	tests := []struct {
		name      string
		errConfig *dadl.ErrorConfig
		notReady  bool
		wantRetry bool
		wantMax   int
	}{
		{name: "declared strategy, retry_on status", errConfig: &dadl.ErrorConfig{RetryStrategy: declared}, wantRetry: true, wantMax: 5},
		{name: "declared strategy, not-ready status", errConfig: &dadl.ErrorConfig{RetryStrategy: declared}, notReady: true, wantRetry: true, wantMax: 5},
		{name: "no strategy, retry_on status", errConfig: &dadl.ErrorConfig{}, wantRetry: false},
		{name: "no strategy, not-ready status", errConfig: &dadl.ErrorConfig{}, notReady: true, wantRetry: true},
		{name: "no errors block, not-ready status", notReady: true, wantRetry: true},
		{name: "no errors block, other status", wantRetry: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strategy, ok := retryStrategyFor(tt.errConfig, tt.notReady)
			if ok != tt.wantRetry {
				t.Errorf("retry = %v, want %v", ok, tt.wantRetry)
			}
			if strategy.MaxRetries != tt.wantMax {
				t.Errorf("max_retries = %d, want %d (0 leaves the default to the retryer)", strategy.MaxRetries, tt.wantMax)
			}
		})
	}
}
