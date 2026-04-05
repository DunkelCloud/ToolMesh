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

package dadl

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTruncateMessage(t *testing.T) {
	if got := truncateMessage("short"); got != "short" {
		t.Errorf("short got %q", got)
	}
	long := strings.Repeat("x", maxErrorMessageLen+50)
	got := truncateMessage(long)
	if !strings.HasSuffix(got, "... (truncated)") {
		t.Errorf("expected truncation suffix, got tail %q", got[len(got)-20:])
	}
	if len(got) <= maxErrorMessageLen {
		t.Errorf("truncated length = %d, want > %d", len(got), maxErrorMessageLen)
	}
}

func TestExtractMessage_InvalidJSON(t *testing.T) {
	m := NewErrorMapper(ErrorConfig{Format: "json", MessagePath: "$.message"})
	msg := m.extractMessage([]byte("not json"))
	if msg != "not json" {
		t.Errorf("fallback msg = %q", msg)
	}
}

func TestExtractMessage_InvalidJSONPath(t *testing.T) {
	m := NewErrorMapper(ErrorConfig{Format: "json", MessagePath: "not a jsonpath"})
	msg := m.extractMessage([]byte(`{"x":1}`))
	// With invalid path, extractMessage returns a truncated version of the body.
	if msg == "" {
		t.Error("expected non-empty fallback")
	}
}

func TestRetryer_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewRetryer(RetryStrategyConfig{MaxRetries: 2, InitialDelay: "1ms", Backoff: "fixed"}, logger)

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := r.Do(context.Background(), func() (*http.Response, error) { //nolint:bodyclose // closed below
		calls++
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
		return http.DefaultClient.Do(req)
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil {
		_ = resp.Body.Close()
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestRetryer_RetriesThenFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewRetryer(RetryStrategyConfig{MaxRetries: 2, InitialDelay: "1ms", Backoff: "exponential"}, logger)

	calls := 0
	fn := func() (*http.Response, error) {
		calls++
		return nil, errors.New("boom")
	}
	_, err := r.Do(context.Background(), fn) //nolint:bodyclose // fn never returns a response
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 3 { // initial + 2 retries
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryer_ContextCancel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewRetryer(RetryStrategyConfig{MaxRetries: 5, InitialDelay: "100ms", Backoff: "linear"}, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before first retry

	_, err := r.Do(ctx, func() (*http.Response, error) { //nolint:bodyclose // fn never returns a response
		return nil, errors.New("boom")
	})
	if err == nil {
		t.Error("expected ctx.Err()")
	}
}

func TestRetryer_DefaultMaxRetries(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	r := NewRetryer(RetryStrategyConfig{InitialDelay: "1ms"}, logger)

	calls := 0
	_, err := r.Do(context.Background(), func() (*http.Response, error) { //nolint:bodyclose // fn never returns a response
		calls++
		return nil, errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// Default is 3 retries + initial = 4 calls.
	if calls != 4 {
		t.Errorf("calls = %d, want 4", calls)
	}
}

func TestCalcDelay(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))

	cases := []struct {
		strategy string
		attempt  int
		initial  time.Duration
		want     time.Duration
	}{
		{"fixed", 3, 10 * time.Millisecond, 10 * time.Millisecond},
		{"linear", 3, 10 * time.Millisecond, 30 * time.Millisecond},
		{"exponential", 2, 10 * time.Millisecond, 20 * time.Millisecond},
		{"unknown", 1, 10 * time.Millisecond, 10 * time.Millisecond},
	}
	for _, tc := range cases {
		r := NewRetryer(RetryStrategyConfig{Backoff: tc.strategy}, logger)
		got := r.calcDelay(tc.attempt, tc.initial)
		if got != tc.want {
			t.Errorf("%s attempt=%d: got %v, want %v", tc.strategy, tc.attempt, got, tc.want)
		}
	}
}

func TestParseDelayOrDefault(t *testing.T) {
	if d := parseDelayOrDefault("", time.Second); d != time.Second {
		t.Errorf("empty: got %v", d)
	}
	if d := parseDelayOrDefault("invalid", time.Second); d != time.Second {
		t.Errorf("invalid: got %v", d)
	}
	if d := parseDelayOrDefault("500ms", time.Second); d != 500*time.Millisecond {
		t.Errorf("parsed: got %v", d)
	}
}
