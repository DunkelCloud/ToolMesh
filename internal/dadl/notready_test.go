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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
)

const (
	// notReadyList is the tool line most cases below declare.
	notReadyList = "not_ready_on: [202]"
	// wrongMethod is the parse error for a tool that is neither GET nor HEAD.
	wrongMethod = "only allowed on GET and HEAD"
)

// streamedBinaryResponse is a response block that pipes the body to the
// file broker, indented by the given prefix.
func streamedBinaryResponse(indent string) string {
	return "response:\n" +
		indent + "  binary: true\n" +
		indent + "  streaming: true\n" +
		indent + "  stream_handling: collect"
}

func TestParseBytes_NotReadyOnValidation(t *testing.T) {
	const base = `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  %s
  tools:
    get_stats:
      method: %s
      path: /stats
      %s
`
	build := func(backendExtra, method, toolExtra string) []byte {
		return []byte(fmt.Sprintf(base, backendExtra, method, toolExtra))
	}

	t.Run("loads on GET and HEAD without warnings", func(t *testing.T) {
		for _, method := range []string{httpMethodGET, httpMethodHEAD, "get"} {
			spec, err := ParseBytes(build("", method, "not_ready_on: [202, 206]"))
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", method, err)
			}
			if len(spec.Warnings) != 0 {
				t.Errorf("%s: not_ready_on is implemented and must not warn, got: %v", method, spec.Warnings)
			}
			got := spec.Backend.Tools["get_stats"].NotReadyOn
			if len(got) != 2 || got[0] != http.StatusAccepted || got[1] != http.StatusPartialContent {
				t.Errorf("%s: not_ready_on = %v, want [202 206]", method, got)
			}
		}
	})

	rejected := []struct {
		name         string
		backendExtra string
		method       string
		toolExtra    string
		wantErr      string
	}{
		{name: "POST", method: httpMethodPOST, toolExtra: notReadyList, wantErr: wrongMethod},
		{name: "PUT", method: httpMethodPUT, toolExtra: notReadyList, wantErr: wrongMethod},
		{name: "DELETE", method: httpMethodDELETE, toolExtra: notReadyList, wantErr: wrongMethod},
		{name: "status 200", method: httpMethodGET, toolExtra: "not_ready_on: [200]", wantErr: "must be a 2xx status other than 200"},
		{name: "status 404", method: httpMethodGET, toolExtra: "not_ready_on: [202, 404]", wantErr: "status 404 must be a 2xx status"},
		{name: "status 302", method: httpMethodGET, toolExtra: "not_ready_on: [302]", wantErr: "status 302 must be a 2xx status"},
		{
			name: "streamed binary response on the tool", method: httpMethodGET,
			toolExtra: notReadyList + "\n      " + streamedBinaryResponse("      "),
			wantErr:   "cannot be combined with a streamed binary response",
		},
		{
			name: "streamed binary response from defaults", method: httpMethodGET,
			backendExtra: "defaults:\n    " + streamedBinaryResponse("    "),
			toolExtra:    notReadyList,
			wantErr:      "cannot be combined with a streamed binary response",
		},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			_, err := ParseBytes(build(tt.backendExtra, tt.method, tt.toolExtra))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}

	t.Run("a buffered binary response is fine", func(t *testing.T) {
		tool := notReadyList + "\n      response:\n        binary: true"
		if _, err := ParseBytes(build("", httpMethodGET, tool)); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// The list belongs to one tool. Under defaults it would reach every
	// tool of the backend, writes included, so the key does not exist there
	// and is reported like any other key the runtime does not know.
	t.Run("is not a defaults key", func(t *testing.T) {
		spec, err := ParseBytes(build("defaults:\n    "+notReadyList, httpMethodGET, ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := spec.Backend.Tools["get_stats"].NotReadyOn; len(got) != 0 {
			t.Errorf("a defaults-level list reached the tool: %v", got)
		}
		if len(spec.Warnings) != 1 || !IsUnknownKeyWarning(spec.Warnings[0]) ||
			!strings.Contains(spec.Warnings[0], `"not_ready_on" in defaults`) {
			t.Errorf("want one unknown-key warning for defaults, got: %v", spec.Warnings)
		}
	})
}

func TestToolDef_NotReadyError(t *testing.T) {
	tool := ToolDef{Method: httpMethodGET, NotReadyOn: []int{http.StatusAccepted}}

	apiErr := tool.NotReadyError(http.StatusAccepted)
	if apiErr == nil {
		t.Fatal("a listed status must yield an error")
	}
	if apiErr.Code != ErrCodeNotReady || apiErr.HTTPStatus != http.StatusAccepted {
		t.Errorf("got code %q status %d, want %q 202", apiErr.Code, apiErr.HTTPStatus, ErrCodeNotReady)
	}
	if !strings.HasPrefix(apiErr.Error(), "[not_ready] HTTP 202: ") {
		t.Errorf("text form = %q", apiErr.Error())
	}

	for _, status := range []int{http.StatusOK, http.StatusNoContent, http.StatusServiceUnavailable} {
		if got := tool.NotReadyError(status); got != nil {
			t.Errorf("status %d is not listed, got %v", status, got)
		}
	}
	plain := ToolDef{Method: httpMethodGET}
	if got := plain.NotReadyError(http.StatusAccepted); got != nil {
		t.Errorf("a tool without not_ready_on must never report not ready, got %v", got)
	}
}

// TestRetryer_Retry pins what separates Retry from Do: the caller has made
// the first attempt, so Retry waits before its own first one and makes
// max_retries attempts, not max_retries plus one.
func TestRetryer_Retry(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
	errFirst := errors.New("first attempt failed")
	errLater := errors.New("still failing")

	t.Run("waits before each of max_retries attempts", func(t *testing.T) {
		r := NewRetryer(RetryStrategyConfig{MaxRetries: 2, InitialDelay: "20ms", Backoff: backoffFixed}, logger)
		calls := 0
		start := time.Now()
		_, err := r.Retry(context.Background(), errFirst, func() (*http.Response, error) { //nolint:bodyclose // fn never returns a response
			calls++
			return nil, errLater
		})
		elapsed := time.Since(start)
		if calls != 2 {
			t.Errorf("calls = %d, want 2", calls)
		}
		if !errors.Is(err, errLater) {
			t.Errorf("error = %v, want it to wrap the last failure", err)
		}
		// Two waits of 20ms; the lower bound leaves room for a coarse clock.
		if elapsed < 30*time.Millisecond {
			t.Errorf("returned after %v, want a wait before every attempt", elapsed)
		}
	})

	t.Run("stops at the first success", func(t *testing.T) {
		r := NewRetryer(RetryStrategyConfig{MaxRetries: 5, InitialDelay: testRetryDelay1ms, Backoff: backoffFixed}, logger)
		calls := 0
		resp, err := r.Retry(context.Background(), errFirst, func() (*http.Response, error) {
			calls++
			if calls < 2 {
				return nil, errLater
			}
			return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if calls != 2 {
			t.Errorf("calls = %d, want 2", calls)
		}
	})

	t.Run("a canceled context ends the wait", func(t *testing.T) {
		r := NewRetryer(RetryStrategyConfig{MaxRetries: 3, InitialDelay: "10s", Backoff: backoffFixed}, logger)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := r.Retry(ctx, errFirst, func() (*http.Response, error) { //nolint:bodyclose // fn must not run
			t.Error("fn ran although the context was canceled")
			return nil, errLater
		})
		if !errors.Is(err, context.Canceled) {
			t.Errorf("error = %v, want context.Canceled", err)
		}
	})
}
