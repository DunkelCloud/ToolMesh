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
	"strings"
	"testing"
)

func TestErrorMapper_CheckResponse(t *testing.T) {
	m := NewErrorMapper(ErrorConfig{
		Format:      testJSONFormat,
		MessagePath: testJSONPathMessage,
		RetryOn:     []int{429, 502, 503},
		Terminal:    []int{400, 404},
	})

	tests := []struct {
		name        string
		status      int
		body        string
		wantErr     bool
		wantRetry   bool
		wantContain string
	}{
		{name: "200 OK", status: 200, wantErr: false},
		{name: "201 Created", status: 201, wantErr: false},
		{name: "429 retryable", status: 429, body: `{"message": "rate limited"}`, wantErr: true, wantRetry: true, wantContain: "rate limited"},
		{name: "503 retryable", status: 503, body: `{"message": "unavailable"}`, wantErr: true, wantRetry: true, wantContain: "unavailable"},
		{name: "400 terminal", status: 400, body: `{"message": "bad request"}`, wantErr: true, wantRetry: false, wantContain: "bad request"},
		{name: "404 terminal", status: 404, body: `{"message": "not found"}`, wantErr: true, wantRetry: false, wantContain: "not found"},
		{name: "500 in neither list terminal", status: 500, body: `{"message": "server error"}`, wantErr: true, wantRetry: false, wantContain: "server error"},
		{name: "403 in neither list terminal", status: 403, body: `{}`, wantErr: true, wantRetry: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, retryable := m.CheckResponse(tt.status, []byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if retryable != tt.wantRetry {
					t.Errorf("retryable = %v, want %v", retryable, tt.wantRetry)
				}
				if tt.wantContain != "" && !strings.Contains(err.Error(), tt.wantContain) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantContain)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// TestErrorMapper_CheckResponse_OnlyRetryOnRetries pins DADL spec §8: only a
// status listed in retry_on is retryable. A status listed in neither retry_on
// nor terminal is terminal, whatever its class — leaving a 5xx out of
// retry_on must stop it from being retried, and a 3xx that surfaces enters
// error mapping like any other status.
func TestErrorMapper_CheckResponse_OnlyRetryOnRetries(t *testing.T) {
	gatewayOnly := ErrorConfig{
		RetryOn:  []int{429, 502, 504},
		Terminal: []int{400, 401, 403, 404, 409},
	}
	noRetryOn := ErrorConfig{
		Terminal: []int{400, 404},
	}
	empty := ErrorConfig{}
	terminal5xx := ErrorConfig{
		RetryOn:  []int{429},
		Terminal: []int{500, 503},
	}

	tests := []struct {
		name      string
		config    ErrorConfig
		status    int
		wantRetry bool
	}{
		// 5xx: only what retry_on lists.
		{name: "503 left out of retry_on", config: gatewayOnly, status: 503, wantRetry: false},
		{name: "500 left out of retry_on", config: gatewayOnly, status: 500, wantRetry: false},
		{name: "502 in retry_on", config: gatewayOnly, status: 502, wantRetry: true},
		{name: "504 in retry_on", config: gatewayOnly, status: 504, wantRetry: true},
		{name: "500 without retry_on", config: noRetryOn, status: 500, wantRetry: false},
		{name: "503 without retry_on", config: noRetryOn, status: 503, wantRetry: false},
		{name: "500 with empty errors block", config: empty, status: 500, wantRetry: false},
		{name: "599 with empty errors block", config: empty, status: 599, wantRetry: false},

		// 3xx that surfaces from the transport.
		{name: "301 surfaces", config: gatewayOnly, status: 301, wantRetry: false},
		{name: "302 surfaces", config: gatewayOnly, status: 302, wantRetry: false},
		{name: "307 surfaces", config: empty, status: 307, wantRetry: false},

		// 4xx: unchanged.
		{name: "429 in retry_on", config: gatewayOnly, status: 429, wantRetry: true},
		{name: "429 without retry_on", config: noRetryOn, status: 429, wantRetry: false},
		{name: "404 in terminal", config: gatewayOnly, status: 404, wantRetry: false},
		{name: "422 in neither list", config: gatewayOnly, status: 422, wantRetry: false},
		{name: "408 with empty errors block", config: empty, status: 408, wantRetry: false},

		// terminal list: unchanged.
		{name: "500 in terminal", config: terminal5xx, status: 500, wantRetry: false},
		{name: "503 in terminal", config: terminal5xx, status: 503, wantRetry: false},
		{name: "429 in retry_on next to terminal 5xx", config: terminal5xx, status: 429, wantRetry: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err, retryable := NewErrorMapper(tt.config).CheckResponse(tt.status, nil)
			if err == nil {
				t.Fatalf("HTTP %d: expected an error, got nil", tt.status)
			}
			if retryable != tt.wantRetry {
				t.Errorf("HTTP %d: retryable = %v, want %v", tt.status, retryable, tt.wantRetry)
			}
		})
	}
}

func TestErrorMapper_NoMessagePath(t *testing.T) {
	m := NewErrorMapper(ErrorConfig{})
	err, _ := m.CheckResponse(500, []byte("raw error"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "(no message)") {
		t.Errorf("expected fallback message, got %q", err.Error())
	}
}
