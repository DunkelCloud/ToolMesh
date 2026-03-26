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
		Format:      "json",
		MessagePath: "$.message",
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
		{name: "500 default retryable", status: 500, body: `{"message": "server error"}`, wantErr: true, wantRetry: true},
		{name: "403 default terminal", status: 403, body: `{}`, wantErr: true, wantRetry: false},
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
