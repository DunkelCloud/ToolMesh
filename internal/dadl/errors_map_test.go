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
	"errors"
	"strings"
	"testing"
)

func TestDefaultSemanticCode(t *testing.T) {
	// One literal per code pins the wire value; repeats use the constants.
	tests := []struct {
		status int
		want   string
	}{
		{400, "invalid_input"},
		{422, ErrCodeInvalidInput},
		{401, "unauthorized"},
		{403, "forbidden"},
		{404, "not_found"},
		{410, ErrCodeNotFound},
		{409, "conflict"},
		{408, "timeout"},
		{429, "rate_limited"},
		{500, "internal"},
		{502, "unavailable"},
		{503, ErrCodeUnavailable},
		{504, ErrCodeUnavailable},
		{418, "client_error"},
		{599, "server_error"},
		{303, "unexpected_status"},
	}
	for _, tt := range tests {
		if got := DefaultSemanticCode(tt.status); got != tt.want {
			t.Errorf("DefaultSemanticCode(%d) = %q, want %q", tt.status, got, tt.want)
		}
	}
}

func TestCheckResponse_SemanticCodes(t *testing.T) {
	config := ErrorConfig{
		Format:      testJSONFormat,
		MessagePath: "$.error.message",
		CodePath:    "$.error.code",
		Map:         map[int]string{400: ErrCodeNotFound},
	}
	mapper := NewErrorMapper(config)
	body := []byte(`{"error": {"message": "no such customer", "code": "resource_missing"}}`)

	t.Run("map overrides default", func(t *testing.T) {
		err, retryable := mapper.CheckResponse(400, body)
		if retryable {
			t.Error("400 must be terminal by default")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("CheckResponse must return *APIError, got %T", err)
		}
		if apiErr.Code != ErrCodeNotFound || apiErr.HTTPStatus != 400 {
			t.Errorf("got code=%q status=%d, want not_found/400", apiErr.Code, apiErr.HTTPStatus)
		}
		if apiErr.ProviderCode != "resource_missing" {
			t.Errorf("provider_code = %q, want resource_missing", apiErr.ProviderCode)
		}
		if apiErr.Message != "no such customer" {
			t.Errorf("message = %q", apiErr.Message)
		}
		text := apiErr.Error()
		if !strings.Contains(text, "[not_found] HTTP 400: no such customer") ||
			!strings.Contains(text, "(provider_code=resource_missing)") {
			t.Errorf("stable text form wrong: %s", text)
		}
	})

	t.Run("unmapped status falls back to default table", func(t *testing.T) {
		err, _ := mapper.CheckResponse(429, body)
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *APIError, got %T", err)
		}
		if apiErr.Code != ErrCodeRateLimited {
			t.Errorf("code = %q, want ErrCodeRateLimited", apiErr.Code)
		}
	})

	t.Run("absent code_path leaves provider code empty", func(t *testing.T) {
		plain := NewErrorMapper(ErrorConfig{MessagePath: testJSONPathMessage})
		err, _ := plain.CheckResponse(404, []byte(`{"message": "gone"}`))
		var apiErr *APIError
		if !errors.As(err, &apiErr) {
			t.Fatalf("want *APIError, got %T", err)
		}
		if apiErr.ProviderCode != "" {
			t.Errorf("provider_code = %q, want empty", apiErr.ProviderCode)
		}
		if got := apiErr.Error(); strings.Contains(got, "provider_code") {
			t.Errorf("text form must omit empty provider_code: %s", got)
		}
	})

	t.Run("retry classification unchanged", func(t *testing.T) {
		m := NewErrorMapper(ErrorConfig{RetryOn: []int{429}, Terminal: []int{503}})
		if _, retryable := m.CheckResponse(429, nil); !retryable {
			t.Error("retry_on status must be retryable")
		}
		if _, retryable := m.CheckResponse(503, nil); retryable {
			t.Error("terminal status must not be retryable")
		}
		if _, retryable := m.CheckResponse(500, nil); !retryable {
			t.Error("5xx default must be retryable")
		}
		if _, retryable := m.CheckResponse(404, nil); retryable {
			t.Error("4xx default must be terminal")
		}
	})
}

func TestParseBytes_ErrorsMapValidation(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  tools:
    t:
      method: GET
      path: /x
      errors:
        %s
`
	t.Run("valid map with integer keys parses", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "map:\n          400: not_found\n          429: rate_limited", 1)
		spec, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 0 {
			t.Errorf("errors.map is implemented and must not warn, got: %v", spec.Warnings)
		}
		m := spec.Backend.Tools["t"].Errors.Map
		if m[400] != "not_found" || m[429] != "rate_limited" {
			t.Errorf("map not parsed, got %v", m)
		}
	})
	t.Run("non-error status key rejected", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "map:\n          200: ok", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "only 4xx/5xx") {
			t.Fatalf("error = %v, want 4xx/5xx rejection", err)
		}
	})
	t.Run("empty code rejected", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "map:\n          404: \"\"", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "empty code") {
			t.Fatalf("error = %v, want empty-code rejection", err)
		}
	})
	t.Run("invalid message_path rejected at load", func(t *testing.T) {
		yaml := strings.Replace(base, "%s", "message_path: \"$..message\"", 1)
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "message_path") {
			t.Fatalf("error = %v, want message_path rejection", err)
		}
	})
	t.Run("invalid code_path in defaults rejected", func(t *testing.T) {
		yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  defaults:
    errors:
      code_path: "$[1:3]"
  tools:
    t:
      method: GET
      path: /x
`
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "defaults.errors.code_path") {
			t.Fatalf("error = %v, want defaults.errors.code_path rejection", err)
		}
	})
}
