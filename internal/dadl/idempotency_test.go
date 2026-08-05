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

	"github.com/google/uuid"
)

func TestNewIdempotencyKey(t *testing.T) {
	cfg := &IdempotencyConfig{Header: testIdemHeader}
	k1, err := NewIdempotencyKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := uuid.Parse(k1); err != nil {
		t.Errorf("key %q is not a UUID: %v", k1, err)
	}
	k2, err := NewIdempotencyKey(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k1 == k2 {
		t.Error("two calls must produce distinct keys")
	}
	if _, err := NewIdempotencyKey(&IdempotencyConfig{Header: "X", Generate: "sequential"}); err == nil {
		t.Error("unknown generator must error")
	}
}

func TestCanAutoRetry(t *testing.T) {
	idem := &IdempotencyConfig{Header: testIdemHeader}
	tests := []struct {
		name string
		tool ToolDef
		want bool
	}{
		{name: "GET is safe", tool: ToolDef{Method: "GET"}, want: true},
		{name: "HEAD is safe", tool: ToolDef{Method: httpMethodHEAD}, want: true},
		{name: "PUT is safe", tool: ToolDef{Method: httpMethodPUT}, want: true},
		{name: "DELETE is safe", tool: ToolDef{Method: httpMethodDELETE}, want: true},
		{name: "lowercase get is safe", tool: ToolDef{Method: "get"}, want: true},
		{name: "bare POST is unsafe", tool: ToolDef{Method: "POST"}, want: false},
		{name: "bare PATCH is unsafe", tool: ToolDef{Method: httpMethodPATCH}, want: false},
		{name: "POST with idempotency is safe", tool: ToolDef{Method: httpMethodPOST, Idempotency: idem}, want: true},
		{name: "PATCH with retry_unsafe opts in", tool: ToolDef{Method: httpMethodPATCH, RetryUnsafe: true}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanAutoRetry(&tt.tool); got != tt.want {
				t.Errorf("CanAutoRetry(%s) = %v, want %v", tt.tool.Method, got, tt.want)
			}
		})
	}
}

func TestParseBytes_IdempotencyValidation(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  %s
  tools:
    create_charge:
      method: POST
      path: /charges
      %s
`
	build := func(backendExtra, toolExtra string) string {
		yaml := strings.Replace(base, "%s", backendExtra, 1)
		return strings.Replace(yaml, "%s", toolExtra, 1)
	}

	t.Run("valid block loads without warnings", func(t *testing.T) {
		yaml := build("", "retry_unsafe: false\n      idempotency:\n        header: Idempotency-Key\n        generate: uuid_v4")
		spec, err := ParseBytes([]byte(yaml))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(spec.Warnings) != 0 {
			t.Errorf("idempotency/retry_unsafe are implemented and must not warn, got: %v", spec.Warnings)
		}
		idem := spec.Backend.Tools["create_charge"].Idempotency
		if idem == nil || idem.Header != testIdemHeader {
			t.Errorf("idempotency not parsed, got %+v", idem)
		}
	})
	t.Run("header required", func(t *testing.T) {
		yaml := build("", "idempotency:\n        generate: uuid_v4")
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "idempotency.header is required") {
			t.Fatalf("error = %v, want header-required rejection", err)
		}
	})
	t.Run("unknown generator rejected fail-closed", func(t *testing.T) {
		yaml := build("", "idempotency:\n        header: Idempotency-Key\n        generate: sequential")
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "not implemented") {
			t.Fatalf("error = %v, want generator rejection", err)
		}
	})
	t.Run("collision with header param is case-insensitive", func(t *testing.T) {
		yaml := build("", "idempotency:\n        header: Idempotency-Key\n      params:\n        IDEMPOTENCY-KEY: { type: string, in: header }")
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "collides with header param") {
			t.Fatalf("error = %v, want param collision rejection", err)
		}
	})
	t.Run("collision with defaults.headers rejected", func(t *testing.T) {
		yaml := build("defaults:\n    headers:\n      idempotency-key: fixed", "idempotency:\n        header: Idempotency-Key")
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "collides with defaults.headers") {
			t.Fatalf("error = %v, want defaults.headers collision rejection", err)
		}
	})
	t.Run("retry_on and terminal must be disjoint", func(t *testing.T) {
		yaml := build("", "errors:\n        retry_on: [503]\n        terminal: [503]")
		_, err := ParseBytes([]byte(yaml))
		if err == nil || !strings.Contains(err.Error(), "both retry_on and terminal") {
			t.Fatalf("error = %v, want disjointness rejection", err)
		}
	})
}
