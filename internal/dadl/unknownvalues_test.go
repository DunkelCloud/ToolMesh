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

// TestParseBytes_UnknownValueRejects pins the spec §15.3 unknown-value
// policy for the behavior-determining enums this runtime implements:
// unimplemented values are rejected fail-closed instead of guessed.
func TestParseBytes_UnknownValueRejects(t *testing.T) {
	base := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  %s
  tools:
    t:
      method: GET
      path: /x
      %s
`
	build := func(backendExtra, toolExtra string) string {
		yaml := strings.Replace(base, "%s", backendExtra, 1)
		return strings.Replace(yaml, "%s", toolExtra, 1)
	}

	tests := []struct {
		name    string
		backend string
		tool    string
		wantErr string
	}{
		{
			name:    "pagination behavior auto accepted",
			backend: "defaults:\n    pagination:\n      strategy: page\n      behavior: auto",
		},
		{
			name:    "pagination behavior expose accepted",
			backend: "defaults:\n    pagination:\n      strategy: page\n      behavior: expose",
		},
		{
			name:    "pagination behavior manual rejected",
			backend: "defaults:\n    pagination:\n      strategy: page\n      behavior: manual",
			wantErr: "behavior must be auto or expose",
		},
		{
			name: "stream_handling collect accepted",
			tool: "response:\n        binary: true\n        streaming: true\n        stream_handling: collect",
		},
		{
			name:    "stream_handling chunked rejected",
			tool:    "response:\n        binary: true\n        streaming: true\n        stream_handling: chunked",
			wantErr: "stream_handling must be collect or skip",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(build(tt.backend, tt.tool)))
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestParseBytes_APIKeyAlias pins the spec §15.4 requirement: api_key is
// accepted and normalized to apikey.
func TestParseBytes_APIKeyAlias(t *testing.T) {
	yaml := `
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
  auth:
    type: api_key
    credential: my_key
    query_param: key
  tools:
    t:
      method: GET
      path: /x
`
	spec, err := ParseBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("api_key alias must be accepted: %v", err)
	}
	if spec.Backend.Auth.Type != authTypeAPIKey {
		t.Errorf("auth type = %q, want normalized %q", spec.Backend.Auth.Type, authTypeAPIKey)
	}
}
