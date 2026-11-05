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

package credentials

import (
	"reflect"
	"strings"
	"testing"
)

// testVaultKV2 is the shape of `vault kv get -format=json` (and `bao kv get
// -format=json`) for a KV version 2 secret.
const testVaultKV2 = `{
  "request_id": "3b0c9a41-1f2e-4d7a-9c55-0e6c2c3f8a10",
  "lease_id": "",
  "lease_duration": 0,
  "renewable": false,
  "data": {
    "data": {
      "CREDENTIAL_GITHUB_TOKEN": "ghp-from-vault",
      "CREDENTIAL_DEEPL_AUTH_KEY": "deepl-from-vault",
      "TOOLMESH_API_KEY": "tm-from-vault"
    },
    "metadata": {
      "created_time": "2026-11-05T10:00:00.000000Z",
      "custom_metadata": null,
      "deletion_time": "",
      "destroyed": false,
      "version": 3
    }
  },
  "warnings": null,
  "mount_type": "kv"
}`

// Fixtures shared by the JSON tests.
const (
	testPathKV2 = "data.data"
	testDataKey = "data"
	testGHKey   = "CREDENTIAL_GITHUB_TOKEN" //nolint:gosec // key name, not a credential
	testVaultGH = "ghp-from-vault"          //nolint:gosec // test fixture, not a credential
	testVaultTM = "tm-from-vault"           //nolint:gosec // test fixture, not a credential
	testOther   = "OTHER"
)

func TestParseJSONOutput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		path  []string
		want  map[string]string
	}{
		{
			name:  "Vault or OpenBao KV v2 with path data.data",
			input: testVaultKV2,
			path:  []string{testDataKey, testDataKey},
			want: map[string]string{ //nolint:gosec // test fixtures, not credentials
				testGHKey:                   testVaultGH,
				"CREDENTIAL_DEEPL_AUTH_KEY": "deepl-from-vault",
				"TOOLMESH_API_KEY":          testVaultTM,
			},
		},
		{
			name:  "flat object at the top level",
			input: `{"CREDENTIAL_A": "alpha", "OTHER": "x"}`,
			want:  map[string]string{testCredA: testAlpha, testOther: "x"},
		},
		{
			name:  "nested objects are flattened to their member names",
			input: `{"github": {"CREDENTIAL_GITHUB_TOKEN": "t1"}, "deepl": {"keys": {"CREDENTIAL_DEEPL_AUTH_KEY": "t2"}}}`,
			want:  map[string]string{testGHKey: "t1", "CREDENTIAL_DEEPL_AUTH_KEY": "t2"},
		},
		{
			name:  "numbers keep their written form, booleans become true or false",
			input: `{"PIN": 12.50, "PORT": 6379, "BIG": 12345678901234567890, "FLAG": true, "RELOAD_IN": 300}`,
			want:  map[string]string{"PIN": "12.50", "PORT": "6379", "BIG": "12345678901234567890", "FLAG": "true", "RELOAD_IN": "300"},
		},
		{
			name:  "null and arrays are skipped",
			input: `{"A": "x", "B": null, "C": ["1", "2"], "D": []}`,
			want:  map[string]string{"A": "x"},
		},
		{
			name:  "strings keep escapes and special characters",
			input: `{"KEY": "line1\nline2 \"q\" <&> \u00e4"}`,
			want:  map[string]string{"KEY": "line1\nline2 \"q\" <&> \u00e4"},
		},
		{
			name:  "empty object",
			input: `{}`,
			want:  map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJSONOutput([]byte(tt.input), tt.path)
			if err != nil {
				t.Fatalf("parseJSONOutput: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseJSONOutput_Errors(t *testing.T) {
	const secret = "json-secret-never-in-errors" //nolint:gosec // test fixture, not a credential
	tests := []struct {
		name  string
		input string
		path  []string
		want  string
	}{
		{"not JSON", `TOKEN=` + secret, nil, "output is not valid JSON (at byte"},
		{"broken JSON", `{"A": "` + secret + `", }`, nil, "output is not valid JSON (at byte"},
		{"truncated JSON", `{"A": "` + secret, nil, "output is not valid JSON"},
		{"trailing data", `{"A": "x"} {"B": "` + secret + `"}`, nil, "unexpected data after the JSON value"},
		{"top level is an array", `["` + secret + `"]`, nil, "the top level is not a JSON object"},
		{"path not found", testVaultKV2, []string{testDataKey, "secrets"}, "path data.secrets not found"},
		{"path ends at a string", `{"data": "` + secret + `"}`, []string{testDataKey}, "path data is not a JSON object"},
		{"path runs through a string", `{"data": "` + secret + `"}`, []string{testDataKey, testDataKey}, "path data is not a JSON object"},
		{"invalid variable name", `{"data": {"api-key": "` + secret + `"}}`, []string{testDataKey}, `member data.api-key: "api-key" is not a valid variable name`},
		{"duplicate after flattening", `{"a": {"TOKEN": "` + secret + `"}, "b": {"TOKEN": "y"}}`, nil, "key TOKEN appears twice after flattening (a.TOKEN and b.TOKEN)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseJSONOutput([]byte(tt.input), tt.path)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not contain %q", err, tt.want)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q leaks a value", err)
			}
		})
	}
}

// TestParseJSONOutput_WithoutPathTakesMetadata shows why the path matters
// for Vault: without it, the response metadata becomes keys as well.
func TestParseJSONOutput_WithoutPathTakesMetadata(t *testing.T) {
	got, err := parseJSONOutput([]byte(testVaultKV2), nil)
	if err != nil {
		t.Fatalf("parseJSONOutput: %v", err)
	}
	for _, k := range []string{"request_id", "mount_type", "created_time", testGHKey} {
		if _, ok := got[k]; !ok {
			t.Errorf("flattening the whole response should include %s, got %q", k, got)
		}
	}
}

func TestOutputFormat(t *testing.T) {
	tests := []struct {
		format, path string
		wantFormat   string
		wantPath     []string
		wantErr      string
	}{
		{format: "", path: "", wantFormat: FormatDotenv},
		{format: FormatDotenv, path: "", wantFormat: FormatDotenv},
		{format: FormatJSON, path: "", wantFormat: FormatJSON},
		{format: FormatJSON, path: ".", wantFormat: FormatJSON},
		{format: FormatJSON, path: testPathKV2, wantFormat: FormatJSON, wantPath: []string{testDataKey, testDataKey}},
		{format: FormatJSON, path: "data..data", wantErr: "empty segment"},
		{format: FormatDotenv, path: "data", wantErr: "needs TOOLMESH_CREDENTIAL_FORMAT=json"},
		{format: "yaml", path: "", wantErr: `unknown output format "yaml"`},
	}
	for _, tt := range tests {
		t.Run(tt.format+"|"+tt.path, func(t *testing.T) {
			format, path, err := outputFormat(tt.format, tt.path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("outputFormat: %v", err)
			}
			if format != tt.wantFormat || !reflect.DeepEqual(path, tt.wantPath) {
				t.Errorf("got %q %q, want %q %q", format, path, tt.wantFormat, tt.wantPath)
			}
		})
	}
}
