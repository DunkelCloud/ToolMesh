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
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// healthFixture builds a DADL with the given health block and extra tool
// definitions next to a parameterless get_me and a get_item with a path
// parameter.
func healthFixture(health, extraTools string) string {
	return `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: test-api
  type: rest
  base_url: https://api.example.com
` + health + `
  tools:
    get_me:
      method: GET
      path: /me
      access: read
      params:
        verbose: { type: boolean, in: query, default: false }
    get_item:
      method: GET
      path: /items/{id}
      params:
        id: { type: integer, in: path, required: true }
    search:
      method: GET
      path: /search
      params:
        q: { type: string, in: query, required: true }
    delete_all:
      method: DELETE
      path: /all
      access: dangerous
` + extraTools + `
  composites:
    summary:
      description: "Summary"
      code: "return 1;"
`
}

func TestParseBytes_HealthValidation(t *testing.T) {
	tests := []struct {
		name    string
		health  string
		wantErr string
	}{
		{name: "form 1 tool reference", health: "  health:\n    tool: get_me"},
		{name: "form 2 inline endpoint", health: "  health:\n    path: /status\n    expect_status: 200\n    expect_path: $.status\n    auth_expires_path: $.expires_at\n    timeout: 3s"},
		{name: "form 2 lowercase method", health: "  health:\n    method: head\n    path: /status"},
		{name: "no health block", health: ""},
		{name: "tool and path together", health: "  health:\n    tool: get_me\n    path: /status", wantErr: "mutually exclusive"},
		{name: "neither tool nor path", health: "  health:\n    expect_status: 200", wantErr: "set tool"},
		{name: "unknown tool", health: "  health:\n    tool: nope", wantErr: `"nope" does not name a tool`},
		{name: "composite instead of tool", health: "  health:\n    tool: summary", wantErr: "names a composite"},
		{name: "tool with path parameter", health: "  health:\n    tool: get_item", wantErr: `requires the parameter "id"`},
		{name: "tool with required query parameter", health: "  health:\n    tool: search", wantErr: `requires the parameter "q"`},
		{name: "tool classified dangerous", health: "  health:\n    tool: delete_all", wantErr: "side-effect-free"},
		{name: "placeholder in inline path", health: "  health:\n    path: /items/{id}", wantErr: "placeholders"},
		{name: "unsupported method", health: "  health:\n    method: TRACE\n    path: /status", wantErr: "unsupported method"},
		{name: "expect_status out of range", health: "  health:\n    path: /status\n    expect_status: 42", wantErr: "not an HTTP status"},
		{name: "bad expect_path", health: "  health:\n    path: /status\n    expect_path: $..status", wantErr: "health.expect_path"},
		{name: "bad auth_expires_path", health: "  health:\n    path: /status\n    auth_expires_path: $.a[x]", wantErr: "health.auth_expires_path"},
		{name: "bad timeout", health: "  health:\n    path: /status\n    timeout: soon", wantErr: "not a valid duration"},
		{name: "timeout too long", health: "  health:\n    path: /status\n    timeout: 5m", wantErr: "between 0 and"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBytes([]byte(healthFixture(tt.health, "")))
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

func TestParseBytes_HealthIsAKnownKey(t *testing.T) {
	spec, err := ParseBytes([]byte(healthFixture("  health:\n    path: /status\n    expose: false", "")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spec.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", spec.Warnings)
	}
	if spec.Backend.Health == nil || spec.Backend.Health.Path != "/status" {
		t.Fatalf("health = %+v, want the parsed block", spec.Backend.Health)
	}
}

func TestParseBytes_HealthRequiresFeature(t *testing.T) {
	doc := strings.Replace(healthFixture("  health:\n    tool: get_me", ""),
		"backend:", "requires:\n  features: [health]\nbackend:", 1)
	if _, err := ParseBytes([]byte(doc)); err != nil {
		t.Fatalf("requires.features [health] refused: %v", err)
	}
}

func TestSyntheticHealthTool(t *testing.T) {
	ownHealthTool := "    health:\n      method: GET\n      path: /healthz\n"
	tests := []struct {
		name          string
		health        string
		extraTools    string
		wantSynthetic bool
		wantWarning   bool
	}{
		{name: "declared check is exposed", health: "  health:\n    tool: get_me", wantSynthetic: true},
		{name: "expose false hides it", health: "  health:\n    tool: get_me\n    expose: false"},
		{name: "no check, no tool", health: ""},
		{name: "own tool named health wins, with a warning", health: "  health:\n    path: /status", extraTools: ownHealthTool, wantWarning: true},
		{name: "own tool referenced with expose false", health: "  health:\n    tool: health\n    expose: false", extraTools: ownHealthTool},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := ParseBytes([]byte(healthFixture(tt.health, tt.extraTools)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := spec.Backend.HasSyntheticHealthTool(); got != tt.wantSynthetic {
				t.Errorf("HasSyntheticHealthTool() = %v, want %v", got, tt.wantSynthetic)
			}
			gotWarning := false
			for _, w := range spec.Warnings {
				if strings.Contains(w, "no synthetic health tool is generated") {
					gotWarning = true
					if IsUnknownKeyWarning(w) {
						t.Errorf("collision warning %q classified as an unknown-key finding", w)
					}
				}
			}
			if gotWarning != tt.wantWarning {
				t.Errorf("collision warning = %v, want %v (warnings: %v)", gotWarning, tt.wantWarning, spec.Warnings)
			}
			ts := GenerateTypeScript(spec)
			if got := strings.Contains(ts, "function test-api_health(): Promise<{ ok: boolean;"); got != tt.wantSynthetic {
				t.Errorf("synthetic health in TypeScript = %v, want %v:\n%s", got, tt.wantSynthetic, ts)
			}
		})
	}
}

func TestHealthToolDef(t *testing.T) {
	spec, err := ParseBytes([]byte(healthFixture("  health:\n    tool: get_me", "")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tool, ok := spec.Backend.HealthToolDef()
	if !ok || tool.Path != "/me" || tool.Params["verbose"].Default != false {
		t.Errorf("form 1 HealthToolDef() = %+v, %v; want the get_me definition", tool, ok)
	}

	spec, err = ParseBytes([]byte(healthFixture("  health:\n    method: head\n    path: /status", "")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tool, ok = spec.Backend.HealthToolDef()
	if !ok || tool.Method != httpMethodHEAD || tool.Path != "/status" || tool.Access != accessRead {
		t.Errorf("form 2 HealthToolDef() = %+v, %v; want HEAD /status classified read", tool, ok)
	}

	if _, ok := (&BackendDef{}).HealthToolDef(); ok {
		t.Error("HealthToolDef() without a check reported ok")
	}
}

func TestHealthConfig_CheckTimeout(t *testing.T) {
	tests := []struct {
		timeout string
		want    time.Duration
	}{
		{"", DefaultHealthTimeout},
		{"2s", 2 * time.Second},
		{"garbage", DefaultHealthTimeout},
		{"-1s", DefaultHealthTimeout},
		{"10m", DefaultHealthTimeout},
	}
	for _, tt := range tests {
		if got := (&HealthConfig{Timeout: tt.timeout}).CheckTimeout(); got != tt.want {
			t.Errorf("CheckTimeout(%q) = %s, want %s", tt.timeout, got, tt.want)
		}
	}
	if got := (*HealthConfig)(nil).CheckTimeout(); got != DefaultHealthTimeout {
		t.Errorf("nil CheckTimeout() = %s, want the default", got)
	}
}

func TestParseExpiry(t *testing.T) {
	want := time.Date(2026, 10, 16, 23, 42, 0, 0, time.UTC)
	midnight := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		in     any
		want   time.Time
		wantOK bool
	}{
		{name: "RFC 3339 UTC", in: "2026-10-16T23:42:00Z", want: want, wantOK: true},
		{name: "RFC 3339 with offset", in: "2026-10-17T01:42:00+02:00", want: want, wantOK: true},
		{name: "fractional seconds", in: "2026-10-16T23:42:00.000Z", want: want, wantOK: true},
		{name: "space separated with zone", in: "2026-10-16 23:42:00Z", want: want, wantOK: true},
		{name: "no zone is UTC", in: "2026-10-16T23:42:00", want: want, wantOK: true},
		{name: "date only", in: "2026-10-16", want: midnight, wantOK: true},
		{name: "epoch seconds number", in: float64(want.Unix()), want: want, wantOK: true},
		{name: "epoch milliseconds number", in: float64(want.UnixMilli()), want: want, wantOK: true},
		{name: "epoch seconds string", in: "1792194120", want: want, wantOK: true},
		{name: "json number", in: json.Number("1792194120"), want: want, wantOK: true},
		{name: "int", in: int(want.Unix()), want: want, wantOK: true},
		{name: "time value", in: want, want: want, wantOK: true},
		{name: "null", in: nil},
		{name: "empty", in: "  "},
		{name: "zero", in: float64(0)},
		{name: "negative", in: "-5"},
		{name: "prose", in: "next Tuesday"},
		{name: "bool", in: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ParseExpiry(tt.in)
			if ok != tt.wantOK {
				t.Fatalf("ParseExpiry(%v) ok = %v, want %v", tt.in, ok, tt.wantOK)
			}
			if ok && !got.Equal(tt.want) {
				t.Errorf("ParseExpiry(%v) = %s, want %s", tt.in, got, tt.want)
			}
			if ok && got.Location() != time.UTC {
				t.Errorf("ParseExpiry(%v) location = %s, want UTC", tt.in, got.Location())
			}
		})
	}
}

func TestJSONPathValue(t *testing.T) {
	body := []byte(`{"status":"ok","token":{"expires_at":"2026-10-16"},"items":[{"id":1},{"id":2}],"empty":[],"nothing":null}`)
	tests := []struct {
		path   string
		want   any
		wantOK bool
	}{
		{path: "$.status", want: "ok", wantOK: true},
		{path: "$.token.expires_at", want: "2026-10-16", wantOK: true},
		{path: "$.items[*].id", want: float64(1), wantOK: true},
		{path: "$.nothing", want: nil, wantOK: true},
		{path: "$.missing"},
		{path: "$.empty[*]"},
		{path: "$..status"},
	}
	for _, tt := range tests {
		got, ok := JSONPathValue(body, tt.path)
		if ok != tt.wantOK || (ok && got != tt.want) {
			t.Errorf("JSONPathValue(%q) = %v, %v; want %v, %v", tt.path, got, ok, tt.want, tt.wantOK)
		}
	}
	if _, ok := JSONPathValue([]byte("<html>"), "$.status"); ok {
		t.Error("JSONPathValue on a non-JSON body reported a match")
	}
}
