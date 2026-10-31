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
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// HealthToolName is the name of the synthetic tool a declared health check
// is exposed as (spec §4.6).
const HealthToolName = "health"

// DefaultHealthTimeout bounds one health check when the declaration sets no
// timeout (spec §4.6).
const DefaultHealthTimeout = 5 * time.Second

// MaxHealthTimeout caps health.timeout. A check is meant to be the cheapest
// call the API offers; a longer budget would only hold monitoring up.
const MaxHealthTimeout = 60 * time.Second

// HealthToolDescription is the description of the synthetic health tool,
// shared by the generated TypeScript interface and the tool descriptors so
// both mark the tool as the standardized check (spec §4.6).
const HealthToolDescription = "Standardized backend health check: verifies that the API is reachable and the configured credential works. Never fails — branch on ok; error names the cause when ok is false."

// HealthResultTS is the TypeScript type of the standardized health result
// (spec §4.6).
const HealthResultTS = "{ ok: boolean; http_status?: number; error_code?: string; latency_ms: number; checked_at: string; auth_expires_at?: string; error?: string }"

// Access classifications a health check must not carry: the check runs
// unattended at startup and on every poll, so it has to be side-effect-free.
const (
	accessWrite     = "write"
	accessAdmin     = "admin"
	accessDangerous = "dangerous"
	accessRead      = "read"
)

// HealthConfig is the optional backend health-check declaration (spec §4.6):
// the cheapest call that verifies the backend is reachable and the
// configured credential works. Form 1 references a declared tool (Tool);
// form 2 describes an inline endpoint (Path, optionally Method). The two
// forms are mutually exclusive.
type HealthConfig struct {
	// Tool names a declared tool (not a composite) without required
	// parameters to use as the check (form 1).
	Tool string `yaml:"tool"`
	// Method is the HTTP method of the inline endpoint (form 2). Default GET.
	Method string `yaml:"method"`
	// Path is the inline endpoint relative to base_url, without {param}
	// placeholders (form 2).
	Path string `yaml:"path"`
	// ExpectStatus is the exact status that passes; 0 means any 2xx.
	ExpectStatus int `yaml:"expect_status"`
	// ExpectPath is a JSONPath that must exist in the response body. Only
	// existence is asserted, the value is not inspected.
	ExpectPath string `yaml:"expect_path"`
	// AuthExpiresPath is a JSONPath extracting the credential expiry from
	// the check response; it feeds auth_expires_at in the result.
	AuthExpiresPath string `yaml:"auth_expires_path"`
	// Timeout bounds the check, as a Go duration. Default 5s.
	Timeout string `yaml:"timeout"`
	// Expose offers the check as the synthetic health tool. nil means true.
	Expose *bool `yaml:"expose"`
}

// CheckTimeout returns the declared timeout, or DefaultHealthTimeout when it
// is unset. Validation rejects malformed and out-of-range values at load
// time; the default here only guards hand-built specs.
func (h *HealthConfig) CheckTimeout() time.Duration {
	if h == nil || h.Timeout == "" {
		return DefaultHealthTimeout
	}
	d, err := time.ParseDuration(h.Timeout)
	if err != nil || d <= 0 || d > MaxHealthTimeout {
		return DefaultHealthTimeout
	}
	return d
}

// Exposed reports whether the check is to be offered as the synthetic
// health tool (expose, default true).
func (h *HealthConfig) Exposed() bool {
	return h != nil && (h.Expose == nil || *h.Expose)
}

// HasSyntheticHealthTool reports whether the backend carries the synthetic
// health tool: a check is declared, expose is not false, and the file
// declares no tool or composite named health itself — a declared one always
// wins, so the interface shows its real signature (spec §4.6).
func (b *BackendDef) HasSyntheticHealthTool() bool {
	if !b.Health.Exposed() {
		return false
	}
	_, isTool := b.Tools[HealthToolName]
	_, isComposite := b.Composites[HealthToolName]
	return !isTool && !isComposite
}

// HealthToolDef returns the request a health check sends: a copy of the
// referenced tool (form 1) or a tool built from the inline method and path
// (form 2). ok is false when the backend declares no check.
func (b *BackendDef) HealthToolDef() (ToolDef, bool) {
	h := b.Health
	if h == nil {
		return ToolDef{}, false
	}
	if h.Tool != "" {
		tool, ok := b.Tools[h.Tool]
		return tool, ok
	}
	method := strings.ToUpper(h.Method)
	if method == "" {
		method = httpMethodGET
	}
	return ToolDef{Method: method, Path: h.Path, Access: accessRead}, true
}

// validateHealth checks the health declaration (spec §4.6): exactly one of
// the two forms, a referenced tool that exists, is no composite, needs no
// parameter and is not classified as a write, an inline path without
// placeholders, and well-formed expectations and timeout.
func validateHealth(b *BackendDef) error {
	h := b.Health
	if h == nil {
		return nil
	}
	inline := h.Method != "" || h.Path != ""
	switch {
	case h.Tool != "" && inline:
		return fmt.Errorf("health: tool and method/path are mutually exclusive")
	case h.Tool != "":
		tool, ok := b.Tools[h.Tool]
		if !ok {
			if _, isComposite := b.Composites[h.Tool]; isComposite {
				return fmt.Errorf("health.tool %q names a composite; the check must reference a declared tool", h.Tool)
			}
			return fmt.Errorf("health.tool %q does not name a tool in this file", h.Tool)
		}
		for pname, p := range tool.Params {
			if p.Required || p.In == paramInPath {
				return fmt.Errorf("health.tool %q requires the parameter %q; a check tool must not have required parameters", h.Tool, pname)
			}
		}
		switch tool.Access {
		case accessWrite, accessAdmin, accessDangerous:
			return fmt.Errorf("health.tool %q is classified access %q; the check must be side-effect-free", h.Tool, tool.Access)
		}
	case h.Path == "":
		return fmt.Errorf("health: set tool (a declared tool) or path (an inline endpoint)")
	default:
		if strings.ContainsAny(h.Path, "{}") {
			return fmt.Errorf("health.path %q must not contain {param} placeholders", h.Path)
		}
		if h.Method != "" && !validMethods[strings.ToUpper(h.Method)] {
			return fmt.Errorf("health.method: unsupported method %q", h.Method)
		}
	}
	if h.ExpectStatus != 0 && (h.ExpectStatus < 100 || h.ExpectStatus > 599) {
		return fmt.Errorf("health.expect_status %d is not an HTTP status", h.ExpectStatus)
	}
	if h.ExpectPath != "" {
		if _, err := NewJSONPath(h.ExpectPath); err != nil {
			return fmt.Errorf("health.expect_path: %w", err)
		}
	}
	if h.AuthExpiresPath != "" {
		if _, err := NewJSONPath(h.AuthExpiresPath); err != nil {
			return fmt.Errorf("health.auth_expires_path: %w", err)
		}
	}
	if h.Timeout != "" {
		d, err := time.ParseDuration(h.Timeout)
		if err != nil {
			return fmt.Errorf("health.timeout %q is not a valid duration (e.g. \"5s\"): %w", h.Timeout, err)
		}
		if d <= 0 || d > MaxHealthTimeout {
			return fmt.Errorf("health.timeout must be between 0 and %s, got %q", MaxHealthTimeout, h.Timeout)
		}
	}
	return nil
}

// healthWarnings reports what a validator warns about in the health
// declaration: a declared tool or composite named health shadows the
// synthetic tool (spec §4.6). Not reported when expose is false — that is
// the documented way to use such a tool as the check.
func healthWarnings(b *BackendDef) []string {
	if !b.Health.Exposed() || b.HasSyntheticHealthTool() {
		return nil
	}
	return []string{fmt.Sprintf(
		"backend declares its own tool or composite %q; it takes precedence and no synthetic health tool is generated (DADL spec 4.6)",
		HealthToolName)}
}

// JSONPathValue applies a JSONPath (§9.4 dialect) to a JSON body. A path
// with wildcards yields its first match. ok is false when the path does not
// parse, the body is not JSON, or nothing matches.
func JSONPathValue(body []byte, path string) (any, bool) {
	val, ok := extractPathValue(body, path)
	if !ok {
		return nil, false
	}
	if nodes, isList := val.([]any); isList {
		jp, err := NewJSONPath(path)
		if err == nil && jp.hasWildcard() {
			if len(nodes) == 0 {
				return nil, false
			}
			return nodes[0], true
		}
	}
	return val, true
}

// expiryLayouts are the timestamp layouts ParseExpiry tries in order.
var expiryLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04",
	"2006-01-02",
}

// epochMillisThreshold separates Unix seconds from milliseconds: 1e12
// seconds lie in the year 33658, 1e12 milliseconds in 2001.
const epochMillisThreshold = 1e12

// ParseExpiry reads a credential-expiry timestamp in the formats spec §4.6
// asks runtimes to accept: RFC 3339 / ISO 8601 with or without a time of
// day (a value without a zone is UTC), and Unix epoch seconds or
// milliseconds as a JSON number or numeric string. The result is UTC. ok is
// false for anything else, including null, empty and non-positive values.
func ParseExpiry(v any) (time.Time, bool) {
	switch t := v.(type) {
	case time.Time:
		return t.UTC(), !t.IsZero()
	case float64:
		return epochTime(t)
	case int:
		return epochTime(float64(t))
	case int64:
		return epochTime(float64(t))
	case json.Number:
		n, err := t.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return epochTime(n)
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return time.Time{}, false
		}
		if n, err := strconv.ParseFloat(s, 64); err == nil {
			return epochTime(n)
		}
		for _, layout := range expiryLayouts {
			if ts, err := time.Parse(layout, s); err == nil {
				return ts.UTC(), true
			}
		}
	}
	return time.Time{}, false
}

// epochTime converts Unix seconds or milliseconds to a UTC time.
func epochTime(n float64) (time.Time, bool) {
	if n <= 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return time.Time{}, false
	}
	if n >= epochMillisThreshold {
		return time.UnixMilli(int64(n)).UTC(), true
	}
	sec, frac := math.Modf(n)
	return time.Unix(int64(sec), int64(frac*float64(time.Second))).UTC(), true
}
