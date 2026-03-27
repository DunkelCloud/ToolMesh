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

// Package dadl implements parsing and validation of DADL (Dunkel API Description Language) files.
package dadl

import "time"

// Spec represents a parsed .dadl file.
type Spec struct {
	Version string     `yaml:"version"`
	Backend BackendDef `yaml:"backend"`
}

// ContainsCode returns true if the spec has composite tools (inline JavaScript).
// Used by CI/CD pipelines to gate on AST-based static analysis.
func (s *Spec) ContainsCode() bool {
	return len(s.Backend.Composites) > 0
}

// BackendDef describes a REST API backend with its tools, auth, and behavior.
type BackendDef struct {
	Name        string                  `yaml:"name"`
	Type        string                  `yaml:"type"` // must be "rest"
	BaseURL     string                  `yaml:"base_url"`
	Description string                  `yaml:"description"`
	Auth        AuthConfig              `yaml:"auth"`
	Defaults    DefaultsConfig          `yaml:"defaults"`
	Tools       map[string]ToolDef      `yaml:"tools"`
	Types       map[string]any          `yaml:"types"`          // JSON Schema subset for TS generation
	Composites  map[string]CompositeDef `yaml:"composites"`     // server-side JS functions combining tools
	Scoping     *ScopingConfig          `yaml:"scoping"`        // nil = expose all tools
	OpenAPI     string                  `yaml:"openapi_source"` // optional path to OpenAPI spec
}

// DefaultsConfig provides default settings inherited by all tools unless overridden.
type DefaultsConfig struct {
	Headers    map[string]string `yaml:"headers"`
	Pagination *PaginationConfig `yaml:"pagination"`
	Errors     *ErrorConfig      `yaml:"errors"`
	Response   *ResponseConfig   `yaml:"response"`
}

// ToolDef describes a single REST API tool (endpoint).
type ToolDef struct {
	Method      string              `yaml:"method"` // GET, POST, PUT, PATCH, DELETE
	Path        string              `yaml:"path"`   // /resource/{id}
	Description string              `yaml:"description"`
	Params      map[string]ParamDef `yaml:"params"`
	Body        *BodyDef            `yaml:"body"`
	Response    *ResponseConfig     `yaml:"response"`
	Pagination  any                 `yaml:"pagination"` // *PaginationConfig, "none", or nil (inherit defaults)
	Errors      *ErrorConfig        `yaml:"errors"`     // nil = inherit defaults
	ContentType string              `yaml:"content_type"`
}

// ParamDef describes a single parameter for a tool.
type ParamDef struct {
	Type     string `yaml:"type"` // string, integer, number, boolean, array, object
	In       string `yaml:"in"`   // path, query, header, body
	Required bool   `yaml:"required"`
	Default  any    `yaml:"default"`
}

// BodyDef describes a request body schema.
type BodyDef struct {
	Schema map[string]any `yaml:"schema"` // JSON Schema subset or $ref
}

// ResponseConfig controls how API responses are processed.
type ResponseConfig struct {
	ResultPath      string `yaml:"result_path"`   // JSONPath, e.g. "$.data"
	MetadataPath    string `yaml:"metadata_path"` // JSONPath for metadata
	Transform       string `yaml:"transform"`     // jq expression
	MaxItems        int    `yaml:"max_items"`
	AllowJQOverride bool   `yaml:"allow_jq_override"`
	Binary          bool   `yaml:"binary"`
	Streaming       bool   `yaml:"streaming"`
	StreamHandling  string `yaml:"stream_handling"` // collect, skip
	MaxDuration     string `yaml:"max_duration"`
	MaxStreamItems  int    `yaml:"max_stream_items"`
	ContentType     string `yaml:"content_type"`
}

// AuthConfig describes how to authenticate with the REST API.
type AuthConfig struct {
	Type       string `yaml:"type"`        // bearer, oauth2, session, apikey, basic
	Credential string `yaml:"credential"`  // logical name for CredentialStore
	InjectInto string `yaml:"inject_into"` // header, query
	HeaderName string `yaml:"header_name"` // e.g. "Authorization"
	Prefix     string `yaml:"prefix"`      // e.g. "Bearer "
	QueryParam string `yaml:"query_param"` // for apikey in query
	// Basic
	UsernameCredential string `yaml:"username_credential"` // credential ref for username
	PasswordCredential string `yaml:"password_credential"` // credential ref for password (optional, default "")
	// OAuth2
	Flow                   string   `yaml:"flow"` // client_credentials
	TokenURL               string   `yaml:"token_url"`
	ClientIDCredential     string   `yaml:"client_id_credential"`
	ClientSecretCredential string   `yaml:"client_secret_credential"`
	Scopes                 []string `yaml:"scopes"`
	TokenCacheKey          string   `yaml:"token_cache_key"`
	RefreshBeforeExpiry    string   `yaml:"refresh_before_expiry"`
	// Session
	Login   *SessionLogin  `yaml:"login"`
	Inject  []InjectRule   `yaml:"inject"`
	Refresh *RefreshConfig `yaml:"refresh"`
}

// SessionLogin describes a session-based login flow.
type SessionLogin struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Body    map[string]string `yaml:"body"`    // values can be credential refs
	Extract map[string]string `yaml:"extract"` // token name → JSONPath
}

// InjectRule describes how to inject a session token into requests.
type InjectRule struct {
	Header string `yaml:"header"`
	Value  string `yaml:"value"` // template with {{token}}, {{csrf}}
}

// RefreshConfig describes session refresh behavior.
type RefreshConfig struct {
	Trigger string `yaml:"trigger"` // e.g. "status_code_401"
	Action  string `yaml:"action"`  // e.g. "re_login"
}

// PaginationConfig describes how to paginate through API results.
type PaginationConfig struct {
	Strategy string             `yaml:"strategy"` // cursor, offset, page, link_header
	Request  PaginationRequest  `yaml:"request"`
	Response PaginationResponse `yaml:"response"`
	Behavior string             `yaml:"behavior"` // auto, expose
	MaxPages int                `yaml:"max_pages"`
}

// PaginationRequest describes how to request the next page.
type PaginationRequest struct {
	CursorParam  string `yaml:"cursor_param"`
	LimitParam   string `yaml:"limit_param"`
	LimitDefault int    `yaml:"limit_default"`
	OffsetParam  string `yaml:"offset_param"`
	PageParam    string `yaml:"page_param"`
}

// PaginationResponse describes how to detect pagination state from a response.
type PaginationResponse struct {
	NextCursor       string `yaml:"next_cursor"`        // JSONPath
	HasMore          string `yaml:"has_more"`           // JSONPath
	TotalPagesHeader string `yaml:"total_pages_header"` // HTTP header name
	TotalCountHeader string `yaml:"total_count_header"` // HTTP header name
}

// ErrorConfig describes how to handle API errors.
type ErrorConfig struct {
	Format        string               `yaml:"format"`       // json
	MessagePath   string               `yaml:"message_path"` // JSONPath
	CodePath      string               `yaml:"code_path"`    // JSONPath
	RetryOn       []int                `yaml:"retry_on"`     // HTTP status codes
	Terminal      []int                `yaml:"terminal"`     // HTTP status codes (no retry)
	RateLimit     *RateLimitConfig     `yaml:"rate_limit"`
	RetryStrategy *RetryStrategyConfig `yaml:"retry_strategy"`
}

// RateLimitConfig describes rate limit header handling.
type RateLimitConfig struct {
	Header           string `yaml:"header"`             // e.g. "X-RateLimit-Remaining"
	RetryAfterHeader string `yaml:"retry_after_header"` // e.g. "Retry-After"
}

// RetryStrategyConfig describes retry behavior on transient errors.
type RetryStrategyConfig struct {
	MaxRetries   int    `yaml:"max_retries"`
	Backoff      string `yaml:"backoff"` // exponential, linear, fixed
	InitialDelay string `yaml:"initial_delay"`
}

// ScopingConfig controls tool visibility for large APIs.
type ScopingConfig struct {
	Strategy  string              `yaml:"strategy"` // static, progressive, dynamic, code_mode, auto
	Threshold int                 `yaml:"threshold"`
	Fallback  string              `yaml:"fallback"`
	Scopes    map[string]ScopeDef `yaml:"scopes"`
	Discovery *DiscoveryConfig    `yaml:"discovery"`
}

// ScopeDef describes a named scope of tools.
type ScopeDef struct {
	Description    string   `yaml:"description"`
	Tools          []string `yaml:"tools"`
	DefaultExposed bool     `yaml:"default_exposed"`
	RequiresPlan   string   `yaml:"requires_plan"`
}

// DiscoveryConfig describes on-demand tool discovery.
type DiscoveryConfig struct {
	ToolName        string   `yaml:"tool_name"`
	Description     string   `yaml:"description"`
	ExposeFields    []string `yaml:"expose_fields"`
	LoadOnDemand    bool     `yaml:"load_on_demand"`
	MaxToolsPerLoad int      `yaml:"max_tools_per_load"`
}

// CompositeDef describes a server-side JavaScript function that combines
// multiple primitive REST tools into a higher-level operation.
// Composites run in a sandboxed goja runtime with access only to api.* calls.
type CompositeDef struct {
	Description string              `yaml:"description"` // required
	Code        string              `yaml:"code"`        // required — JavaScript source
	Params      map[string]ParamDef `yaml:"params"`      // optional input parameters
	Timeout     string              `yaml:"timeout"`     // optional, default "30s", max "120s"
	DependsOn   []string            `yaml:"depends_on"`  // optional — primitive tools used
}

// MaxCompositeTimeout is the maximum allowed timeout for a composite tool.
const MaxCompositeTimeout = 120 * time.Second

// DefaultCompositeTimeout is the default timeout for a composite tool.
const DefaultCompositeTimeout = 30 * time.Second

// CompositeTimeout parses the timeout string and returns the duration,
// clamped to [0, MaxCompositeTimeout]. Returns DefaultCompositeTimeout if empty.
func (c *CompositeDef) CompositeTimeout() time.Duration {
	if c.Timeout == "" {
		return DefaultCompositeTimeout
	}
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return DefaultCompositeTimeout
	}
	if d <= 0 {
		return DefaultCompositeTimeout
	}
	if d > MaxCompositeTimeout {
		return MaxCompositeTimeout
	}
	return d
}
