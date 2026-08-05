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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/DunkelCloud/ToolMesh/internal/version"
)

// pathParamRe matches {param} placeholders in URL paths.
var pathParamRe = regexp.MustCompile(`\{(\w+)\}`)

// dadlSpecV01URL is the canonical URL of the DADL v0.1 specification.
const dadlSpecV01URL = "https://dadl.ai/spec/dadl-spec-v0.1.md"

// dadlSpecV02URL is the canonical URL of the DADL v0.2 specification.
// v0.2 is an additive superset of v0.1; features introduced with it
// (oauth2 flow refresh_token) require the file to declare this spec.
const dadlSpecV02URL = "https://dadl.ai/spec/dadl-spec-v0.2.md"

// Pagination strategy values used in DADL specs.
const (
	paginationStrategyCursor     = "cursor"
	paginationStrategyOffset     = "offset"
	paginationStrategyPage       = "page"
	paginationStrategyLinkHeader = "link_header"
)

// HTTP method literals used in DADL tool definitions.
const (
	httpMethodGET  = "GET"
	httpMethodPOST = "POST"
)

// Backend transport / param-location literals used in DADL specs.
const (
	backendTypeREST = "rest"
	paramInPath     = "path"
	paramInBody     = "body"
)

// supportedSpecs lists spec URLs accepted by this version of ToolMesh.
// Add new entries when a new DADL spec version is released.
var supportedSpecs = map[string]bool{
	dadlSpecV01URL: true,
	dadlSpecV02URL: true,
}

// specVersionRe extracts the version from a DADL spec URL.
var specVersionRe = regexp.MustCompile(`^https://dadl\.ai/spec/dadl-spec-v(\d+\.\d+)\.md$`)

// backendVersionRe matches the optional backend.version field — MAJOR.MINOR
// or MAJOR.MINOR.PATCH, both forms appear in the registry.
var backendVersionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

// Parse reads and validates a .dadl file, returning the parsed Spec.
func Parse(path string) (*Spec, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read dadl file %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses DADL content from bytes.
//
// Keys the runtime does not implement are collected into Spec.Warnings and
// otherwise ignored (DADL spec §15.3 warn-and-ignore) — except when the
// file's requires block names a missing capability, which refuses the load
// entirely (fail-closed, ADR-0003).
func ParseBytes(data []byte) (*Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse dadl: %w", err)
	}
	if err := Validate(&spec); err != nil {
		return nil, fmt.Errorf("validate dadl: %w", err)
	}
	spec.Warnings = unknownKeyWarnings(data)
	if err := checkRequires(&spec, version.Version); err != nil {
		return nil, fmt.Errorf("refusing to load dadl: %w", err)
	}
	// Normalize CRLF to LF so the same file produces the same hash on Windows and Linux.
	normalized := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	hash := sha256.Sum256(normalized)
	spec.ContentHash = hex.EncodeToString(hash[:])
	return &spec, nil
}

// yamlFieldErrRe matches the unknown-field messages gopkg.in/yaml.v3 emits
// under Decoder.KnownFields(true): "line N: field F not found in type T".
var yamlFieldErrRe = regexp.MustCompile(`^line (\d+): field (\S+) not found in type (\S+)$`)

// yamlTypeContext maps the Go struct names appearing in yaml.v3 unknown-field
// messages to the DADL document location they represent, so warnings speak
// spec language instead of Go type names.
var yamlTypeContext = map[string]string{
	"dadl.Spec":                "top level",
	"dadl.RequiresConfig":      "requires",
	"dadl.BackendDef":          "backend",
	"dadl.AuthConfig":          "auth",
	"dadl.SessionLogin":        "auth.login",
	"dadl.InjectRule":          "auth.inject",
	"dadl.RefreshConfig":       "auth.refresh",
	"dadl.DefaultsConfig":      "defaults",
	"dadl.PaginationConfig":    "pagination",
	"dadl.PaginationRequest":   "pagination.request",
	"dadl.PaginationResponse":  "pagination.response",
	"dadl.ErrorConfig":         "errors",
	"dadl.RateLimitConfig":     "errors.rate_limit",
	"dadl.RetryStrategyConfig": "errors.retry_strategy",
	"dadl.ResponseConfig":      "response",
	"dadl.ToolDef":             "tool definition",
	"dadl.ParamDef":            "parameter definition",
	"dadl.BodyDef":             "body",
	"dadl.CompositeDef":        "composite definition",
	"dadl.ScopingConfig":       "scoping",
	"dadl.ScopeDef":            "scoping.scopes",
	"dadl.DiscoveryConfig":     "scoping.discovery",
}

// unknownKeyWarnings re-decodes data strictly and reports every key this
// runtime does not know, implementing the spec §15.3 runtime policy: warn
// and ignore, so a file using only additive newer features keeps working —
// degraded but visibly. Underscore-prefixed keys are the spec's YAML anchor
// workspace and stay silent.
//
// It relies on the lenient decode in ParseBytes having succeeded: the only
// errors the strict re-decode can add are unknown-field errors.
func unknownKeyWarnings(data []byte) []string {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var strict Spec
	err := dec.Decode(&strict)
	if err == nil {
		return nil
	}
	var typeErr *yaml.TypeError
	if !errors.As(err, &typeErr) {
		// Unexpected given the lenient decode succeeded — surface rather than drop.
		return []string{fmt.Sprintf("strict re-parse failed: %v", err)}
	}
	// Aggregate per key and location kind: a key repeated across many tools
	// (e.g. max_body_size on every upload tool) yields one warning with a
	// count, not one per occurrence.
	type unknownKey struct {
		field, context, firstLine string
		count                     int
	}
	var warnings []string
	var order []*unknownKey
	seen := make(map[string]*unknownKey)
	for _, msg := range typeErr.Errors {
		m := yamlFieldErrRe.FindStringSubmatch(msg)
		if m == nil {
			warnings = append(warnings, msg)
			continue
		}
		line, field, goType := m[1], m[2], m[3]
		if strings.HasPrefix(field, "_") {
			continue
		}
		dedupeKey := field + "\x00" + goType
		if entry, ok := seen[dedupeKey]; ok {
			entry.count++
			continue
		}
		context, ok := yamlTypeContext[goType]
		if !ok {
			context = strings.TrimPrefix(goType, "dadl.")
		}
		entry := &unknownKey{field: field, context: context, firstLine: line, count: 1}
		seen[dedupeKey] = entry
		order = append(order, entry)
	}
	for _, e := range order {
		location := fmt.Sprintf("line %s", e.firstLine)
		if e.count > 1 {
			location = fmt.Sprintf("%d occurrences, first at line %s", e.count, e.firstLine)
		}
		warnings = append(warnings, fmt.Sprintf(
			"unknown key %q in %s (%s): not implemented by this ToolMesh version, ignored (DADL spec 15.3)",
			e.field, e.context, location))
	}
	return warnings
}

// validAuthTypes lists the supported authentication types.
var validAuthTypes = map[string]bool{
	authTypeBearer:  true,
	authTypeOAuth2:  true,
	authTypeSession: true,
	authTypeAPIKey:  true,
	authTypeBasic:   true,
}

// validPaginationStrategies lists the supported pagination strategies.
var validPaginationStrategies = map[string]bool{
	paginationStrategyCursor:     true,
	paginationStrategyOffset:     true,
	paginationStrategyPage:       true,
	paginationStrategyLinkHeader: true,
}

// validMethods lists the supported HTTP methods.
var validMethods = map[string]bool{
	httpMethodGET:  true,
	httpMethodPOST: true,
	"PUT":          true,
	"PATCH":        true,
	"DELETE":       true,
	"HEAD":         true,
}

// Validate checks a Spec for structural correctness.
func Validate(spec *Spec) error {
	if !supportedSpecs[spec.Spec] {
		supported := make([]string, 0, len(supportedSpecs))
		for s := range supportedSpecs {
			supported = append(supported, s)
		}
		return fmt.Errorf("unsupported spec %q (supported: %s)", spec.Spec, strings.Join(supported, ", "))
	}

	b := &spec.Backend
	if b.Type != backendTypeREST {
		return fmt.Errorf("backend.type must be \"rest\", got %q", b.Type)
	}
	// base_url is optional in the DADL — can be provided via backends.yaml at runtime
	if b.Name == "" {
		return fmt.Errorf("backend.name must not be empty")
	}

	// Validate optional backend.version — accept MAJOR.MINOR or MAJOR.MINOR.PATCH.
	if b.Version != "" && !backendVersionRe.MatchString(b.Version) {
		return fmt.Errorf("backend.version %q must be MAJOR.MINOR or MAJOR.MINOR.PATCH (e.g. \"1.0\", \"1.2.1\")", b.Version)
	}

	// Validate auth
	if b.Auth.Type != "" {
		if !validAuthTypes[b.Auth.Type] {
			return fmt.Errorf("auth.type must be one of bearer, oauth2, session, apikey, basic; got %q", b.Auth.Type)
		}
		if b.Auth.Type == authTypeOAuth2 {
			switch b.Auth.Flow {
			case "", oauth2FlowClientCredentials:
			case oauth2FlowRefreshToken:
				// Introduced with spec v0.2. Rejecting it under a v0.1
				// declaration keeps the spec URL an honest capability
				// contract: pre-v0.2 runtimes fail such files at load
				// time instead of sending the wrong grant at call time.
				if spec.Spec == dadlSpecV01URL {
					return fmt.Errorf("auth.flow %q requires spec v0.2 (%s)", oauth2FlowRefreshToken, dadlSpecV02URL)
				}
				if b.Auth.RefreshTokenCredential == "" {
					return fmt.Errorf("auth.flow %q requires auth.refresh_token_credential", oauth2FlowRefreshToken)
				}
			default:
				return fmt.Errorf("auth.flow must be client_credentials or refresh_token; got %q", b.Auth.Flow)
			}
		}
	}

	// Validate default pagination
	if b.Defaults.Pagination != nil {
		if err := validatePagination(b.Defaults.Pagination, "defaults.pagination"); err != nil {
			return err
		}
	}

	// Validate default response config
	if err := validateResponse(b.Defaults.Response, "defaults.response"); err != nil {
		return err
	}

	// Validate tools
	if len(b.Tools) == 0 {
		return fmt.Errorf("backend must define at least one tool")
	}

	for name, tool := range b.Tools {
		if err := validateTool(name, &tool); err != nil {
			return err
		}
	}

	// Validate composites
	for name, comp := range b.Composites {
		if err := validateComposite(name, &comp, b.Tools, b.Composites); err != nil {
			return err
		}
	}

	return nil
}

func validateTool(name string, tool *ToolDef) error {
	if tool.Method == "" {
		return fmt.Errorf("tool %q: method is required", name)
	}
	if !validMethods[strings.ToUpper(tool.Method)] {
		return fmt.Errorf("tool %q: unsupported method %q", name, tool.Method)
	}
	if tool.Path == "" {
		return fmt.Errorf("tool %q: path is required", name)
	}

	// Check that path params referenced in the path template are declared in params
	pathParams := pathParamRe.FindAllStringSubmatch(tool.Path, -1)
	for _, match := range pathParams {
		paramName := match[1]
		param, exists := tool.Params[paramName]
		if !exists {
			return fmt.Errorf("tool %q: path parameter {%s} not declared in params", name, paramName)
		}
		if param.In != "" && param.In != paramInPath {
			return fmt.Errorf("tool %q: parameter %q is used in path but declared as in=%q", name, paramName, param.In)
		}
	}

	if err := validateFileURLParams(name, tool); err != nil {
		return err
	}

	return validateResponse(tool.Response, fmt.Sprintf("tool %q: response", name))
}

// validateFileURLParams enforces the file_url constraints of DADL spec §6.2.1:
// file_url params carry the request payload, so they must be `in: body`, and
// outside multipart/form-data mode the fetched bytes ARE the raw request body —
// a second body param would have nowhere to go.
func validateFileURLParams(name string, tool *ToolDef) error {
	fileURLCount := 0
	otherBodyCount := 0
	for pname, p := range tool.Params {
		if p.Type == ParamTypeFileURL {
			if p.In != paramInBody {
				return fmt.Errorf("tool %q: file_url parameter %q must be in: body, got in: %q", name, pname, p.In)
			}
			fileURLCount++
		} else if p.In == paramInBody {
			otherBodyCount++
		}
	}
	if fileURLCount > 0 && tool.ContentType != ContentTypeMultipartForm {
		if fileURLCount > 1 {
			return fmt.Errorf("tool %q: multiple file_url parameters require content_type: %s", name, ContentTypeMultipartForm)
		}
		if otherBodyCount > 0 {
			return fmt.Errorf("tool %q: a file_url parameter must be the only body parameter unless content_type is %s", name, ContentTypeMultipartForm)
		}
	}
	return nil
}

// validateResponse checks the response block of a tool or the backend defaults.
func validateResponse(rc *ResponseConfig, prefix string) error {
	if rc == nil {
		return nil
	}
	if rc.Type != "" && rc.Type != ResponseTypeFileURL {
		return fmt.Errorf("%s.type must be %q or empty, got %q", prefix, ResponseTypeFileURL, rc.Type)
	}
	if rc.TTL != "" {
		if rc.Type != ResponseTypeFileURL {
			return fmt.Errorf("%s.ttl requires type: %s", prefix, ResponseTypeFileURL)
		}
		d, err := time.ParseDuration(rc.TTL)
		if err != nil {
			return fmt.Errorf("%s.ttl %q is not a valid duration (e.g. \"24h\"): %w", prefix, rc.TTL, err)
		}
		if d <= 0 {
			return fmt.Errorf("%s.ttl must be positive, got %q", prefix, rc.TTL)
		}
	}
	return nil
}

func validatePagination(p *PaginationConfig, prefix string) error {
	if p.Strategy != "" && !validPaginationStrategies[p.Strategy] {
		return fmt.Errorf("%s.strategy must be one of cursor, offset, page, link_header; got %q", prefix, p.Strategy)
	}
	return nil
}

func validateComposite(name string, comp *CompositeDef, tools map[string]ToolDef, composites map[string]CompositeDef) error {
	if comp.Description == "" {
		return fmt.Errorf("composite %q: description is required", name)
	}
	if strings.TrimSpace(comp.Code) == "" {
		return fmt.Errorf("composite %q: code must not be empty", name)
	}

	// Validate timeout
	if comp.Timeout != "" {
		d, err := time.ParseDuration(comp.Timeout)
		if err != nil {
			return fmt.Errorf("composite %q: invalid timeout %q: %w", name, comp.Timeout, err)
		}
		if d > MaxCompositeTimeout {
			return fmt.Errorf("composite %q: timeout %s exceeds maximum %s", name, comp.Timeout, MaxCompositeTimeout)
		}
		if d <= 0 {
			return fmt.Errorf("composite %q: timeout must be positive", name)
		}
	}

	// Validate depends_on references — must be primitive tools, not other composites
	for _, dep := range comp.DependsOn {
		if _, ok := tools[dep]; !ok {
			return fmt.Errorf("composite %q: depends_on references unknown tool %q", name, dep)
		}
		if _, ok := composites[dep]; ok {
			return fmt.Errorf("composite %q: depends_on must reference primitive tools, not composite %q", name, dep)
		}
	}

	// Composite name must not collide with primitive tools
	if _, ok := tools[name]; ok {
		return fmt.Errorf("composite %q: name conflicts with a primitive tool", name)
	}

	return nil
}
