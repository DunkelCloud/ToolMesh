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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// pathParamRe matches {param} placeholders in URL paths.
var pathParamRe = regexp.MustCompile(`\{(\w+)\}`)

// supportedSpecs lists spec URLs accepted by this version of ToolMesh.
// Add new entries when a new DADL spec version is released.
var supportedSpecs = map[string]bool{
	"https://dadl.ai/spec/dadl-spec-v0.1.md": true,
}

// specVersionRe extracts the version from a DADL spec URL.
var specVersionRe = regexp.MustCompile(`^https://dadl\.ai/spec/dadl-spec-v(\d+\.\d+)\.md$`)

// Parse reads and validates a .dadl file, returning the parsed Spec.
func Parse(path string) (*Spec, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if err != nil {
		return nil, fmt.Errorf("read dadl file %s: %w", path, err)
	}
	return ParseBytes(data)
}

// ParseBytes parses DADL content from bytes.
func ParseBytes(data []byte) (*Spec, error) {
	var spec Spec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse dadl: %w", err)
	}
	if err := Validate(&spec); err != nil {
		return nil, fmt.Errorf("validate dadl: %w", err)
	}
	hash := sha256.Sum256(data)
	spec.ContentHash = hex.EncodeToString(hash[:])
	return &spec, nil
}

// validAuthTypes lists the supported authentication types.
var validAuthTypes = map[string]bool{
	"bearer":  true,
	"oauth2":  true,
	"session": true,
	"apikey":  true,
	"basic":   true,
}

// validPaginationStrategies lists the supported pagination strategies.
var validPaginationStrategies = map[string]bool{
	"cursor":      true,
	"offset":      true,
	"page":        true,
	"link_header": true,
}

// validMethods lists the supported HTTP methods.
var validMethods = map[string]bool{
	"GET":    true,
	"POST":   true,
	"PUT":    true,
	"PATCH":  true,
	"DELETE": true,
	"HEAD":   true,
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
	if b.Type != "rest" {
		return fmt.Errorf("backend.type must be \"rest\", got %q", b.Type)
	}
	// base_url is optional in the DADL — can be provided via backends.yaml at runtime
	if b.Name == "" {
		return fmt.Errorf("backend.name must not be empty")
	}

	// Validate auth
	if b.Auth.Type != "" {
		if !validAuthTypes[b.Auth.Type] {
			return fmt.Errorf("auth.type must be one of bearer, oauth2, session, apikey, basic; got %q", b.Auth.Type)
		}
	}

	// Validate default pagination
	if b.Defaults.Pagination != nil {
		if err := validatePagination(b.Defaults.Pagination, "defaults.pagination"); err != nil {
			return err
		}
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
		if param.In != "" && param.In != "path" {
			return fmt.Errorf("tool %q: parameter %q is used in path but declared as in=%q", name, paramName, param.In)
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
