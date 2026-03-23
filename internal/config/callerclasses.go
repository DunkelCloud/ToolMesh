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

package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// CallerClassUntrusted is the default caller class when no pattern matches.
const CallerClassUntrusted = "untrusted"

// CallerClasses maps CallerID patterns to trust classes.
type CallerClasses struct {
	Classes map[string][]string `yaml:"classes"` // class → list of CallerID patterns
}

// LoadCallerClasses loads caller-classes.yaml. Returns nil if the file doesn't exist.
func LoadCallerClasses(path string) (*CallerClasses, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read caller-classes config: %w", err)
	}

	var cc CallerClasses
	if err := yaml.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("parse caller-classes config: %w", err)
	}
	return &cc, nil
}

// Resolve finds the CallerClass for a given CallerID.
// Supports exact match and suffix-wildcard (e.g. "partner-*" matches "partner-acme").
// Default: "untrusted" when no pattern matches.
func (cc *CallerClasses) Resolve(callerID string) string {
	if cc == nil || callerID == "" {
		return CallerClassUntrusted
	}
	for class, patterns := range cc.Classes {
		for _, pattern := range patterns {
			if matchPattern(pattern, callerID) {
				return class
			}
		}
	}
	return CallerClassUntrusted
}

// matchPattern checks if callerID matches a pattern.
// Supports exact match and suffix-wildcard ("prefix*").
func matchPattern(pattern, callerID string) bool {
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(callerID, prefix)
	}
	return pattern == callerID
}
