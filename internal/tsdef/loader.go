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

package tsdef

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadDir reads all .ts files from a directory and parses them into ToolDefs.
// Returns an empty slice (not error) if the directory does not exist.
func LoadDir(dir string) ([]ToolDef, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read tools dir %s: %w", dir, err)
	}

	var all []ToolDef
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".ts" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path) //nolint:gosec // path from trusted config dir
		if err != nil {
			return nil, fmt.Errorf("read tool file %s: %w", path, err)
		}

		defs, err := ParseSource(string(data), entry.Name())
		if err != nil {
			return nil, fmt.Errorf("parse tool file %s: %w", path, err)
		}

		all = append(all, defs...)
	}

	return all, nil
}

// LoadRawTS reads all .ts files from a directory and returns their
// concatenated source code. This is served as-is for Code Mode list_tools.
func LoadRawTS(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read tools dir %s: %w", dir, err)
	}

	parts := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".ts" {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path) //nolint:gosec // path from trusted config dir
		if err != nil {
			return "", fmt.Errorf("read tool file %s: %w", path, err)
		}
		parts = append(parts, string(data))
	}

	return joinParts(parts), nil
}

func joinParts(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "\n"
		}
		result += p
	}
	return result
}
