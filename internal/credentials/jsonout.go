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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// parseJSONOutput reads credentials from a command's JSON output, such as
// `vault kv get -format=json` or `bao kv get -format=json`:
//
//   - path selects the object that holds them, for example data.data for a
//     KV version 2 secret of Vault or OpenBao, or data for version 1. An
//     empty path selects the top level. Everything outside the selected
//     object, such as Vault's request and lease metadata, is ignored.
//   - Below it, nested objects are flattened: every string, number and
//     boolean becomes a key named after its own member name, however deep it
//     sits. Numbers keep their written form. null values and arrays are
//     skipped.
//   - Member names that become keys must be environment variable names and
//     must be unique after flattening; otherwise the output is refused.
//
// Errors name the path and member names, never values.
func parseJSONOutput(data []byte, path []string) (map[string]string, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, jsonSyntaxError(err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after the JSON value")
	}

	node := root
	for i, name := range path {
		obj, ok := node.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s is not a JSON object", jsonPathName(path[:i]))
		}
		next, ok := obj[name]
		if !ok {
			return nil, fmt.Errorf("%s not found", jsonPathName(path[:i+1]))
		}
		node = next
	}
	obj, ok := node.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", jsonPathName(path))
	}

	vars := make(map[string]string)
	origin := make(map[string]string)
	if err := flattenJSON(obj, strings.Join(path, "."), vars, origin); err != nil {
		return nil, err
	}
	return vars, nil
}

// flattenJSON adds the scalar members of obj and of every object nested in
// it to vars. origin records where each key came from, for the error on a
// duplicate. Members are visited in name order, so errors are stable.
func flattenJSON(obj map[string]any, at string, vars, origin map[string]string) error {
	names := make([]string, 0, len(obj))
	for name := range obj {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		member := name
		if at != "" {
			member = at + "." + name
		}
		var val string
		switch v := obj[name].(type) {
		case map[string]any:
			if err := flattenJSON(v, member, vars, origin); err != nil {
				return err
			}
			continue
		case string:
			val = v
		case json.Number:
			val = v.String()
		case bool:
			val = strconv.FormatBool(v)
		default: // null and arrays
			continue
		}
		if !validEnvName(name) {
			return fmt.Errorf("member %s: %q is not a valid variable name", member, name)
		}
		if prev, dup := origin[name]; dup {
			return fmt.Errorf("key %s appears twice after flattening (%s and %s)", name, prev, member)
		}
		vars[name] = val
		origin[name] = member
	}
	return nil
}

// jsonPathName describes a JSON path for an error message.
func jsonPathName(path []string) string {
	if len(path) == 0 {
		return "the top level"
	}
	return "path " + strings.Join(path, ".")
}

// jsonSyntaxError reports where the JSON broke without quoting it: the
// decoder's own message may contain a character of the output.
func jsonSyntaxError(err error) error {
	var syn *json.SyntaxError
	if errors.As(err, &syn) {
		return fmt.Errorf("output is not valid JSON (at byte %d)", syn.Offset)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errors.New("output is not valid JSON (it ends early)")
	}
	return errors.New("output is not valid JSON")
}
