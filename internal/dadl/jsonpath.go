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
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// JSONPath implements the dialect pinned in DADL spec §9.4: an RFC 9535
// subset of root, name selectors (dot notation), index selectors including
// negative, and the wildcard selector. Descendant segments, slices, and
// filters are outside the dialect and rejected by the parser.
// Supports: $.field, $.field.nested, $.field[0], $.data[-1], $[*].secret,
// $.data[*].id, $.settings.*.
type JSONPath struct {
	segments []pathSegment
}

type pathSegment struct {
	field    string
	index    *int // nil = no index, non-nil = array index (negative = from end)
	wildcard bool // [*] or .* — selects every child of the current node
}

// NewJSONPath parses a JSONPath expression in the §9.4 dialect
// (e.g. "$.data", "$.items[0].id", "$.data[-1]", "$[*].secret").
func NewJSONPath(expr string) (*JSONPath, error) {
	if expr == "" {
		return nil, fmt.Errorf("empty jsonpath expression")
	}

	// Strip leading "$." or "$"
	path := expr
	if strings.HasPrefix(path, "$.") {
		path = path[2:]
	} else if strings.HasPrefix(path, "$") {
		path = path[1:]
	}

	if path == "" {
		return &JSONPath{}, nil // root
	}

	parts := strings.Split(path, ".")
	segments := make([]pathSegment, 0, len(parts))
	for _, part := range parts {
		seg, err := parseSegment(part)
		if err != nil {
			return nil, fmt.Errorf("parse segment %q: %w", part, err)
		}
		segments = append(segments, seg)
	}
	return &JSONPath{segments: segments}, nil
}

func parseSegment(s string) (pathSegment, error) {
	if s == "" {
		// A ".." in the expression: descendant segments are outside the
		// §9.4 dialect — reject instead of silently misreading the path.
		return pathSegment{}, fmt.Errorf("empty segment (descendant segments are not part of the DADL JSONPath dialect)")
	}
	bracketIdx := strings.Index(s, "[")
	if bracketIdx < 0 {
		// RFC 9535 wildcard shorthand ".*"; a literal member named "*"
		// would need quoted bracket notation, which the dialect omits.
		if s == "*" {
			return pathSegment{wildcard: true}, nil
		}
		return pathSegment{field: s}, nil
	}

	field := s[:bracketIdx]
	rest := s[bracketIdx:]

	if !strings.HasSuffix(rest, "]") {
		return pathSegment{}, fmt.Errorf("unclosed bracket in %q", s)
	}
	idxStr := rest[1 : len(rest)-1]
	if idxStr == "*" {
		return pathSegment{field: field, wildcard: true}, nil
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		return pathSegment{}, fmt.Errorf("invalid array index %q: %w", idxStr, err)
	}
	return pathSegment{field: field, index: &idx}, nil
}

// hasWildcard reports whether any segment selects every child.
func (jp *JSONPath) hasWildcard() bool {
	for _, seg := range jp.segments {
		if seg.wildcard {
			return true
		}
	}
	return false
}

// Extract applies the JSONPath to parsed JSON data and returns the matched
// value. A path without wildcards returns the single matched node, or an
// error when the path is absent (pre-wildcard behavior, unchanged). A path
// with wildcards returns the RFC 9535 nodelist as []any — branches that do
// not match are skipped, never an error — so an empty result is possible.
func (jp *JSONPath) Extract(data any) (any, error) {
	if jp.hasWildcard() {
		return collectNodes(data, jp.segments), nil
	}

	current := data
	for _, seg := range jp.segments {
		if seg.field != "" {
			m, ok := current.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("expected object at %q, got %T", seg.field, current)
			}
			val, exists := m[seg.field]
			if !exists {
				return nil, fmt.Errorf("field %q not found", seg.field)
			}
			current = val
		}

		if seg.index != nil {
			arr, ok := current.([]any)
			if !ok {
				return nil, fmt.Errorf("expected array for index [%d], got %T", *seg.index, current)
			}
			idx := *seg.index
			if idx < 0 {
				idx = len(arr) + idx
			}
			if idx < 0 || idx >= len(arr) {
				return nil, fmt.Errorf("array index %d out of bounds (len=%d)", *seg.index, len(arr))
			}
			current = arr[idx]
		}
	}
	return current, nil
}

// collectNodes gathers every node the segments select, RFC 9535
// nodelist-style: non-matching branches drop out silently.
func collectNodes(data any, segs []pathSegment) []any {
	if len(segs) == 0 {
		return []any{data}
	}
	seg, rest := segs[0], segs[1:]

	current := data
	if seg.field != "" {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		val, exists := m[seg.field]
		if !exists {
			return nil
		}
		current = val
	}

	switch {
	case seg.wildcard:
		var out []any
		switch v := current.(type) {
		case []any:
			for _, item := range v {
				out = append(out, collectNodes(item, rest)...)
			}
		case map[string]any:
			for _, key := range sortedKeys(v) {
				out = append(out, collectNodes(v[key], rest)...)
			}
		}
		return out
	case seg.index != nil:
		arr, ok := current.([]any)
		if !ok {
			return nil
		}
		idx := *seg.index
		if idx < 0 {
			idx = len(arr) + idx
		}
		if idx < 0 || idx >= len(arr) {
			return nil
		}
		return collectNodes(arr[idx], rest)
	default:
		return collectNodes(current, rest)
	}
}

// sortedKeys returns map keys in sorted order so wildcard-over-object
// results are deterministic.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ExtractResult applies a JSONPath expression string to JSON data bytes.
func ExtractResult(body []byte, resultPath string) ([]byte, error) {
	if resultPath == "" {
		return body, nil
	}

	jp, err := NewJSONPath(resultPath)
	if err != nil {
		return nil, fmt.Errorf("parse result_path: %w", err)
	}

	var data any
	if err := jsonUnmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}

	result, err := jp.Extract(data)
	if err != nil {
		return nil, fmt.Errorf("extract result_path %q: %w", resultPath, err)
	}

	return jsonMarshal(result)
}
