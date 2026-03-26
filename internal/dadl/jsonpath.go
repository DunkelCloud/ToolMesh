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
	"strconv"
	"strings"
)

// JSONPath provides minimal JSONPath extraction for dot-notation paths.
// Supports: $.field, $.field.nested, $.field[0], $.field[-1].
type JSONPath struct {
	segments []pathSegment
}

type pathSegment struct {
	field string
	index *int // nil = no index, non-nil = array index (negative = from end)
}

// NewJSONPath parses a JSONPath expression. Only dot-notation with optional
// array indices is supported (e.g. "$.data", "$.items[0].id", "$.data[-1]").
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
	bracketIdx := strings.Index(s, "[")
	if bracketIdx < 0 {
		return pathSegment{field: s}, nil
	}

	field := s[:bracketIdx]
	rest := s[bracketIdx:]

	if !strings.HasSuffix(rest, "]") {
		return pathSegment{}, fmt.Errorf("unclosed bracket in %q", s)
	}
	idxStr := rest[1 : len(rest)-1]
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		return pathSegment{}, fmt.Errorf("invalid array index %q: %w", idxStr, err)
	}
	return pathSegment{field: field, index: &idx}, nil
}

// Extract applies the JSONPath to parsed JSON data and returns the matched value.
func (jp *JSONPath) Extract(data any) (any, error) {
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
