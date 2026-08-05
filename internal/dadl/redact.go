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

import "fmt"

// RedactedPlaceholder replaces every value matched by a response.redact
// path (DADL spec §9.3).
const RedactedPlaceholder = "[REDACTED]"

// RedactResult applies response.redact paths to a JSON response body
// (DADL spec §9.3): every value matched by a path is replaced with
// RedactedPlaceholder. A path that is valid but absent from the data is a
// no-op; a path the engine cannot parse is an error — the caller must fail
// the call rather than return unredacted data (§9.4). An empty path list
// returns the body unchanged.
func RedactResult(body []byte, paths []string) ([]byte, error) {
	if len(paths) == 0 {
		return body, nil
	}

	parsed := make([]*JSONPath, 0, len(paths))
	for _, p := range paths {
		jp, err := NewJSONPath(p)
		if err != nil {
			return nil, fmt.Errorf("parse redact path %q: %w", p, err)
		}
		parsed = append(parsed, jp)
	}

	var data any
	if err := jsonUnmarshal(body, &data); err != nil {
		return nil, fmt.Errorf("parse json for redact: %w", err)
	}

	for _, jp := range parsed {
		data = redactValue(data, jp.segments)
	}

	out, err := jsonMarshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal redacted result: %w", err)
	}
	return out, nil
}

// redactValue walks data along segs and replaces every matched node with
// RedactedPlaceholder, returning the (possibly replaced) value. Maps and
// slices are mutated in place; the return value matters for the root and
// for scalar replacement. Branches where the path does not apply are left
// untouched (§9.3: valid-but-absent is a no-op).
func redactValue(data any, segs []pathSegment) any {
	if len(segs) == 0 {
		return RedactedPlaceholder
	}
	seg, rest := segs[0], segs[1:]

	current := data
	if seg.field != "" {
		m, ok := current.(map[string]any)
		if !ok {
			return data
		}
		val, exists := m[seg.field]
		if !exists {
			return data
		}
		if seg.index == nil && !seg.wildcard {
			m[seg.field] = redactValue(val, rest)
			return data
		}
		m[seg.field] = redactSelected(val, seg, rest)
		return data
	}
	return redactSelected(current, seg, rest)
}

// redactSelected applies a bracket selector (wildcard or index) of seg to
// val and recurses with the remaining segments.
func redactSelected(val any, seg pathSegment, rest []pathSegment) any {
	if seg.wildcard {
		switch v := val.(type) {
		case []any:
			for i := range v {
				v[i] = redactValue(v[i], rest)
			}
		case map[string]any:
			for k := range v {
				v[k] = redactValue(v[k], rest)
			}
		}
		return val
	}
	if seg.index != nil {
		arr, ok := val.([]any)
		if !ok {
			return val
		}
		idx := *seg.index
		if idx < 0 {
			idx = len(arr) + idx
		}
		if idx < 0 || idx >= len(arr) {
			return val
		}
		arr[idx] = redactValue(arr[idx], rest)
		return val
	}
	// Plain name segment: already resolved by the caller.
	return redactValue(val, rest)
}
