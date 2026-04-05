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

	"github.com/itchyny/gojq"
)

// maxJQOutputBytes is the maximum output size for jq transforms (M-21).
const maxJQOutputBytes = 10 * 1024 * 1024 // 10 MB

// maxJQResults is the maximum number of result items from a jq expression.
const maxJQResults = 100_000

// ApplyTransform runs a jq expression on JSON data and returns the result.
func ApplyTransform(data []byte, jqExpr string) ([]byte, error) {
	if jqExpr == "" {
		return data, nil
	}

	query, err := gojq.Parse(jqExpr)
	if err != nil {
		return nil, fmt.Errorf("parse jq expression %q: %w", jqExpr, err)
	}

	var input any
	if err := jsonUnmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse json input for jq: %w", err)
	}

	iter := query.Run(input)
	var results []any
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, isErr := v.(error); isErr {
			return nil, fmt.Errorf("jq execution error: %w", err)
		}
		results = append(results, v)
		if len(results) > maxJQResults {
			return nil, fmt.Errorf("jq output exceeded maximum result count (%d)", maxJQResults)
		}
	}

	// If single result, return it directly; otherwise return array
	var out []byte
	if len(results) == 1 {
		out, err = jsonMarshal(results[0])
	} else {
		out, err = jsonMarshal(results)
	}
	if err != nil {
		return nil, err
	}
	if len(out) > maxJQOutputBytes {
		return nil, fmt.Errorf("jq output exceeded maximum size (%d bytes)", maxJQOutputBytes)
	}
	return out, nil
}
