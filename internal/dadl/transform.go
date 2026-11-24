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

// Response fields whose expressions an ExpressionError names.
const (
	FieldResultPath = "result_path"
	FieldTransform  = "transform"
)

// ExpressionError reports a response.result_path or response.transform that
// cannot be parsed or compiled. Unlike every other failure of the response
// pipeline it does not depend on the response: the expression fails on every
// input, so the tool can never produce the result its DADL declares.
type ExpressionError struct {
	Field string // FieldResultPath or FieldTransform
	Err   error
}

// Error names the field and why its expression is invalid.
func (e *ExpressionError) Error() string {
	return fmt.Sprintf("response.%s is invalid: %v", e.Field, e.Err)
}

// Unwrap returns the parser's or compiler's error.
func (e *ExpressionError) Unwrap() error { return e.Err }

// CompileTransform parses and compiles a jq expression. A failure is an
// *ExpressionError. Compiling resolves function names and arities, so a call
// of an undefined function fails here rather than on the first response.
func CompileTransform(jqExpr string) (*gojq.Code, error) {
	query, err := gojq.Parse(jqExpr)
	if err != nil {
		return nil, &ExpressionError{Field: FieldTransform, Err: fmt.Errorf("parse jq expression: %w", err)}
	}
	code, err := gojq.Compile(query)
	if err != nil {
		return nil, &ExpressionError{Field: FieldTransform, Err: fmt.Errorf("compile jq expression: %w", err)}
	}
	return code, nil
}

// CheckResponseExpressions reports the first expression of rc that cannot be
// parsed or compiled, as an *ExpressionError, or nil when rc is nil or both
// its result_path and transform are valid. It looks at the expressions only,
// so it can run when a DADL is loaded, before any response exists.
func CheckResponseExpressions(rc *ResponseConfig) error {
	if rc == nil {
		return nil
	}
	if rc.ResultPath != "" {
		if _, err := NewJSONPath(rc.ResultPath); err != nil {
			return &ExpressionError{Field: FieldResultPath, Err: fmt.Errorf("parse %q: %w", rc.ResultPath, err)}
		}
	}
	if rc.Transform != "" {
		if _, err := CompileTransform(rc.Transform); err != nil {
			return err
		}
	}
	return nil
}

// ApplyTransform runs a jq expression on JSON data and returns the result.
// An expression that cannot be parsed or compiled is an *ExpressionError;
// every other error depends on the data.
func ApplyTransform(data []byte, jqExpr string) ([]byte, error) {
	if jqExpr == "" {
		return data, nil
	}

	code, err := CompileTransform(jqExpr)
	if err != nil {
		return nil, err
	}

	var input any
	if err := jsonUnmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("parse json input for jq: %w", err)
	}

	iter := code.Run(input)
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
