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
	"errors"
	"testing"
)

// TestExpressionErrorSeparatesDefectsFromData pins which pipeline failures
// are defects of the DADL (*ExpressionError) and which depend on the data:
// the adapter fails the call for the first kind and passes the body on for
// the second.
func TestExpressionErrorSeparatesDefectsFromData(t *testing.T) {
	tests := []struct {
		name       string
		run        func() error
		wantDefect bool
		wantField  string
	}{
		{name: "jq keyword as function name", wantDefect: true, wantField: FieldTransform,
			run: func() error { _, err := ApplyTransform([]byte(`{}`), "def label: .; label"); return err }},
		{name: "undefined jq function", wantDefect: true, wantField: FieldTransform,
			run: func() error { _, err := ApplyTransform([]byte(`{}`), "frobnicate"); return err }},
		{name: "unparsable result_path", wantDefect: true, wantField: FieldResultPath,
			run: func() error { _, err := ExtractResult([]byte(`{}`), "$.a[0"); return err }},
		{name: "jq runtime error", wantDefect: false,
			run: func() error { _, err := ApplyTransform([]byte(`null`), ".[] | .id"); return err }},
		{name: "jq on non-JSON", wantDefect: false,
			run: func() error { _, err := ApplyTransform([]byte(`plain text`), "."); return err }},
		{name: "result_path field absent", wantDefect: false,
			run: func() error { _, err := ExtractResult([]byte(`{"id": 1}`), "$.results"); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run()
			if err == nil {
				t.Fatal("expected an error")
			}
			var exprErr *ExpressionError
			if isDefect := errors.As(err, &exprErr); isDefect != tt.wantDefect {
				t.Fatalf("ExpressionError = %v, want %v (err: %v)", isDefect, tt.wantDefect, err)
			}
			if tt.wantDefect && exprErr.Field != tt.wantField {
				t.Errorf("field = %q, want %q", exprErr.Field, tt.wantField)
			}
		})
	}
}

func TestCheckResponseExpressions(t *testing.T) {
	tests := []struct {
		name    string
		rc      *ResponseConfig
		wantErr bool
	}{
		{name: "nil config", rc: nil},
		{name: "empty config", rc: &ResponseConfig{}},
		{name: "valid", rc: &ResponseConfig{ResultPath: "$.data", Transform: "map({id, name})"}},
		{name: "helper functions", rc: &ResponseConfig{Transform: "def nn: with_entries(select(.value != null)); map(nn)"}},
		{name: "invalid transform", rc: &ResponseConfig{Transform: "def label: .; label"}, wantErr: true},
		{name: "invalid result_path", rc: &ResponseConfig{ResultPath: "$..x"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckResponseExpressions(tt.rc)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			var exprErr *ExpressionError
			if err != nil && !errors.As(err, &exprErr) {
				t.Errorf("error %v is not an *ExpressionError", err)
			}
		})
	}
}
