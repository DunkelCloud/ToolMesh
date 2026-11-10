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

// TestValidateRequiredParams covers the open-set variant: an undeclared
// argument passes, a missing required one does not.
func TestValidateRequiredParams(t *testing.T) {
	t.Run("undeclared argument passes", func(t *testing.T) {
		params := map[string]any{testParamQuery: "x", testParamTimeRange: map[string]any{}, testParamRange: 14400}
		if err := ValidateRequiredParams("search", searchParams(), params); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("missing required is still reported", func(t *testing.T) {
		params := map[string]any{testParamQuery: "x", testParamRange: 14400}
		err := ValidateRequiredParams("search", searchParams(), params)
		var perr *ParamError
		if !errors.As(err, &perr) {
			t.Fatalf("expected a ParamError, got %v", err)
		}
		if len(perr.Unknown) != 0 {
			t.Errorf("unknown = %v, want none", perr.Unknown)
		}
		if len(perr.MissingRequired) != 1 || perr.MissingRequired[0] != testParamTimeRange {
			t.Errorf("missing = %v, want [%s]", perr.MissingRequired, testParamTimeRange)
		}
	})
}
