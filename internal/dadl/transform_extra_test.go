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
	"strings"
	"testing"
)

func TestApplyTransform_JQExecutionError(t *testing.T) {
	// Division by zero or incompatible operation inside jq -> execution error.
	_, err := ApplyTransform([]byte(`{"a": "str"}`), ".a + 1")
	if err == nil {
		t.Fatal("expected execution error")
	}
	if !strings.Contains(err.Error(), "execution error") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestApplyTransform_InvalidJSON(t *testing.T) {
	_, err := ApplyTransform([]byte("not json"), ".")
	if err == nil {
		t.Fatal("expected json parse error")
	}
}

func TestApplyTransform_ResultCountLimit(t *testing.T) {
	// Build a large array in the input.
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < maxJQResults+10; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, "%d", i)
	}
	sb.WriteString("]")

	// .[] emits one result per element — exceeds the limit.
	_, err := ApplyTransform([]byte(sb.String()), ".[]")
	if err == nil {
		t.Fatal("expected result count error")
	}
	if !strings.Contains(err.Error(), "maximum result count") {
		t.Errorf("error = %q", err.Error())
	}
}
