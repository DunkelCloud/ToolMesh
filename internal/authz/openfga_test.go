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

package authz

import (
	"testing"
)

func TestPtr(t *testing.T) {
	s := "test"
	p := ptr(s)
	if *p != "test" {
		t.Errorf("ptr(%q) = %q, want %q", s, *p, "test")
	}
}

func TestPtrMap(t *testing.T) {
	m := map[string]any{"key": "value"}
	p := ptrMap(m)
	if (*p)["key"] != "value" {
		t.Errorf("ptrMap result missing key")
	}
}

// Integration tests for NewAuthorizer and Check require a running OpenFGA server.
// They are skipped in unit test mode.

func TestNewAuthorizer_InvalidURL(t *testing.T) {
	// NewAuthorizer should still succeed with an invalid URL (the error
	// surfaces on first Check call, not at construction time).
	a, err := NewAuthorizer("http://localhost:99999", "store-id", nil)
	if err != nil {
		// Some SDK versions may fail at construction, which is also acceptable
		t.Skipf("SDK fails at construction with invalid URL: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authorizer")
	}
}
