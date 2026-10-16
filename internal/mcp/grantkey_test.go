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

package mcp

import (
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// Keys of one user without caller_id share the caller id but are bound to
// grants of kits each on its own; a key with a caller_id is bound by it.
func TestAPIKeyCaller_GrantKey(t *testing.T) {
	s := &Server{}
	a := s.apiKeyCaller(&auth.APIKeyEntry{UserID: testKitUserBob, KeySHA256: "aa"})
	b := s.apiKeyCaller(&auth.APIKeyEntry{UserID: testKitUserBob, KeyHash: "$2a$10$bob"})
	if a.CallerID != testKitUserBob || b.CallerID != testKitUserBob {
		t.Errorf("caller ids = %q, %q; want the user id, as before", a.CallerID, b.CallerID)
	}
	if a.GrantKey == "" || b.GrantKey == "" || a.GrantBinding() == b.GrantBinding() {
		t.Errorf("grant bindings = %q, %q; want one per key", a.GrantBinding(), b.GrantBinding())
	}
	named := s.apiKeyCaller(&auth.APIKeyEntry{UserID: testKitUserBob, KeySHA256: "aa", CallerID: "ci-runner"})
	if named.GrantKey != "" || named.GrantBinding() != "ci-runner" {
		t.Errorf("key with caller_id: grant key %q, binding %q; want the caller id", named.GrantKey, named.GrantBinding())
	}
}
