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

package backend

import (
	"testing"
)

func TestBackendRegistry(t *testing.T) {
	// "echo" is auto-registered via init().
	if _, err := NewBackend("echo", nil); err != nil {
		t.Errorf("NewBackend(echo): %v", err)
	}

	if _, err := NewBackend("nonexistent-xyz", nil); err == nil {
		t.Error("expected error for unknown backend")
	}

	names := BackendNames()
	found := false
	for _, n := range names {
		if n == "echo" {
			found = true
		}
	}
	if !found {
		t.Errorf("echo not in BackendNames: %v", names)
	}
}

func TestBackendRegistry_DuplicatePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate Register")
		}
	}()
	Register("echo", nil)
}
