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

package audit

import (
	"testing"
)

func TestRegistry_SQLiteFactory(t *testing.T) {
	store, err := New("sqlite", map[string]string{
		"data_dir":       t.TempDir(),
		"retention_days": "7",
	})
	if err != nil {
		t.Fatalf("New sqlite: %v", err)
	}
	if store == nil {
		t.Fatal("nil store")
	}
	if s, ok := store.(*SQLiteStore); ok {
		t.Cleanup(func() { _ = s.Close() })
	}

	// Invalid retention days is silently ignored.
	store2, err := New("sqlite", map[string]string{
		"data_dir":       t.TempDir(),
		"retention_days": "not-a-number",
	})
	if err != nil {
		t.Fatalf("New with bad retention: %v", err)
	}
	if store2 == nil {
		t.Fatal("nil store2")
	}
	if s, ok := store2.(*SQLiteStore); ok {
		t.Cleanup(func() { _ = s.Close() })
	}
}

func TestRegistry_DuplicateRegisterPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate Register")
		}
	}()
	Register("sqlite", nil)
}
