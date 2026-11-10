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

package credentials

import (
	"context"
	"testing"
)

// TestStores_CanonicalCredentialKey pins that every credential store and
// the remapping name a credential's variable the same way, the way the
// credential binding compares names: CanonicalEnvKey(CREDENTIAL_<name>).
func TestStores_CanonicalCredentialKey(t *testing.T) {
	t.Setenv("CREDENTIAL_CANON_TOKEN", "embedded")
	command := &CommandStore{}
	command.set.Store(&commandSet{vars: map[string]string{"CREDENTIAL_CANON_TOKEN": "command", "MAPPED_CANON": "mapped"}})
	ctx := context.Background()

	for name, store := range map[string]CredentialStore{"embedded": NewEmbeddedStore(), "command": command} {
		for _, logical := range []string{"canon_token", "Canon_Token", "CANON_TOKEN"} {
			if v, err := store.Get(ctx, logical, TenantInfo{}); err != nil || v != name {
				t.Errorf("%s: Get(%q) = %q, %v", name, logical, v, err)
			}
		}
		lister, ok := store.(PrefixLister)
		if !ok {
			t.Fatalf("%s: no PrefixLister", name)
		}
		if got, err := lister.ListByPrefix(ctx, "canon", TenantInfo{}); err != nil || got["CANON_TOKEN"] != name {
			t.Errorf("%s: ListByPrefix = %v, %v", name, got, err)
		}
	}

	remap := NewRemappingStore(command, map[string]string{"credential_canon_token": "MAPPED_CANON"})
	if v, err := remap.Get(ctx, "Canon_Token", TenantInfo{}); err != nil || v != "mapped" {
		t.Errorf("remapping over the command store: Get = %q, %v", v, err)
	}
}
