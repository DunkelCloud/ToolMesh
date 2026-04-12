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

func TestRemappingStore_Get_Remapped(t *testing.T) {
	t.Setenv("MY_PROD_TOKEN", "secret-prod-value")

	delegate := NewEmbeddedStore()
	store := NewRemappingStore(delegate, map[string]string{ //nolint:gosec // test credential mapping, not real secrets
		"CREDENTIAL_ANTHROPIC_TOKEN": "MY_PROD_TOKEN",
	})

	val, err := store.Get(context.Background(), "ANTHROPIC_TOKEN", TenantInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "secret-prod-value" {
		t.Errorf("got %q, want %q", val, "secret-prod-value")
	}
}

func TestRemappingStore_Get_Delegates(t *testing.T) {
	t.Setenv("CREDENTIAL_OTHER_KEY", "delegate-value")

	delegate := NewEmbeddedStore()
	store := NewRemappingStore(delegate, map[string]string{ //nolint:gosec // test credential mapping, not real secrets
		"CREDENTIAL_ANTHROPIC_TOKEN": "MY_PROD_TOKEN",
	})

	// OTHER_KEY is not in the remap — should delegate to EmbeddedStore.
	val, err := store.Get(context.Background(), "OTHER_KEY", TenantInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if val != "delegate-value" {
		t.Errorf("got %q, want %q", val, "delegate-value")
	}
}

func TestRemappingStore_Get_EmptyRemapped(t *testing.T) {
	// Remapped env var is empty — should return error.
	t.Setenv("EMPTY_VAR", "")

	delegate := NewEmbeddedStore()
	store := NewRemappingStore(delegate, map[string]string{ //nolint:gosec // test credential mapping
		"CREDENTIAL_ANTHROPIC_TOKEN": "EMPTY_VAR",
	})

	_, err := store.Get(context.Background(), "ANTHROPIC_TOKEN", TenantInfo{})
	if err == nil {
		t.Fatal("expected error for empty remapped credential")
	}
}

func TestRemappingStore_ListByPrefix_MergesRemapped(t *testing.T) {
	t.Setenv("CREDENTIAL_GITHUB_TOKEN", "from-env")
	t.Setenv("CUSTOM_GH_SECRET", "from-remap")

	delegate := NewEmbeddedStore()
	store := NewRemappingStore(delegate, map[string]string{ //nolint:gosec // test credential mapping
		"CREDENTIAL_GITHUB_SECRET": "CUSTOM_GH_SECRET",
	})

	result, err := store.ListByPrefix(context.Background(), "GITHUB_", TenantInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should contain both the delegate result and the remapped one.
	if result["GITHUB_TOKEN"] != "from-env" {
		t.Errorf("GITHUB_TOKEN = %q, want %q", result["GITHUB_TOKEN"], "from-env")
	}
	if result["GITHUB_SECRET"] != "from-remap" {
		t.Errorf("GITHUB_SECRET = %q, want %q", result["GITHUB_SECRET"], "from-remap")
	}
}

func TestRemappingStore_Healthy(t *testing.T) {
	delegate := NewEmbeddedStore()
	store := NewRemappingStore(delegate, nil)

	if err := store.Healthy(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
