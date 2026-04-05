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

func TestCredentialContext(t *testing.T) {
	ctx := context.Background()
	if got := CredentialsFromContext(ctx); got != nil {
		t.Errorf("expected nil, got %v", got)
	}

	creds := map[string]string{"KEY": "secret"}
	ctx = WithCredentials(ctx, creds)

	got := CredentialsFromContext(ctx)
	if got["KEY"] != "secret" {
		t.Errorf("got %v, want KEY=secret", got)
	}
}

func TestRegistry(t *testing.T) {
	// embedded registered via init; New should succeed
	store, err := New("embedded", nil)
	if err != nil {
		t.Fatalf("New(embedded): %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil store")
	}

	if _, err := New("nonexistent-store-type", nil); err == nil {
		t.Error("expected error for unknown store type")
	}

	names := Names()
	found := false
	for _, n := range names {
		if n == "embedded" {
			found = true
		}
	}
	if !found {
		t.Errorf("embedded not in Names(): %v", names)
	}
}

func TestRegister_Duplicate(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate Register")
		}
	}()
	Register("embedded", func(_ map[string]string) (CredentialStore, error) { return nil, nil })
}

func TestEmbeddedStore_ListByPrefix(t *testing.T) {
	t.Setenv("CREDENTIAL_GITHUB_TOKEN", "gh-token-value")
	t.Setenv("CREDENTIAL_GITHUB_API_KEY", "gh-apikey")
	t.Setenv("CREDENTIAL_OTHER_KEY", "other")

	store := NewEmbeddedStore()
	creds, err := store.ListByPrefix(context.Background(), "GITHUB_", TenantInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 2 {
		t.Errorf("got %d creds, want 2: %v", len(creds), creds)
	}
	if creds["GITHUB_TOKEN"] != "gh-token-value" {
		t.Errorf("GITHUB_TOKEN = %q", creds["GITHUB_TOKEN"])
	}
}
