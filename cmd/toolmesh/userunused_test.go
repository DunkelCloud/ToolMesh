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

package main

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
)

// Fixtures of the test of stored values that are not used.
const (
	unBackend = "post"
	unTracker = "tracker"
	unLogin   = "post_login"
	unScope   = "post_scope"
	unOldPin  = "post_old_pin"
	unToken   = "tracker_token" //nolint:gosec // credential name, not a credential
	unAlice   = "alice"
	unBob     = "bob"
)

// TestUnusedUserValues pins what the check after a load reports: values
// users hold under a name a backend with user credentials does not ask
// for. That is how an operator learns that the limits users stored are no
// longer applied after the entry of the limit was renamed or removed.
func TestUnusedUserValues(t *testing.T) {
	ctx := context.Background()
	store, err := credentials.NewFileUserStore(t.TempDir(), bytes.Repeat([]byte{4}, credentials.UserCredentialsKeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	put := func(user, backendName, name string) {
		t.Helper()
		slot := credentials.UserSlot{UserID: user, Backend: backendName, Account: user + "@example.com", Name: name}
		if err := store.PutUser(ctx, slot, "v"); err != nil {
			t.Fatal(err)
		}
	}
	put(unAlice, unBackend, unLogin)
	put(unAlice, unBackend, unScope)
	put(unBob, unBackend, unLogin)
	put(unBob, unBackend, unScope)
	put(unBob, unBackend, unOldPin)
	put(unBob, unTracker, unToken)
	put(unBob, "gone", "gone_token")

	cases := []struct {
		name     string
		declared map[string][]string
		want     map[string][]string
	}{
		{
			"everything stored is asked for",
			map[string][]string{unBackend: {unLogin, "POST_SCOPE", unOldPin}, unTracker: {unToken}},
			map[string][]string{},
		},
		{
			"the entry of the limit is gone",
			map[string][]string{unBackend: {unLogin, unOldPin}, unTracker: {unToken}},
			map[string][]string{unBackend: {unScope}},
		},
		{
			"the entry of the limit was renamed",
			map[string][]string{unBackend: {unLogin, "post_limit"}},
			map[string][]string{unBackend: {unOldPin, unScope}},
		},
		{
			"no backend with user credentials",
			map[string][]string{},
			map[string][]string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := unusedUserValues(ctx, store, c.declared)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("unused values = %v, want %v", got, c.want)
			}
		})
	}
}
