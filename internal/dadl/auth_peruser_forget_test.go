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
	"strings"
	"testing"
)

// TestRestAuth_ForgetAccount_LeavesTheOtherAccounts pins that a changed
// account costs that account its session and nobody else theirs: not the
// other accounts of the same user, and not other users.
func TestRestAuth_ForgetAccount_LeavesTheOtherAccounts(t *testing.T) {
	api := newSessionAPI(t)
	store, users := puStores(t)
	puStore(t, users, puAlice, puAccount, "first")
	puStore(t, users, puAlice, puSecond, "second")
	puStore(t, users, puBob, puBobAcct, "bob")

	a := NewRestAuth(sessionConfig(puLogin), api.srv.URL, store, newQuietLogger())
	a.SetPerUser(puBackend, store)

	call := func(user, account, wantSecret string) {
		t.Helper()
		req, err := puInject(t, a, puCtx(user, account), api.srv.URL+puDataPath)
		if err != nil {
			t.Fatalf("%s/%s: %v", user, account, err)
		}
		if got := req.Header.Get(headerAuthorization); !strings.HasPrefix(got, "Bearer tok-"+wantSecret+"-") {
			t.Errorf("%s/%s: Authorization = %q, want the session of %q", user, account, got, wantSecret)
		}
	}
	logins := func(want int32, when string) {
		t.Helper()
		if got := api.logins.Load(); got != want {
			t.Errorf("logins %s = %d, want %d", when, got, want)
		}
	}

	call(puAlice, puAccount, "first")
	call(puAlice, puSecond, "second")
	call(puBob, puBobAcct, "bob")
	logins(3, "after the first call of each account")

	// Alice changes her first account. The label arrives as a caller may
	// write it, padded and in another case.
	puStore(t, users, puAlice, puAccount, "changed")
	a.ForgetAccount(puAlice, "  "+strings.ToUpper(puAccount)+" ")
	call(puAlice, puSecond, "second")
	call(puBob, puBobAcct, "bob")
	logins(3, "after forgetting one account: the other account and the other user")
	call(puAlice, puAccount, "changed")
	logins(4, "after the changed account's next call")

	// Forgetting what is not there changes nothing.
	a.ForgetAccount("nobody", puAccount)
	a.ForgetAccount(puAlice, "no-such-account")
	a.ForgetAccount(puAlice, "not a label")
	call(puAlice, puAccount, "changed")
	call(puAlice, puSecond, "second")
	logins(4, "after forgetting accounts that do not exist")
}
