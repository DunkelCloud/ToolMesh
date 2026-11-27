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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
)

// TestServer_StoreSwapWhileRequestsRun puts users.yaml and apikeys.yaml
// stores in force again and again while API keys, access tokens, refreshes
// and password logins are used. Every swap puts an equivalent store in force
// (same users, same password hash, same keys), so every request must
// succeed. Run with -race to check that a swap and a request in flight share
// no unguarded state.
func TestServer_StoreSwapWhileRequestsRun(t *testing.T) {
	const password = "pw-swap"
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{
		users:         map[string]string{refreshTestUser: password},
		apiKeys:       []string{testLoginAPIKey},
		apiKeyDigests: true,
	})
	hash := ts.srv.UserStore().Lookup(refreshTestUser).PasswordHash
	sum := sha256.Sum256([]byte(testLoginAPIKey))
	keysYAML := fmt.Sprintf("keys:\n  - user_id: %s\n    key_sha256: %s\n", testKitUserBob, hex.EncodeToString(sum[:]))
	equivalentUsers := func() *auth.UserStore { return writeUsers(t, map[string]string{refreshTestUser: hash}) }
	equivalentKeys := func() *auth.APIKeyStore {
		keys, err := auth.ParseAPIKeyStore([]byte(keysYAML), nil)
		if err != nil {
			t.Error(err)
		}
		return keys
	}
	// Built up front: t.Fatal and t.TempDir must not run in the swapper.
	userStores := []*auth.UserStore{equivalentUsers(), equivalentUsers()}
	keyStores := []*auth.APIKeyStore{equivalentKeys(), equivalentKeys()}

	// Two pairs: a refresh deletes the access token of its own pair.
	access, _ := ts.issuePair(t, refreshTestUser, nil)
	_, refresh := ts.issuePair(t, refreshTestUser, nil)

	var stop atomic.Bool
	var swapper sync.WaitGroup
	swapper.Go(func() {
		for i := 0; !stop.Load(); i++ {
			ts.srv.SetUserStore(userStores[i%2])
			ts.srv.SetAPIKeyStore(keyStores[i%2])
		}
	})

	const rounds = 40
	var failures atomic.Int64
	fail := func(format string, args ...any) {
		failures.Add(1)
		t.Errorf(format, args...)
	}
	var requests sync.WaitGroup
	requests.Go(func() {
		for range rounds {
			if w := ts.mcpCall("Bearer " + testLoginAPIKey); w.Code != http.StatusOK {
				fail("API key: status %d", w.Code)
			}
		}
	})
	requests.Go(func() {
		for range rounds {
			if w := ts.mcpCall("Bearer " + access); w.Code != http.StatusOK {
				fail("access token: status %d", w.Code)
			}
		}
	})
	requests.Go(func() {
		next := refresh
		for range rounds {
			w := ts.refreshGrant(next)
			if w.Code != http.StatusOK {
				fail("refresh: status %d, body %s", w.Code, w.Body.String())
				return
			}
			var resp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				fail("refresh response: %v", err)
				return
			}
			next, _ = resp[oauthRefreshToken].(string)
		}
	})
	requests.Go(func() {
		for range rounds / 4 {
			if w := ts.login(refreshTestUser, password, testLoginAddr); !isRedirectWithCode(w) {
				fail("login: status %d", w.Code)
			}
		}
	})
	requests.Wait()
	stop.Store(true)
	swapper.Wait()
	if failures.Load() > 0 {
		t.Logf("log:\n%s", ts.logs.String())
	}
}
