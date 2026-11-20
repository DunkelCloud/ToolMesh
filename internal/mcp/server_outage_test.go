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
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
	"github.com/redis/go-redis/v9"
)

// redisLoading is the error a Redis gives every command while it loads its
// data after a start.
const redisLoading = "LOADING Redis is loading the dataset in memory"

// newOutageTestServer returns a login test server whose token store is the
// hybrid of its Redis and a file store, as ToolMesh runs with Redis. The
// registered client is stored through it, so both stores hold it.
func newOutageTestServer(t *testing.T) *loginTestServer {
	t.Helper()
	ts := newLoginTestServer(t, loginTestConfig(), loginTestOptions{})
	fs, err := auth.NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: ts.redis.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	hybrid := auth.NewHybridTokenStore(auth.NewRedisTokenStore(rdb), fs)
	ctx := context.Background()
	client, err := ts.srv.tokenStore.GetClient(ctx, ts.clientID)
	if err != nil {
		t.Fatal(err)
	}
	if err := hybrid.SaveClient(ctx, client); err != nil {
		t.Fatal(err)
	}
	ts.srv.tokenStore = hybrid
	return ts
}

// TestRefresh_DuringRedisOutage pins that a client that refreshes its
// tokens while Redis cannot be reached gets a new pair that works, during
// the outage and after it, and that the pair it gave up stays spent when
// Redis answers again with the copies it kept. A refresh that spent the
// refresh token and then failed to store the new pair would leave the
// client signed out for good.
func TestRefresh_DuringRedisOutage(t *testing.T) {
	ts := newOutageTestServer(t)
	const remote = "203.0.113.70:4000"
	oldAccess, oldRefresh := ts.issuePair(t, ts.srv.cfg.AuthUser, nil)

	ts.redis.SetError(redisLoading)
	w := ts.refreshGrant(oldRefresh)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh during the outage: status %d, body %s", w.Code, w.Body.String())
	}
	var pair struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&pair); err != nil || pair.Access == "" || pair.Refresh == "" {
		t.Fatalf("refresh during the outage returned no pair: %v %+v", err, pair)
	}
	if code := ts.mcpCallFrom(remote, authSchemeBearer+" "+pair.Access).Code; code != http.StatusOK {
		t.Errorf("new access token during the outage: status %d, want 200", code)
	}
	if code := ts.mcpCallFrom(remote, authSchemeBearer+" "+oldAccess).Code; code != http.StatusUnauthorized {
		t.Errorf("old access token during the outage: status %d, want 401", code)
	}

	ts.redis.SetError("")
	if code := ts.mcpCallFrom(remote, authSchemeBearer+" "+pair.Access).Code; code != http.StatusOK {
		t.Errorf("new access token after the outage: status %d, want 200", code)
	}
	if code := ts.mcpCallFrom(remote, authSchemeBearer+" "+oldAccess).Code; code != http.StatusUnauthorized {
		t.Errorf("old access token after the outage: status %d, want 401", code)
	}
	if code := ts.refreshGrant(oldRefresh).Code; code == http.StatusOK {
		t.Error("the refresh token spent during the outage was accepted again after it")
	}
	if code := ts.refreshGrant(pair.Refresh).Code; code != http.StatusOK {
		t.Errorf("the refresh token issued during the outage: status %d after it, want 200", code)
	}
}

// TestRegister_DuringRedisOutage pins that a client can register while
// Redis cannot be reached and is known afterwards, within the limit that
// holds during the outage.
func TestRegister_DuringRedisOutage(t *testing.T) {
	ts := newOutageTestServer(t)
	const redirect = "https://client.example.com/cb"

	ts.redis.SetError(redisLoading)
	w := registerClient(t, ts.mux, "outage client", redirect)
	if w.Code != http.StatusCreated {
		t.Fatalf("registration during the outage: status %d, body %s", w.Code, w.Body.String())
	}
	clientID := registeredClientID(t, w)

	ts.redis.SetError("")
	client, err := ts.srv.tokenStore.GetClient(context.Background(), clientID)
	if err != nil {
		t.Fatalf("the client registered during the outage is not known after it: %v", err)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != redirect {
		t.Errorf("client = %+v", client)
	}
}
