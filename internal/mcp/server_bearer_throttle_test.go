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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func (ts *loginTestServer) mcpCallFrom(remote, authorization string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authorization)
	req.RemoteAddr = remote
	w := httptest.NewRecorder()
	ts.mux.ServeHTTP(w, req)
	return w
}

// TestBearer_FailedAPIKeysAreThrottledPerAddress pins that guessing at API
// keys on /mcp is limited per client address like password logins, without
// locking out other addresses or issued access tokens.
func TestBearer_FailedAPIKeysAreThrottledPerAddress(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	cfg.LoginMaxFailuresPerIP = 3
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	const attacker, other = "203.0.113.50:4000", "203.0.113.51:4000"

	for i := 0; i < cfg.LoginMaxFailuresPerIP; i++ {
		if w := ts.mcpCallFrom(attacker, "Bearer guess-"+string(rune('a'+i))); w.Code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401", i+1, w.Code)
		}
	}
	w := ts.mcpCallFrom(attacker, "Bearer guess-z")
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("guess over the limit: status %d, Retry-After %q; want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	// Even the right key is refused from the throttled address ...
	if w := ts.mcpCallFrom(attacker, "Bearer "+testLoginAPIKey); w.Code != http.StatusTooManyRequests {
		t.Errorf("right key from a throttled address: status %d, want 429", w.Code)
	}
	// ... but works from another address.
	if w := ts.mcpCallFrom(other, "Bearer "+testLoginAPIKey); w.Code != http.StatusOK {
		t.Errorf("right key from another address: status %d, want 200", w.Code)
	}
	// Issued access tokens are not throttled: an unknown one still gets 401.
	if w := ts.mcpCallFrom(attacker, "Bearer "+generateID()); w.Code != http.StatusUnauthorized {
		t.Errorf("token-shaped bearer from a throttled address: status %d, want 401", w.Code)
	}
}
