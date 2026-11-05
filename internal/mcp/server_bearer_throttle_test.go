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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/auth"
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
	cfg.APIKeyMaxFailuresPerIP = 3
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	const attacker, other = "203.0.113.50:4000", "203.0.113.51:4000"

	for i := 0; i < cfg.APIKeyMaxFailuresPerIP; i++ {
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

// TestBearer_ConcurrentGuessesReserveSlots pins that the throttle reserves a
// slot before the credential is checked: a burst of concurrent guesses from
// one address gets no more verdicts than the limit allows, whether the
// counters live in Redis or in process memory.
func TestBearer_ConcurrentGuessesReserveSlots(t *testing.T) {
	for _, local := range []bool{false, true} {
		t.Run(fmt.Sprintf("localThrottle=%v", local), func(t *testing.T) {
			cfg := loginTestConfig()
			cfg.APIKey = testLoginAPIKey
			cfg.APIKeyMaxFailuresPerIP = 3
			ts := newLoginTestServer(t, cfg, loginTestOptions{localThrottle: local})
			const attacker = "203.0.113.50:4000"
			const n = 200
			codes := make([]int, n)
			var wg sync.WaitGroup
			start := make(chan struct{})
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					codes[i] = ts.mcpCallFrom(attacker, fmt.Sprintf("Bearer guess-%d", i)).Code
				}(i)
			}
			close(start)
			wg.Wait()
			verified := 0
			for _, c := range codes {
				switch c {
				case http.StatusUnauthorized:
					verified++
				case http.StatusTooManyRequests:
				default:
					t.Errorf("unexpected status %d", c)
				}
			}
			if verified > cfg.APIKeyMaxFailuresPerIP {
				t.Errorf("%d of %d concurrent guesses were checked, limit %d", verified, n, cfg.APIKeyMaxFailuresPerIP)
			}
		})
	}
}

// TestBearer_TokenShapedValuesReserveBeforeBcrypt pins that a value shaped
// like an issued access token, which reserves no slot up front, takes one
// before it costs bcrypt comparisons against key_hash-only entries. Once the
// address is throttled such a value skips the comparison and is answered
// 401 (a client holding an expired token can still refresh it).
func TestBearer_TokenShapedValuesReserveBeforeBcrypt(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKeyMaxFailuresPerIP = 3
	limiter := auth.NewCompareLimiter(1)
	ts := newLoginTestServer(t, cfg, loginTestOptions{apiKeys: []string{"tm_bcrypt_only_key"}, limiter: limiter})

	// Each of these costs a bcrypt comparison against the unseen entry and
	// is charged to the address.
	for i := 0; i < cfg.APIKeyMaxFailuresPerIP; i++ {
		if w := ts.mcpCall("Bearer " + generateID()); w.Code != http.StatusUnauthorized {
			t.Fatalf("token-shaped value %d: status %d, want 401", i+1, w.Code)
		}
	}
	// The address is used up: the next token-shaped value must not reach
	// the bcrypt stage, and is still answered 401, not 429.
	release := holdCompareSlots(t, limiter)
	if w := ts.mcpCallNoComparison(t, "Bearer "+generateID()); w.Code != http.StatusUnauthorized {
		t.Errorf("token-shaped value from a throttled address: status %d, want 401", w.Code)
	}
	release()
	// Other values from that address are refused outright.
	if w := ts.mcpCall("Bearer tm_bcrypt_only_key"); w.Code != http.StatusTooManyRequests {
		t.Errorf("API key from a throttled address: status %d, want 429", w.Code)
	}
}
