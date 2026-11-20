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
	"testing"
)

// TestBearer_LockoutBehindUnlistedProxyIsNamed pins what the log says when
// a reverse proxy is missing from TOOLMESH_TRUSTED_PROXIES and the limit on
// failed API keys strikes: every client behind the proxy is counted under
// its address, so a few wrong keys from anyone lock out the client with the
// right one. The log names that cause when it happens, once and not per
// refused request, and stays quiet when the refused requests carry no
// X-Forwarded-For.
func TestBearer_LockoutBehindUnlistedProxyIsNamed(t *testing.T) {
	cfg := loginTestConfig()
	cfg.APIKey = testLoginAPIKey
	cfg.APIKeyMaxFailuresPerIP = 3
	ts := newLoginTestServer(t, cfg, loginTestOptions{})
	const proxy, direct = "172.18.0.1:4000", "203.0.113.60:4000"

	call := func(remote, authorization, forwardedFor string) int {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", authorization)
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		ts.mux.ServeHTTP(w, req)
		return w.Code
	}

	// Wrong keys from different clients, all arriving through the proxy.
	for i := range cfg.APIKeyMaxFailuresPerIP {
		if code := call(proxy, fmt.Sprintf("Bearer guess-%d", i), fmt.Sprintf("198.51.100.%d", i+1)); code != http.StatusUnauthorized {
			t.Fatalf("guess %d: status %d, want 401", i+1, code)
		}
	}
	if n := len(ts.logs.lines(t, msgLimitBehindUnlistedProxy)); n != 0 {
		t.Fatalf("the warning was logged %d times before any request was refused", n)
	}
	// The client with the right key shares the proxy's address and its limit.
	for range 5 {
		if code := call(proxy, "Bearer "+testLoginAPIKey, "198.51.100.99"); code != http.StatusTooManyRequests {
			t.Fatalf("right key behind the proxy: status %d, want 429", code)
		}
	}
	lines := ts.logs.lines(t, msgLimitBehindUnlistedProxy)
	if len(lines) != 1 {
		t.Fatalf("the warning was logged %d times, want once", len(lines))
	}
	if lines[0]["level"] != testLogLevelWarn || lines[0][logKeyRemote] != "172.18.0.1" || lines[0]["limit"] != "failed API keys" {
		t.Errorf("warning = %v, want WARN with the proxy's address and the limit", lines[0])
	}

	// A client that connects directly and sends no header is refused too,
	// without the warning: nothing says a proxy is involved.
	ts.srv.unlistedProxyWarned.Store(0)
	for i := range cfg.APIKeyMaxFailuresPerIP {
		call(direct, fmt.Sprintf("Bearer direct-guess-%d", i), "")
	}
	if code := call(direct, "Bearer "+testLoginAPIKey, ""); code != http.StatusTooManyRequests {
		t.Fatalf("direct client over the limit: status %d, want 429", code)
	}
	if n := len(ts.logs.lines(t, msgLimitBehindUnlistedProxy)); n != 1 {
		t.Errorf("a lockout without X-Forwarded-For logged the warning (%d lines)", n)
	}
}
