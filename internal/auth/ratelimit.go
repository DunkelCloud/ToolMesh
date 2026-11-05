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

package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	prefixDCRRate = "oauth:dcr:ratelimit:"
	dcrRateLimit  = 5
	dcrRateWindow = time.Hour

	// maxLocalDCRWindows caps the process-local table. Source addresses are
	// attacker-chosen, so the table must not grow without bound.
	maxLocalDCRWindows = 50_000
)

// DCRRateLimiter enforces per-IP rate limits on Dynamic Client Registration.
// It counts in Redis when created with a client, so the limit holds across
// replicas, and in process memory otherwise (NewLocalDCRRateLimiter).
type DCRRateLimiter struct {
	rdb *redis.Client

	mu    sync.Mutex
	local map[string]dcrWindow
	now   func() time.Time
}

// dcrWindow is one source address's registrations in the current window.
type dcrWindow struct {
	count   int
	resetAt time.Time
}

// NewDCRRateLimiter creates a new DCR rate limiter backed by Redis.
func NewDCRRateLimiter(rdb *redis.Client) *DCRRateLimiter {
	return &DCRRateLimiter{rdb: rdb}
}

// NewLocalDCRRateLimiter creates a DCR rate limiter that counts in process
// memory, for deployments without Redis. The limit then applies per process.
func NewLocalDCRRateLimiter() *DCRRateLimiter {
	return &DCRRateLimiter{local: make(map[string]dcrWindow), now: time.Now}
}

// allowLocal counts one registration from ip in process memory. An IPv6
// address counts as its /64, like the login throttle's per-address limit.
func (rl *DCRRateLimiter) allowLocal(ip string) bool {
	key := normalizeLoginIP(ip)
	now := rl.now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	w, ok := rl.local[key]
	if !ok || !now.Before(w.resetAt) {
		if !ok && len(rl.local) >= maxLocalDCRWindows {
			rl.evictLocked(now)
		}
		w = dcrWindow{resetAt: now.Add(dcrRateWindow)}
	}
	w.count++
	rl.local[key] = w
	return w.count <= dcrRateLimit
}

// evictLocked makes room in a full table: expired windows go first, then the
// one that ends soonest. Callers must hold rl.mu.
func (rl *DCRRateLimiter) evictLocked(now time.Time) {
	var oldestKey string
	var oldest time.Time
	for k, w := range rl.local {
		if !now.Before(w.resetAt) {
			delete(rl.local, k)
			continue
		}
		if oldestKey == "" || w.resetAt.Before(oldest) {
			oldestKey, oldest = k, w.resetAt
		}
	}
	if len(rl.local) >= maxLocalDCRWindows && oldestKey != "" {
		delete(rl.local, oldestKey)
	}
}

// rateLimitScript atomically increments and sets TTL in a single round-trip.
// This prevents a crash between INCR and EXPIRE from leaving a key without TTL.
var rateLimitScript = redis.NewScript(`
	local count = redis.call("INCR", KEYS[1])
	if count == 1 then
		redis.call("EXPIRE", KEYS[1], ARGV[1])
	end
	return count
`)

// Allow checks if the given IP is allowed to perform another DCR registration.
// Returns true if allowed, false if the rate limit is exceeded.
func (rl *DCRRateLimiter) Allow(ctx context.Context, ip string) (bool, error) {
	if rl.rdb == nil {
		return rl.allowLocal(ip), nil
	}
	key := prefixDCRRate + ip
	windowSecs := int(dcrRateWindow.Seconds())

	count, err := rateLimitScript.Run(ctx, rl.rdb, []string{key}, windowSecs).Int64()
	if err != nil {
		return false, fmt.Errorf("dcr rate limit check: %w", err)
	}

	return count <= int64(dcrRateLimit), nil
}
