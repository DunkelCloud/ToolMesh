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

	// A client revokes its tokens when a user signs out: a few requests per
	// session, also from the shared addresses of hosted clients. The limit
	// is far above that and still keeps one address from occupying the
	// token store with revocation requests.
	prefixRevokeRate = "oauth:revoke:ratelimit:"
	revokeRateLimit  = 60
	revokeRateWindow = time.Minute

	// maxLocalRateWindows caps the process-local table of one limiter.
	// Source addresses are attacker-chosen, so the table must not grow
	// without bound.
	maxLocalRateWindows = 50_000

	// rateLimitRedisTimeout bounds the counter operation in Redis, so a
	// Redis that does not answer delays a request by at most this much
	// before the process-local count decides.
	rateLimitRedisTimeout = time.Second
)

// AddressRateLimiter allows each client address a fixed number of requests
// per window. It counts in process memory in every case, and in Redis as
// well when created with a client: Redis decides while it answers, so the
// limit holds across replicas, and the process-local count decides when it
// does not, so an outage of Redis neither lifts the limit nor turns every
// client away.
type AddressRateLimiter struct {
	rdb    *redis.Client
	prefix string
	limit  int
	window time.Duration

	mu    sync.Mutex
	local map[string]rateWindow
	now   func() time.Time
}

// DCRRateLimiter is the AddressRateLimiter of Dynamic Client Registration.
type DCRRateLimiter = AddressRateLimiter

// rateWindow is one source address's requests in the current window.
type rateWindow struct {
	count   int
	resetAt time.Time
}

func newAddressRateLimiter(rdb *redis.Client, prefix string, limit int, window time.Duration) *AddressRateLimiter {
	return &AddressRateLimiter{
		rdb:    rdb,
		prefix: prefix,
		limit:  limit,
		window: window,
		local:  make(map[string]rateWindow),
		now:    time.Now,
	}
}

// NewDCRRateLimiter creates the rate limiter of Dynamic Client Registration
// backed by Redis.
func NewDCRRateLimiter(rdb *redis.Client) *DCRRateLimiter {
	return newAddressRateLimiter(rdb, prefixDCRRate, dcrRateLimit, dcrRateWindow)
}

// NewLocalDCRRateLimiter creates a DCR rate limiter that counts in process
// memory only, for deployments without Redis. The limit then applies per
// process.
func NewLocalDCRRateLimiter() *DCRRateLimiter {
	return NewDCRRateLimiter(nil)
}

// NewRevokeRateLimiter creates the rate limiter of token revocation. rdb may
// be nil, which keeps the count in process memory only.
func NewRevokeRateLimiter(rdb *redis.Client) *AddressRateLimiter {
	return newAddressRateLimiter(rdb, prefixRevokeRate, revokeRateLimit, revokeRateWindow)
}

// allowLocal counts one request from ip in process memory. An IPv6 address
// counts as its /64, like the login throttle's per-address limit.
func (rl *AddressRateLimiter) allowLocal(ip string) bool {
	key := normalizeLoginIP(ip)
	now := rl.now()
	rl.mu.Lock()
	defer rl.mu.Unlock()
	w, ok := rl.local[key]
	if !ok || !now.Before(w.resetAt) {
		if !ok && len(rl.local) >= maxLocalRateWindows {
			rl.evictLocked(now)
		}
		w = rateWindow{resetAt: now.Add(rl.window)}
	}
	w.count++
	rl.local[key] = w
	return w.count <= rl.limit
}

// evictLocked makes room in a full table: expired windows go first, then the
// one that ends soonest. Callers must hold rl.mu.
func (rl *AddressRateLimiter) evictLocked(now time.Time) {
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
	if len(rl.local) >= maxLocalRateWindows && oldestKey != "" {
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

// Allow counts one request from ip and reports whether it is within the
// limit.
//
// With Redis the verdict is Redis's. When Redis cannot be asked, the verdict
// is the process-local count's, and the error is returned with it for the
// caller to log: the request is then limited per process instead of across
// replicas, never without a limit. The local count sees every request of
// this process, so it does not start from zero when Redis fails.
func (rl *AddressRateLimiter) Allow(ctx context.Context, ip string) (bool, error) {
	local := rl.allowLocal(ip)
	if rl.rdb == nil {
		return local, nil
	}
	// Same unit as the process-local counters: an IPv6 address counts as
	// its /64.
	key := rl.prefix + normalizeLoginIP(ip)
	rctx, cancel := context.WithTimeout(ctx, rateLimitRedisTimeout)
	defer cancel()
	count, err := rateLimitScript.Run(rctx, rl.rdb, []string{key}, int(rl.window.Seconds())).Int64()
	if err != nil {
		return local, fmt.Errorf("rate limit check in redis: %w", err)
	}
	return count <= int64(rl.limit), nil
}
