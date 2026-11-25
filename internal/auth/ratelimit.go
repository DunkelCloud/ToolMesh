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

	// A request to the authorization endpoint that names a client by the
	// URL of its metadata document makes the server fetch that document,
	// before anyone has logged in. A person connecting a client causes one
	// or two fetches, and none while the document is cached. The limit
	// keeps one address from using the server to send requests to hosts of
	// its choice.
	prefixClientMetadataRate = "oauth:cimd:ratelimit:"
	clientMetadataRateLimit  = 10
	clientMetadataRateWindow = time.Minute

	// maxLocalRateWindows caps the process-local table of one limiter.
	// Source addresses are attacker-chosen, so the table must not grow
	// without bound.
	maxLocalRateWindows = 50_000

	// localEvictionBatch is how many windows a full table gives up at once.
	localEvictionBatch = maxLocalRateWindows / 16

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

// NewClientMetadataRateLimiter creates the rate limiter of the fetches of
// client ID metadata documents. rdb may be nil, which keeps the count in
// process memory only.
func NewClientMetadataRateLimiter(rdb *redis.Client) *AddressRateLimiter {
	return newAddressRateLimiter(rdb, prefixClientMetadataRate, clientMetadataRateLimit, clientMetadataRateWindow)
}

// Window returns the length of the window the limit counts in, which is
// also the longest a refused client has to wait.
func (rl *AddressRateLimiter) Window() time.Duration {
	return rl.window
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

// evictLocked makes room in a full table: expired windows go first, and
// when none has expired, a batch of windows goes, so that the next
// addresses do not each pay for a walk through the whole table. Which
// windows go is left to the order of the map. A table this full is a flood
// from tens of thousands of addresses, and an address that loses its window
// gets a fresh one. Callers must hold rl.mu.
func (rl *AddressRateLimiter) evictLocked(now time.Time) {
	for k, w := range rl.local {
		if !now.Before(w.resetAt) {
			delete(rl.local, k)
		}
	}
	if len(rl.local) < maxLocalRateWindows {
		return
	}
	batch := localEvictionBatch
	for k := range rl.local {
		if batch == 0 {
			break
		}
		delete(rl.local, k)
		batch--
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
// A request is allowed when neither count is over the limit. Redis counts
// the requests of all replicas; the process-local count sees every request
// of this process, also the ones Redis missed while it could not be asked.
// So an outage does not reset the count in either direction: it does not
// start from zero when Redis fails, and what was counted during the outage
// still counts when Redis answers again. When Redis cannot be asked, the
// local count alone decides, and the error is returned with the verdict
// for the caller to log.
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
	return local && count <= int64(rl.limit), nil
}
