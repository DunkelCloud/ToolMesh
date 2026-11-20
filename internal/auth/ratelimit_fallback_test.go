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
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestAddressRateLimiter_RedisOutage pins what a Redis-backed limiter does
// while Redis cannot be asked: it neither allows everything nor refuses
// everything. The count in process memory decides, the error comes back
// with the verdict, and that count includes the requests this process saw
// while Redis still answered.
func TestAddressRateLimiter_RedisOutage(t *testing.T) {
	const addr = "203.0.113.20"
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	rl := NewDCRRateLimiter(rdb)

	const before = 3
	for i := range before {
		if ok, err := rl.Allow(ctx, addr); err != nil || !ok {
			t.Fatalf("request %d with Redis up: allowed=%v err=%v", i+1, ok, err)
		}
	}

	mr.Close()
	for i := before; i < dcrRateLimit; i++ {
		ok, err := rl.Allow(ctx, addr)
		if err == nil {
			t.Fatalf("request %d: no error although Redis is down", i+1)
		}
		if !ok {
			t.Errorf("request %d within the limit was refused during the outage", i+1)
		}
	}
	if ok, err := rl.Allow(ctx, addr); ok || err == nil {
		t.Errorf("request over the limit during the outage: allowed=%v err=%v, want refused with the error", ok, err)
	}
	if ok, _ := rl.Allow(ctx, "198.51.100.20"); !ok {
		t.Error("another address must keep its own limit during the outage")
	}
}

// TestRevokeRateLimiter pins the limit of the revocation endpoint: more
// than a client needs, counted per address, in process memory without
// Redis.
func TestRevokeRateLimiter(t *testing.T) {
	rl := NewRevokeRateLimiter(nil)
	ctx := context.Background()
	for i := range revokeRateLimit {
		if ok, err := rl.Allow(ctx, "203.0.113.30"); err != nil || !ok {
			t.Fatalf("revocation %d refused (%v)", i+1, err)
		}
	}
	if ok, _ := rl.Allow(ctx, "203.0.113.30"); ok {
		t.Error("revocation over the limit allowed")
	}
	if ok, _ := rl.Allow(ctx, "203.0.113.31"); !ok {
		t.Error("another address must have its own limit")
	}
}
