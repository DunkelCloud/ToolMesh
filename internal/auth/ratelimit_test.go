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
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestDCRRateLimiter(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	rl := NewDCRRateLimiter(rdb)
	ctx := context.Background()
	ip := "192.168.1.100"

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		allowed, err := rl.Allow(ctx, ip)
		if err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
		if !allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	allowed, err := rl.Allow(ctx, ip)
	if err != nil {
		t.Fatalf("request 6: %v", err)
	}
	if allowed {
		t.Error("request 6 should be denied (rate limit exceeded)")
	}

	// Different IP should still be allowed
	allowed, err = rl.Allow(ctx, "10.0.0.1")
	if err != nil {
		t.Fatalf("different IP: %v", err)
	}
	if !allowed {
		t.Error("different IP should be allowed")
	}
}

func TestLocalDCRRateLimiter(t *testing.T) {
	rl := NewLocalDCRRateLimiter()
	now := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return now }
	ctx := context.Background()

	for i := 0; i < dcrRateLimit; i++ {
		if ok, err := rl.Allow(ctx, "203.0.113.9"); err != nil || !ok {
			t.Fatalf("registration %d refused (%v)", i+1, err)
		}
	}
	if ok, _ := rl.Allow(ctx, "203.0.113.9"); ok {
		t.Error("registration over the limit allowed")
	}
	if ok, _ := rl.Allow(ctx, "198.51.100.1"); !ok {
		t.Error("another address must have its own limit")
	}

	// One IPv6 /64 counts as one address.
	for i := 0; i < dcrRateLimit; i++ {
		_, _ = rl.Allow(ctx, fmt.Sprintf("2001:db8:1:2::%x", i+1))
	}
	if ok, _ := rl.Allow(ctx, "2001:db8:1:2::ffff"); ok {
		t.Error("a fresh address in the same /64 escaped the limit")
	}

	now = now.Add(dcrRateWindow)
	if ok, _ := rl.Allow(ctx, "203.0.113.9"); !ok {
		t.Error("the limit must reset after the window")
	}
}

func TestLocalDCRRateLimiter_TableIsBounded(t *testing.T) {
	rl := NewLocalDCRRateLimiter()
	now := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return now }
	for i := 0; i < maxLocalDCRWindows+10; i++ {
		_, _ = rl.Allow(context.Background(), fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if n := len(rl.local); n > maxLocalDCRWindows {
		t.Errorf("table holds %d windows, cap is %d", n, maxLocalDCRWindows)
	}
}

// TestDCRRateLimiter_RedisCountsIPv6Per64 pins that the Redis-backed limit
// counts like the local one: a fresh address in the same /64 is no new
// client.
func TestDCRRateLimiter_RedisCountsIPv6Per64(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	rl := NewDCRRateLimiter(rdb)
	ctx := context.Background()
	for i := 0; i < dcrRateLimit; i++ {
		if ok, err := rl.Allow(ctx, fmt.Sprintf("2001:db8:5:6::%x", i+1)); err != nil || !ok {
			t.Fatalf("registration %d refused (%v)", i+1, err)
		}
	}
	if ok, _ := rl.Allow(ctx, "2001:db8:5:6::ffff"); ok {
		t.Error("a fresh address in the same /64 escaped the Redis-backed limit")
	}
}
