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

	mr.SetError("LOADING Redis is loading the dataset in memory")
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

	// Redis is back and has counted only the requests before the outage.
	// What was counted here during the outage still counts.
	mr.SetError("")
	if ok, err := rl.Allow(ctx, addr); err != nil || ok {
		t.Errorf("request over the limit after the outage: allowed=%v err=%v, want refused", ok, err)
	}
}

// TestAddressRateLimiter_FullTableEvictsABatch pins that a full table makes
// room for more than one address at a time: each new address would
// otherwise walk the whole table.
func TestAddressRateLimiter_FullTableEvictsABatch(t *testing.T) {
	rl := NewLocalDCRRateLimiter()
	now := time.Unix(1_700_000_000, 0)
	rl.now = func() time.Time { return now }
	ctx := context.Background()
	for i := range maxLocalRateWindows {
		_, _ = rl.Allow(ctx, fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff))
	}
	if n := len(rl.local); n != maxLocalRateWindows {
		t.Fatalf("table holds %d windows, want it full at %d", n, maxLocalRateWindows)
	}
	_, _ = rl.Allow(ctx, "192.0.2.1")
	if n := len(rl.local); n != maxLocalRateWindows-localEvictionBatch+1 {
		t.Errorf("after one more address the table holds %d windows, want %d", n, maxLocalRateWindows-localEvictionBatch+1)
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

// TestClientMetadataRateLimiter pins the limit of the fetches of client ID
// metadata documents: counted per address, in process memory without Redis,
// and with a window short enough that a person who ran into it can go on
// soon.
func TestClientMetadataRateLimiter(t *testing.T) {
	rl := NewClientMetadataRateLimiter(nil)
	ctx := context.Background()
	for i := range clientMetadataRateLimit {
		if ok, err := rl.Allow(ctx, "203.0.113.40"); err != nil || !ok {
			t.Fatalf("fetch %d refused (%v)", i+1, err)
		}
	}
	if ok, _ := rl.Allow(ctx, "203.0.113.40"); ok {
		t.Error("fetch over the limit allowed")
	}
	if ok, _ := rl.Allow(ctx, "203.0.113.41"); !ok {
		t.Error("another address must have its own limit")
	}
	if rl.Window() > time.Minute {
		t.Errorf("window = %s, want a minute at most", rl.Window())
	}
}
