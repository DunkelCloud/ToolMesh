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
