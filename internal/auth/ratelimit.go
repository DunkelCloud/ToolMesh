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
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	prefixDCRRate = "oauth:dcr:ratelimit:"
	dcrRateLimit  = 5
	dcrRateWindow = time.Hour
)

// DCRRateLimiter enforces per-IP rate limits on Dynamic Client Registration.
type DCRRateLimiter struct {
	rdb *redis.Client
}

// NewDCRRateLimiter creates a new DCR rate limiter.
func NewDCRRateLimiter(rdb *redis.Client) *DCRRateLimiter {
	return &DCRRateLimiter{rdb: rdb}
}

// Allow checks if the given IP is allowed to perform another DCR registration.
// Returns true if allowed, false if the rate limit is exceeded.
func (rl *DCRRateLimiter) Allow(ctx context.Context, ip string) (bool, error) {
	key := prefixDCRRate + ip

	pipe := rl.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, dcrRateWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("dcr rate limit check: %w", err)
	}

	count := incrCmd.Val()
	return count <= int64(dcrRateLimit), nil
}
