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
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// TestRedisTokenStore_ConsumeTellsOutageFromNotFound pins that consuming a
// refresh token or an authorization code reports a Redis that cannot be
// asked as an error, not as "not found". After "not found" the entry is
// gone; after an error Redis still holds it, and the hybrid store must know
// the difference to keep a consumed entry consumed.
func TestRedisTokenStore_ConsumeTellsOutageFromNotFound(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisTokenStore(rdb)
	ctx := context.Background()

	ti := &TokenInfo{AccessToken: "redis-at", RefreshToken: "redis-rt", RefreshExpiresAt: time.Now().Add(time.Hour)}
	if err := store.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthCode(ctx, &AuthCode{Code: "redis-code"}); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ConsumeRefreshToken(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown refresh token: %v, want ErrNotFound", err)
	}
	if _, err := store.ConsumeAuthCode(ctx, "unknown"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown code: %v, want ErrNotFound", err)
	}

	mr.SetError("LOADING Redis is loading the dataset in memory")
	if _, err := store.ConsumeRefreshToken(ctx, ti.RefreshToken); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("refresh token while Redis fails: %v, want an error other than ErrNotFound", err)
	}
	if _, err := store.ConsumeAuthCode(ctx, "redis-code"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("code while Redis fails: %v, want an error other than ErrNotFound", err)
	}

	mr.SetError("")
	if got, err := store.ConsumeRefreshToken(ctx, ti.RefreshToken); err != nil || got.AccessToken != ti.AccessToken {
		t.Errorf("refresh token after the outage: %v, %v", got, err)
	}
	if _, err := store.ConsumeAuthCode(ctx, "redis-code"); err != nil {
		t.Errorf("code after the outage: %v", err)
	}
	if _, err := store.ConsumeRefreshToken(ctx, ti.RefreshToken); !errors.Is(err, ErrNotFound) {
		t.Errorf("a consumed refresh token: %v, want ErrNotFound", err)
	}
}
