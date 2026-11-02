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

const (
	testClientUnused = "unused"
	testClientUsed   = "used"
	testClientLegacy = "legacy"
)

func TestOAuthClient_Expired(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"no expiry", time.Time{}, false},
		{"in the future", now.Add(time.Minute), false},
		{"exactly now", now, true},
		{"in the past", now.Add(-time.Minute), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &OAuthClient{ExpiresAt: tt.expiresAt}
			if got := c.Expired(now); got != tt.want {
				t.Errorf("Expired = %v, want %v", got, tt.want)
			}
		})
	}
}

func newTestRedis(t *testing.T) (*RedisTokenStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRedisTokenStore(rdb), mr
}

func TestRedisTokenStore_ClientExpiry(t *testing.T) {
	s, mr := newTestRedis(t)
	ctx := context.Background()

	if err := s.SaveClient(ctx, &OAuthClient{ClientID: testClientLegacy}); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(prefixClient + testClientLegacy); ttl != 0 {
		t.Errorf("client without ExpiresAt has TTL %v, want none", ttl)
	}

	if err := s.SaveClient(ctx, &OAuthClient{ClientID: testClientUnused, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(prefixClient + testClientUnused); ttl <= 59*time.Minute || ttl > time.Hour {
		t.Errorf("TTL = %v, want about an hour", ttl)
	}

	mr.FastForward(61 * time.Minute)
	if _, err := s.GetClient(ctx, testClientUnused); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetClient after expiry: err = %v, want ErrNotFound", err)
	}
	if _, err := s.GetClient(ctx, testClientLegacy); err != nil {
		t.Errorf("client without ExpiresAt gone: %v", err)
	}

	// Saving a client that has already expired removes it.
	if err := s.SaveClient(ctx, &OAuthClient{ClientID: testClientLegacy, ExpiresAt: time.Now().Add(-time.Second)}); err != nil {
		t.Fatal(err)
	}
	if mr.Exists(prefixClient + testClientLegacy) {
		t.Error("expired client is still stored")
	}
}

func TestFileTokenStore_ClientExpiry(t *testing.T) {
	dir := t.TempDir()
	fs, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()

	clients := []*OAuthClient{
		{ClientID: testClientLegacy},
		{ClientID: testClientUnused, ExpiresAt: now.Add(-time.Minute)},
		{ClientID: testClientUsed, ExpiresAt: now.Add(time.Hour)},
	}
	for _, c := range clients {
		if err := fs.SaveClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	// An expired client is not handed out, even before Cleanup ran.
	if _, err := fs.GetClient(ctx, testClientUnused); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetClient(expired) err = %v, want ErrNotFound", err)
	}

	// A restart does not bring it back.
	reloaded, err := NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.clients[testClientUnused]; ok {
		t.Error("expired client restored from disk")
	}
	if _, ok := reloaded.clients[testClientUsed]; !ok {
		t.Error("live client not restored from disk")
	}

	// Cleanup removes it and persists the removal.
	fs.removeExpired(now)
	if _, ok := fs.clients[testClientUnused]; ok {
		t.Error("expired client still in memory after cleanup")
	}
	fs.removeExpired(now.Add(2 * time.Hour))
	if _, ok := fs.clients[testClientUsed]; ok {
		t.Error("client still in memory after its expiry")
	}
	if _, ok := fs.clients[testClientLegacy]; !ok {
		t.Error("client without ExpiresAt removed by cleanup")
	}
	reloaded, err = NewFileTokenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.clients) != 1 {
		t.Errorf("%d clients on disk after cleanup, want 1 (the one without expiry)", len(reloaded.clients))
	}
}

func TestExtendClient(t *testing.T) {
	ctx := context.Background()
	fs, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	redisStore, mr := newTestRedis(t)
	store := NewHybridTokenStore(redisStore, fs)

	soon := time.Now().Add(time.Hour)
	if err := store.SaveClient(ctx, &OAuthClient{ClientID: testClientUsed, ClientName: "Claude", ExpiresAt: soon}); err != nil {
		t.Fatal(err)
	}
	stored := fs.clients[testClientUsed]

	later := time.Now().Add(90 * 24 * time.Hour)
	if err := ExtendClient(ctx, store, testClientUsed, later); err != nil {
		t.Fatalf("ExtendClient: %v", err)
	}
	if ttl := mr.TTL(prefixClient + testClientUsed); ttl < 89*24*time.Hour {
		t.Errorf("Redis TTL after extension = %v, want about 90 days", ttl)
	}
	got, err := fs.GetClient(ctx, testClientUsed)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ExpiresAt.Equal(later) || got.ClientName != "Claude" {
		t.Errorf("file store client = %+v, want ExpiresAt %v and the name kept", got, later)
	}
	// The record the file store handed out earlier is not changed in place.
	if !stored.ExpiresAt.Equal(soon) {
		t.Error("ExtendClient changed the file store's record in place")
	}

	// A zero expiry keeps the client forever.
	if err := ExtendClient(ctx, store, testClientUsed, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(prefixClient + testClientUsed); ttl != 0 {
		t.Errorf("Redis TTL after extension to forever = %v, want none", ttl)
	}

	if err := ExtendClient(ctx, store, "unknown", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("ExtendClient(unknown) err = %v, want ErrNotFound", err)
	}
}

func TestHybridStore_ExpiredClientNotServedFromFile(t *testing.T) {
	ctx := context.Background()
	fs, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	redisStore, mr := newTestRedis(t)
	store := NewHybridTokenStore(redisStore, fs)

	// The file store keeps the record until its cleanup runs; the fallback
	// must not serve it once Redis has let the key expire.
	if err := store.SaveClient(ctx, &OAuthClient{ClientID: testClientUnused, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(2 * time.Hour)
	// Two hours on for the file store as well, which reads the wall clock.
	fs.clients[testClientUnused] = &OAuthClient{ClientID: testClientUnused, ExpiresAt: time.Now().Add(-time.Hour)}
	if _, err := store.GetClient(ctx, testClientUnused); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetClient err = %v, want ErrNotFound", err)
	}
}

func TestFileTokenStore_WarmUpSkipsExpiredClients(t *testing.T) {
	ctx := context.Background()
	fs, err := NewFileTokenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	_ = fs.SaveClient(ctx, &OAuthClient{ClientID: testClientUnused, ExpiresAt: now.Add(-time.Minute)})
	_ = fs.SaveClient(ctx, &OAuthClient{ClientID: testClientUsed, ExpiresAt: now.Add(time.Hour)})

	redisStore, mr := newTestRedis(t)
	fs.WarmUp(ctx, redisStore)

	if mr.Exists(prefixClient + testClientUnused) {
		t.Error("expired client copied to Redis")
	}
	if ttl := mr.TTL(prefixClient + testClientUsed); ttl <= 0 || ttl > time.Hour {
		t.Errorf("live client TTL in Redis = %v, want its remaining lifetime", ttl)
	}
}
