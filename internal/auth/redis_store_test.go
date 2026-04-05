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

func newTestRedisStore(t *testing.T) *RedisTokenStore {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRedisTokenStore(rdb)
}

func TestRedisTokenStore_ClientRoundTrip(t *testing.T) {
	s := newTestRedisStore(t)
	ctx := context.Background()

	c := &OAuthClient{ClientID: "c1", ClientSecret: "sec"}
	if err := s.SaveClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, "c1")
	if err != nil || got.ClientID != "c1" {
		t.Errorf("got %+v, err %v", got, err)
	}

	if _, err := s.GetClient(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRedisTokenStore_AuthCodeConsume(t *testing.T) {
	s := newTestRedisStore(t)
	ctx := context.Background()

	ac := &AuthCode{Code: "abc", ClientID: "c"}
	if err := s.SaveAuthCode(ctx, ac); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeAuthCode(ctx, "abc")
	if err != nil || got.Code != "abc" {
		t.Errorf("got %+v, err %v", got, err)
	}
	// Already consumed.
	if _, err := s.ConsumeAuthCode(ctx, "abc"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRedisTokenStore_TokenRoundTrip(t *testing.T) {
	s := newTestRedisStore(t)
	ctx := context.Background()

	ti := &TokenInfo{AccessToken: "t", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetToken(ctx, "t")
	if err != nil || got.UserID != "u" {
		t.Errorf("got %+v, err %v", got, err)
	}

	if err := s.DeleteToken(ctx, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetToken(ctx, "t"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRedisTokenStore_RefreshTokenConsume(t *testing.T) {
	s := newTestRedisStore(t)
	ctx := context.Background()

	ti := &TokenInfo{RefreshToken: "r", UserID: "u", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatal(err)
	}
	got, err := s.ConsumeRefreshToken(ctx, "r")
	if err != nil || got.UserID != "u" {
		t.Errorf("got %+v, err %v", got, err)
	}
	if _, err := s.ConsumeRefreshToken(ctx, "r"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
