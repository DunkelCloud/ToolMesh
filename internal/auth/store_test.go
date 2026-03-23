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
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*RedisTokenStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRedisTokenStore(rdb), mr
}

func TestRedisTokenStore_Client(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	client := &OAuthClient{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURIs: []string{"https://example.com/callback"},
		CreatedAt:    time.Now().Truncate(time.Second),
	}

	if err := store.SaveClient(ctx, client); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	got, err := store.GetClient(ctx, "test-client")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.ClientID != client.ClientID {
		t.Errorf("ClientID = %q, want %q", got.ClientID, client.ClientID)
	}
	if got.ClientSecret != client.ClientSecret {
		t.Errorf("ClientSecret = %q, want %q", got.ClientSecret, client.ClientSecret)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("RedirectURIs = %v", got.RedirectURIs)
	}

	// Non-existent client
	_, err = store.GetClient(ctx, "nonexistent")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRedisTokenStore_AuthCode(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	ac := &AuthCode{
		Code:          "test-code",
		ClientID:      "c1",
		RedirectURI:   "https://example.com/callback",
		CodeChallenge: "challenge",
		Scope:         "claudeai",
		UserID:        "admin",
		CompanyID:     "dunkelcloud",
		Plan:          "pro",
		Roles:         []string{"admin"},
		ExpiresAt:     time.Now().Add(5 * time.Minute),
	}

	if err := store.SaveAuthCode(ctx, ac); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	// Consume should return the code and delete it
	got, err := store.ConsumeAuthCode(ctx, "test-code")
	if err != nil {
		t.Fatalf("ConsumeAuthCode: %v", err)
	}
	if got.Code != ac.Code {
		t.Errorf("Code = %q, want %q", got.Code, ac.Code)
	}
	if got.UserID != "admin" {
		t.Errorf("UserID = %q, want %q", got.UserID, "admin")
	}
	if got.Plan != "pro" {
		t.Errorf("Plan = %q, want %q", got.Plan, "pro")
	}

	// Second consume should fail (atomic delete)
	_, err = store.ConsumeAuthCode(ctx, "test-code")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on second consume, got %v", err)
	}
}

func TestRedisTokenStore_Token(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	ti := &TokenInfo{
		AccessToken:  "at-123",
		RefreshToken: "rt-123",
		ClientID:     "c1",
		UserID:       "admin",
		CompanyID:    "dunkelcloud",
		Plan:         "pro",
		Roles:        []string{"admin"},
		Scope:        "claudeai",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := store.SaveToken(ctx, ti); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}

	got, err := store.GetToken(ctx, "at-123")
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if got.AccessToken != ti.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, ti.AccessToken)
	}
	if got.UserID != "admin" {
		t.Errorf("UserID = %q, want %q", got.UserID, "admin")
	}
	if got.CompanyID != "dunkelcloud" {
		t.Errorf("CompanyID = %q, want %q", got.CompanyID, "dunkelcloud")
	}
	if got.Plan != "pro" {
		t.Errorf("Plan = %q, want %q", got.Plan, "pro")
	}

	// Delete token
	if err := store.DeleteToken(ctx, "at-123"); err != nil {
		t.Fatalf("DeleteToken: %v", err)
	}
	_, err = store.GetToken(ctx, "at-123")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestRedisTokenStore_RefreshToken(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	ti := &TokenInfo{
		AccessToken:  "at-456",
		RefreshToken: "rt-456",
		ClientID:     "c1",
		UserID:       "demo",
		CompanyID:    "demo-corp",
		Plan:         "free",
		Roles:        []string{"viewer"},
		Scope:        "claudeai",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := store.SaveRefreshToken(ctx, ti); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	// Consume should return the token and delete it
	got, err := store.ConsumeRefreshToken(ctx, "rt-456")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken: %v", err)
	}
	if got.UserID != "demo" {
		t.Errorf("UserID = %q, want %q", got.UserID, "demo")
	}

	// Second consume should fail
	_, err = store.ConsumeRefreshToken(ctx, "rt-456")
	if err != ErrNotFound {
		t.Errorf("expected ErrNotFound on second consume, got %v", err)
	}
}

func TestRedisTokenStore_Persistence(t *testing.T) {
	// Simulate server restart: create token with store1, read with store2 (same Redis)
	mr := miniredis.RunT(t)

	rdb1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb1.Close()
	store1 := NewRedisTokenStore(rdb1)

	ctx := context.Background()
	ti := &TokenInfo{
		AccessToken:  "persistent-token",
		RefreshToken: "persistent-refresh",
		ClientID:     "c1",
		UserID:       "admin",
		CompanyID:    "dunkelcloud",
		Plan:         "pro",
		Roles:        []string{"admin"},
		Scope:        "claudeai",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	if err := store1.SaveToken(ctx, ti); err != nil {
		t.Fatalf("SaveToken: %v", err)
	}
	rdb1.Close()

	// "Restart" — new client, same Redis
	rdb2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb2.Close()
	store2 := NewRedisTokenStore(rdb2)

	got, err := store2.GetToken(ctx, "persistent-token")
	if err != nil {
		t.Fatalf("GetToken after restart: %v", err)
	}
	if got.UserID != "admin" {
		t.Errorf("UserID = %q, want %q", got.UserID, "admin")
	}
}
