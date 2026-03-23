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

// Package auth provides OAuth token storage and user identity management.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// OAuthClient represents a registered OAuth 2.1 Dynamic Client.
type OAuthClient struct {
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	ClientName   string    `json:"client_name,omitempty"`
	RedirectURIs []string  `json:"redirect_uris"`
	CreatedAt    time.Time `json:"created_at"`
}

// AuthCode represents a short-lived authorization code.
type AuthCode struct {
	Code          string    `json:"code"`
	ClientID      string    `json:"client_id"`
	RedirectURI   string    `json:"redirect_uri"`
	CodeChallenge string    `json:"code_challenge"`
	Scope         string    `json:"scope"`
	UserID        string    `json:"user_id"`
	CompanyID     string    `json:"company_id"`
	Plan          string    `json:"plan"`
	Roles         []string  `json:"roles"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// TokenInfo represents an access or refresh token with associated user data.
type TokenInfo struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ClientID     string    `json:"client_id"`
	UserID       string    `json:"user_id"`
	CompanyID    string    `json:"company_id"`
	Plan         string    `json:"plan"`
	Roles        []string  `json:"roles"`
	CallerID     string    `json:"caller_id,omitempty"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// ErrNotFound is returned when a key does not exist in the store.
var ErrNotFound = errors.New("not found")

// TokenStore defines the interface for OAuth state persistence.
type TokenStore interface {
	SaveClient(ctx context.Context, c *OAuthClient) error
	GetClient(ctx context.Context, clientID string) (*OAuthClient, error)
	SaveAuthCode(ctx context.Context, ac *AuthCode) error
	ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error)
	SaveToken(ctx context.Context, ti *TokenInfo) error
	GetToken(ctx context.Context, accessToken string) (*TokenInfo, error)
	SaveRefreshToken(ctx context.Context, ti *TokenInfo) error
	ConsumeRefreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error)
	DeleteToken(ctx context.Context, accessToken string) error
}

const (
	prefixClient  = "oauth:client:"
	prefixCode    = "oauth:code:"
	prefixToken   = "oauth:token:" //nolint:gosec // Redis key prefix, not a credential
	prefixRefresh = "oauth:refresh:"

	ttlAuthCode     = 5 * time.Minute
	ttlAccessToken  = 1 * time.Hour
	ttlRefreshToken = 7 * 24 * time.Hour
)

// Lua script for atomic GET + DELETE (consume pattern).
var consumeScript = redis.NewScript(`
local val = redis.call("GET", KEYS[1])
if val then
	redis.call("DEL", KEYS[1])
end
return val
`)

// RedisTokenStore implements TokenStore backed by Redis.
type RedisTokenStore struct {
	rdb *redis.Client
}

// NewRedisTokenStore creates a new Redis-backed token store.
func NewRedisTokenStore(rdb *redis.Client) *RedisTokenStore {
	return &RedisTokenStore{rdb: rdb}
}

// SaveClient stores an OAuth client registration in Redis.
func (s *RedisTokenStore) SaveClient(ctx context.Context, c *OAuthClient) error {
	data, err := json.Marshal(c) //nolint:gosec // G117: intentional — storing OAuth data in Redis
	if err != nil {
		return fmt.Errorf("marshal client: %w", err)
	}
	return s.rdb.Set(ctx, prefixClient+c.ClientID, data, 0).Err()
}

// GetClient retrieves an OAuth client by its client ID.
func (s *RedisTokenStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	data, err := s.rdb.Get(ctx, prefixClient+clientID).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}
	var c OAuthClient
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("unmarshal client: %w", err)
	}
	return &c, nil
}

// SaveAuthCode stores an authorization code with a short TTL.
func (s *RedisTokenStore) SaveAuthCode(ctx context.Context, ac *AuthCode) error {
	data, err := json.Marshal(ac)
	if err != nil {
		return fmt.Errorf("marshal auth code: %w", err)
	}
	return s.rdb.Set(ctx, prefixCode+ac.Code, data, ttlAuthCode).Err()
}

// ConsumeAuthCode atomically retrieves and deletes an authorization code.
func (s *RedisTokenStore) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	val, err := consumeScript.Run(ctx, s.rdb, []string{prefixCode + code}).Result()
	if errors.Is(err, redis.Nil) || val == nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume auth code: %w", err)
	}
	var ac AuthCode
	if err := json.Unmarshal([]byte(val.(string)), &ac); err != nil {
		return nil, fmt.Errorf("unmarshal auth code: %w", err)
	}
	return &ac, nil
}

// SaveToken stores an access token with the configured TTL.
func (s *RedisTokenStore) SaveToken(ctx context.Context, ti *TokenInfo) error {
	data, err := json.Marshal(ti) //nolint:gosec // G117: intentional — storing OAuth data in Redis
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}
	return s.rdb.Set(ctx, prefixToken+ti.AccessToken, data, ttlAccessToken).Err()
}

// GetToken retrieves token information by access token.
func (s *RedisTokenStore) GetToken(ctx context.Context, accessToken string) (*TokenInfo, error) {
	data, err := s.rdb.Get(ctx, prefixToken+accessToken).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get token: %w", err)
	}
	var ti TokenInfo
	if err := json.Unmarshal(data, &ti); err != nil {
		return nil, fmt.Errorf("unmarshal token: %w", err)
	}
	return &ti, nil
}

// DeleteToken removes an access token from the store.
func (s *RedisTokenStore) DeleteToken(ctx context.Context, accessToken string) error {
	return s.rdb.Del(ctx, prefixToken+accessToken).Err()
}

// SaveRefreshToken stores a refresh token with the configured TTL.
func (s *RedisTokenStore) SaveRefreshToken(ctx context.Context, ti *TokenInfo) error {
	data, err := json.Marshal(ti) //nolint:gosec // G117: intentional — storing OAuth data in Redis
	if err != nil {
		return fmt.Errorf("marshal refresh token: %w", err)
	}
	return s.rdb.Set(ctx, prefixRefresh+ti.RefreshToken, data, ttlRefreshToken).Err()
}

// ConsumeRefreshToken atomically retrieves and deletes a refresh token.
func (s *RedisTokenStore) ConsumeRefreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error) {
	val, err := consumeScript.Run(ctx, s.rdb, []string{prefixRefresh + refreshToken}).Result()
	if errors.Is(err, redis.Nil) || val == nil {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}
	var ti TokenInfo
	if err := json.Unmarshal([]byte(val.(string)), &ti); err != nil {
		return nil, fmt.Errorf("unmarshal refresh token: %w", err)
	}
	return &ti, nil
}
