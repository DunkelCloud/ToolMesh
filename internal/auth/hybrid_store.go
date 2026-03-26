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
	"log/slog"
)

// HybridTokenStore combines a primary store (typically Redis) with a
// file-based store that always writes in parallel. On reads, the primary
// store is preferred; the file store serves as fallback when the primary
// returns an error. This ensures OAuth state survives restarts even when
// the primary store loses its data.
type HybridTokenStore struct {
	primary TokenStore
	file    *FileTokenStore
}

// NewHybridTokenStore creates a hybrid store that writes to both stores
// and reads from the primary with file-based fallback.
func NewHybridTokenStore(primary TokenStore, file *FileTokenStore) *HybridTokenStore {
	return &HybridTokenStore{primary: primary, file: file}
}

// SaveClient stores a client in both stores.
func (h *HybridTokenStore) SaveClient(ctx context.Context, c *OAuthClient) error {
	if err := h.file.SaveClient(ctx, c); err != nil {
		slog.Warn("file store: SaveClient failed", "error", err)
	}
	return h.primary.SaveClient(ctx, c)
}

// GetClient reads from the primary store, falls back to file store.
func (h *HybridTokenStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	c, err := h.primary.GetClient(ctx, clientID)
	if err == nil {
		return c, nil
	}
	return h.file.GetClient(ctx, clientID)
}

// SaveAuthCode stores an auth code in both stores.
func (h *HybridTokenStore) SaveAuthCode(ctx context.Context, ac *AuthCode) error {
	if err := h.file.SaveAuthCode(ctx, ac); err != nil {
		slog.Warn("file store: SaveAuthCode failed", "error", err)
	}
	return h.primary.SaveAuthCode(ctx, ac)
}

// ConsumeAuthCode consumes from the primary store, falls back to file store.
func (h *HybridTokenStore) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	ac, err := h.primary.ConsumeAuthCode(ctx, code)
	if err == nil {
		// Also consume from file store to keep them in sync.
		_, _ = h.file.ConsumeAuthCode(ctx, code)
		return ac, nil
	}
	return h.file.ConsumeAuthCode(ctx, code)
}

// SaveToken stores an access token in both stores.
func (h *HybridTokenStore) SaveToken(ctx context.Context, ti *TokenInfo) error {
	if err := h.file.SaveToken(ctx, ti); err != nil {
		slog.Warn("file store: SaveToken failed", "error", err)
	}
	return h.primary.SaveToken(ctx, ti)
}

// GetToken reads from the primary store, falls back to file store.
func (h *HybridTokenStore) GetToken(ctx context.Context, accessToken string) (*TokenInfo, error) {
	ti, err := h.primary.GetToken(ctx, accessToken)
	if err == nil {
		return ti, nil
	}
	return h.file.GetToken(ctx, accessToken)
}

// DeleteToken removes a token from both stores.
func (h *HybridTokenStore) DeleteToken(ctx context.Context, accessToken string) error {
	if err := h.file.DeleteToken(ctx, accessToken); err != nil {
		slog.Warn("file store: DeleteToken failed", "error", err)
	}
	return h.primary.DeleteToken(ctx, accessToken)
}

// SaveRefreshToken stores a refresh token in both stores.
func (h *HybridTokenStore) SaveRefreshToken(ctx context.Context, ti *TokenInfo) error {
	if err := h.file.SaveRefreshToken(ctx, ti); err != nil {
		slog.Warn("file store: SaveRefreshToken failed", "error", err)
	}
	return h.primary.SaveRefreshToken(ctx, ti)
}

// ConsumeRefreshToken consumes from the primary store, falls back to file store.
func (h *HybridTokenStore) ConsumeRefreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error) {
	ti, err := h.primary.ConsumeRefreshToken(ctx, refreshToken)
	if err == nil {
		// Also consume from file store to keep them in sync.
		_, _ = h.file.ConsumeRefreshToken(ctx, refreshToken)
		return ti, nil
	}
	return h.file.ConsumeRefreshToken(ctx, refreshToken)
}
