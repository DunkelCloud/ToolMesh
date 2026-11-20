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
	"log/slog"
)

// HybridTokenStore combines a primary store (typically Redis) with a
// file-based store that always writes in parallel. On reads, the primary
// store is preferred; the file store serves as fallback when the primary
// returns an error. This ensures OAuth state survives restarts even when
// the primary store loses its data.
//
// An outage of the primary store costs nothing that the file store can
// carry:
//
//   - A write that only the file store took succeeds. Reads fall back to
//     the file store, so a login, a token refresh or a client registration
//     made during the outage works during it and after it. Failing the
//     write instead would also burn what the request had already consumed:
//     a refresh would spend its refresh token and return no new pair.
//   - A removal holds. When an access token is deleted, or a refresh token
//     or authorization code is consumed, while the primary store cannot be
//     told, that store keeps its copy, and the copy would count again once
//     the store answers: a revoked token would work again, a spent refresh
//     token or code could be used a second time. The file store therefore
//     remembers such a removal until the entry expires. A copy the primary
//     store hands out for a remembered removal is refused, and the copy is
//     removed there: when it is presented, by FileTokenStore.Cleanup within
//     half a minute of the store answering again, and by
//     FileTokenStore.WarmUp after a restart.
//
// A removal stays remembered after the primary store has been told. Several
// requests can fetch the same copy before it is removed there, and each of
// them has to find the record. It is dropped early only where the primary
// store itself hands a copy out once, which is consuming it.
//
// This covers the entries the file store held itself, which is every entry
// this process wrote. With several processes on one primary store, an entry
// only another process wrote is known here through the primary store alone.
type HybridTokenStore struct {
	primary TokenStore
	file    *FileTokenStore
}

// NewHybridTokenStore creates a hybrid store that writes to both stores
// and reads from the primary with file-based fallback.
func NewHybridTokenStore(primary TokenStore, file *FileTokenStore) *HybridTokenStore {
	return &HybridTokenStore{primary: primary, file: file}
}

// saved gives the result of a write to both stores: it failed only when
// neither took it. A write only one store took is logged; reads find it.
func saved(op string, fileErr, primaryErr error) error {
	switch {
	case fileErr == nil && primaryErr == nil:
		return nil
	case fileErr != nil && primaryErr != nil:
		return primaryErr
	case primaryErr != nil:
		slog.Warn("primary store: write failed, kept in the file store only", "op", op, "error", primaryErr)
	default:
		slog.Warn("file store: write failed, kept in the primary store only", "op", op, "error", fileErr)
	}
	return nil
}

// SaveClient stores a client in both stores.
func (h *HybridTokenStore) SaveClient(ctx context.Context, c *OAuthClient) error {
	return saved("SaveClient", h.file.SaveClient(ctx, c), h.primary.SaveClient(ctx, c))
}

// GetClient reads from the primary store, falls back to file store.
func (h *HybridTokenStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	c, err := h.primary.GetClient(ctx, clientID)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, ErrNotFound) {
		slog.Warn("primary store: GetClient failed, trying file store", "error", err)
	}
	return h.file.GetClient(ctx, clientID)
}

// SaveAuthCode stores an auth code in both stores.
func (h *HybridTokenStore) SaveAuthCode(ctx context.Context, ac *AuthCode) error {
	return saved("SaveAuthCode", h.file.SaveAuthCode(ctx, ac), h.primary.SaveAuthCode(ctx, ac))
}

// ConsumeAuthCode consumes from the primary store, falls back to file store.
// A code consumed while the primary store was unreachable stays consumed.
func (h *HybridTokenStore) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	ac, err := h.primary.ConsumeAuthCode(ctx, code)
	switch {
	case err == nil:
		// Also consume from file store to keep them in sync.
		_, _ = h.file.ConsumeAuthCode(ctx, code)
		if h.file.dropRemoved(removedCode, code) {
			return nil, ErrNotFound
		}
		return ac, nil
	case errors.Is(err, ErrNotFound):
		return h.file.ConsumeAuthCode(ctx, code)
	}
	slog.Warn("primary store: ConsumeAuthCode failed, trying file store", "error", err)
	held, ferr := h.file.ConsumeAuthCode(ctx, code)
	if ferr == nil {
		h.file.markRemoved(removedCode, code, held.ExpiresAt)
	}
	return held, ferr
}

// SaveToken stores an access token in both stores.
func (h *HybridTokenStore) SaveToken(ctx context.Context, ti *TokenInfo) error {
	return saved("SaveToken", h.file.SaveToken(ctx, ti), h.primary.SaveToken(ctx, ti))
}

// GetToken reads from the primary store, falls back to file store. A token
// deleted while the primary store was unreachable is not found, whatever the
// primary store still holds; the deletion is then completed there.
func (h *HybridTokenStore) GetToken(ctx context.Context, accessToken string) (*TokenInfo, error) {
	ti, err := h.primary.GetToken(ctx, accessToken)
	if err == nil {
		if h.file.isRemoved(removedAccess, accessToken) {
			if derr := h.primary.DeleteToken(ctx, accessToken); derr == nil {
				h.file.removed.setApplied(removedAccess, accessToken)
			}
			return nil, ErrNotFound
		}
		return ti, nil
	}
	if !errors.Is(err, ErrNotFound) {
		slog.Warn("primary store: GetToken failed, trying file store", "error", err)
	}
	return h.file.GetToken(ctx, accessToken)
}

// RefreshTokenOf implements PairLookup through the file store, which holds a
// copy of every token pair.
func (h *HybridTokenStore) RefreshTokenOf(ctx context.Context, accessToken string) (string, error) {
	return h.file.RefreshTokenOf(ctx, accessToken)
}

// Holds implements TokenHolder through the file store, which holds a copy
// of every token this process wrote.
func (h *HybridTokenStore) Holds(token string) bool {
	return h.file.Holds(token)
}

// DeleteToken removes a token from both stores. When the primary store
// cannot be told, the file store remembers the deletion, and the token
// counts as deleted.
func (h *HybridTokenStore) DeleteToken(ctx context.Context, accessToken string) error {
	held := h.file.deleteToken(accessToken)
	err := h.primary.DeleteToken(ctx, accessToken)
	if err == nil {
		return nil
	}
	if held == nil {
		return err
	}
	h.file.markRemoved(removedAccess, accessToken, held.ExpiresAt)
	slog.Warn("primary store: DeleteToken failed, deletion remembered in the file store", "error", err)
	return nil
}

// SaveRefreshToken stores a refresh token in both stores.
func (h *HybridTokenStore) SaveRefreshToken(ctx context.Context, ti *TokenInfo) error {
	return saved("SaveRefreshToken", h.file.SaveRefreshToken(ctx, ti), h.primary.SaveRefreshToken(ctx, ti))
}

// ConsumeRefreshToken consumes from the primary store, falls back to file
// store. A refresh token consumed while the primary store was unreachable
// stays consumed: the copy the primary store kept is dropped, not honored.
func (h *HybridTokenStore) ConsumeRefreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error) {
	ti, err := h.primary.ConsumeRefreshToken(ctx, refreshToken)
	switch {
	case err == nil:
		// Also consume from file store to keep them in sync.
		h.file.consumeRefreshToken(refreshToken)
		if h.file.dropRemoved(removedRefresh, refreshToken) {
			return nil, ErrNotFound
		}
		return ti, nil
	case errors.Is(err, ErrNotFound):
		if held := h.file.consumeRefreshToken(refreshToken); held != nil {
			return held, nil
		}
		return nil, ErrNotFound
	}
	slog.Warn("primary store: ConsumeRefreshToken failed, trying file store", "error", err)
	held := h.file.consumeRefreshToken(refreshToken)
	if held == nil {
		return nil, ErrNotFound
	}
	h.file.markRemoved(removedRefresh, refreshToken, held.RefreshExpiry())
	return held, nil
}
