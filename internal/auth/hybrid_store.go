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
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// slowPrimaryCall is how long a failed call to the primary store has to
	// have taken for the store to count as hanging, not just failing. A
	// refused connection or an error reply comes back at once and costs
	// nothing to try again.
	slowPrimaryCall = 500 * time.Millisecond
	// primaryPause is how long the primary store is left alone after a call
	// to it hung. A request makes several calls, and each would wait for
	// the store's timeout again: a token refresh against a store that does
	// not answer would take its client longer than the client waits.
	primaryPause = 5 * time.Second
)

// errPrimaryPaused stands for a call that was not made because the primary
// store is being left alone.
var errPrimaryPaused = errors.New("primary store is paused after a call to it hung")

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
//     or authorization code is consumed, the file store removes its copy
//     and puts the removal on record in one step, before the primary store
//     is asked. If that store cannot be told, it keeps its copy, and the
//     record is what stands against it: the copy is refused when the store
//     hands it out, and removed there, at the latest by
//     FileTokenStore.Cleanup within half a minute of the store answering
//     again, or by FileTokenStore.WarmUp after a restart. Without the
//     record a revoked token would work again, and a spent refresh token or
//     code could be used a second time.
//   - A primary store that hangs is left alone for a moment after a call
//     to it timed out, so a request does not wait for it call after call.
//
// The record is written with the removal, not after the primary store has
// failed, for two reasons. A second request that presents the same token
// meanwhile finds either the copy in the file store or the record, never
// neither, so one request at most gets the token. And a process that dies
// between the two steps leaves the record on disk for the next start.
//
// This covers the entries the file store holds itself, which is every entry
// this process wrote. With several processes on one primary store, each
// with a file store of its own, an entry is reliably removed only at the
// process that wrote it: the others know it through the primary store
// alone, and the writer falls back to its own copy when the primary store
// no longer has the entry.
type HybridTokenStore struct {
	primary TokenStore
	file    *FileTokenStore

	// pausedUntil is the time until which the primary store is left alone,
	// in Unix nanoseconds; 0 when it is not.
	pausedUntil atomic.Int64
	now         func() time.Time

	// missed holds the tokens and codes whose write certainly did not
	// reach the primary store (see notWritten), with the time they expire.
	// It has no copy of them, so their removal needs no record.
	mu     sync.Mutex
	missed map[string]time.Time
}

// missedPruneAt is the size from which noteWrite drops expired entries of
// missed before it adds one.
const missedPruneAt = 1024

// NewHybridTokenStore creates a hybrid store that writes to both stores
// and reads from the primary with file-based fallback.
func NewHybridTokenStore(primary TokenStore, file *FileTokenStore) *HybridTokenStore {
	return &HybridTokenStore{primary: primary, file: file, now: time.Now, missed: make(map[string]time.Time)}
}

// viaPrimary makes a call to the primary store, unless the store is being
// left alone, and returns its error. A call that fails after hanging
// starts a pause; ErrNotFound is an answer, not a failure.
func (h *HybridTokenStore) viaPrimary(op string, call func() error) error {
	start := h.now()
	if start.UnixNano() < h.pausedUntil.Load() {
		return errPrimaryPaused
	}
	err := call()
	if err == nil || errors.Is(err, ErrNotFound) {
		return err
	}
	end := h.now()
	if end.Sub(start) >= slowPrimaryCall {
		h.pausedUntil.Store(end.Add(primaryPause).UnixNano())
		slog.Warn("primary store: call hung, using the file store alone for a moment", "op", op, "error", err, "pause", primaryPause)
	} else {
		slog.Warn("primary store: call failed, using the file store", "op", op, "error", err)
	}
	return err
}

// notWritten reports whether a failed write certainly did not reach the
// primary store: the call was not made, the connection could not be
// opened, or the store answered with an error. After any other failure, a
// timeout or a connection that broke, the store may have carried the write
// out without its answer arriving, and it has to count as holding a copy.
func notWritten(err error) bool {
	if errors.Is(err, errPrimaryPaused) {
		return true
	}
	var dial *net.OpError
	if errors.As(err, &dial) && dial.Op == "dial" {
		return true
	}
	var reply redis.Error
	return errors.As(err, &reply)
}

// noteWrite records what the write of key, an entry that expires at
// expires, tells about the primary store holding a copy.
func (h *HybridTokenStore) noteWrite(key string, expires time.Time, primaryErr error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if primaryErr == nil || !notWritten(primaryErr) {
		delete(h.missed, key)
		return
	}
	if len(h.missed) >= missedPruneAt {
		now := h.now()
		for k, until := range h.missed {
			if !until.After(now) {
				delete(h.missed, k)
			}
		}
	}
	h.missed[key] = expires
}

// primaryMayHold reports whether the primary store can hold a copy of key,
// and forgets what it knew about key: the entry is being removed.
func (h *HybridTokenStore) primaryMayHold(key string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, missed := h.missed[key]
	delete(h.missed, key)
	return !missed
}

// saved gives the result of a write to both stores: it failed only when
// neither took it. A write only one store took succeeds; reads find it.
func saved(op string, fileErr, primaryErr error) error {
	if fileErr != nil {
		if primaryErr != nil {
			return primaryErr
		}
		slog.Warn("file store: write failed, kept in the primary store only", "op", op, "error", fileErr)
	}
	return nil
}

// SaveClient stores a client in both stores.
func (h *HybridTokenStore) SaveClient(ctx context.Context, c *OAuthClient) error {
	ferr := h.file.SaveClient(ctx, c)
	perr := h.viaPrimary("SaveClient", func() error { return h.primary.SaveClient(ctx, c) })
	return saved("SaveClient", ferr, perr)
}

// GetClient reads from the primary store, falls back to file store.
func (h *HybridTokenStore) GetClient(ctx context.Context, clientID string) (*OAuthClient, error) {
	var c *OAuthClient
	err := h.viaPrimary("GetClient", func() (err error) {
		c, err = h.primary.GetClient(ctx, clientID)
		return err
	})
	if err == nil {
		return c, nil
	}
	return h.file.GetClient(ctx, clientID)
}

// SaveAuthCode stores an auth code in both stores.
func (h *HybridTokenStore) SaveAuthCode(ctx context.Context, ac *AuthCode) error {
	ferr := h.file.SaveAuthCode(ctx, ac)
	perr := h.viaPrimary("SaveAuthCode", func() error { return h.primary.SaveAuthCode(ctx, ac) })
	h.noteWrite(string(removedCode)+ac.Code, ac.ExpiresAt, perr)
	return saved("SaveAuthCode", ferr, perr)
}

// ConsumeAuthCode hands an authorization code out once, whichever store
// holds it and whether or not the primary store can be asked.
func (h *HybridTokenStore) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	held := h.file.removeCode(code, h.primaryMayHold(string(removedCode)+code))
	var ac *AuthCode
	err := h.viaPrimary("ConsumeAuthCode", func() (err error) {
		ac, err = h.primary.ConsumeAuthCode(ctx, code)
		return err
	})
	if err == nil || errors.Is(err, ErrNotFound) {
		h.file.removed.setApplied(removedCode, code, h.now())
	}
	switch {
	case held != nil:
		return held, nil
	case err == nil && !h.file.isRemoved(removedCode, code):
		// A code only the primary store knew.
		return ac, nil
	}
	return nil, ErrNotFound
}

// SaveToken stores an access token in both stores.
func (h *HybridTokenStore) SaveToken(ctx context.Context, ti *TokenInfo) error {
	ferr := h.file.SaveToken(ctx, ti)
	perr := h.viaPrimary("SaveToken", func() error { return h.primary.SaveToken(ctx, ti) })
	h.noteWrite(string(removedAccess)+ti.AccessToken, ti.ExpiresAt, perr)
	return saved("SaveToken", ferr, perr)
}

// GetToken reads from the primary store, falls back to file store. A token
// whose deletion is on record is not found, whatever the primary store
// still holds; the deletion is then completed there.
func (h *HybridTokenStore) GetToken(ctx context.Context, accessToken string) (*TokenInfo, error) {
	var ti *TokenInfo
	err := h.viaPrimary("GetToken", func() (err error) {
		ti, err = h.primary.GetToken(ctx, accessToken)
		return err
	})
	if err != nil {
		return h.file.GetToken(ctx, accessToken)
	}
	if h.file.isRemoved(removedAccess, accessToken) {
		derr := h.viaPrimary("DeleteToken", func() error { return h.primary.DeleteToken(ctx, accessToken) })
		if derr == nil {
			h.file.removed.setApplied(removedAccess, accessToken, h.now())
		}
		return nil, ErrNotFound
	}
	return ti, nil
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

// DeleteToken removes a token from both stores. It fails only when the
// primary store could not be told about a token the file store does not
// hold: nothing stands for the deletion then.
func (h *HybridTokenStore) DeleteToken(ctx context.Context, accessToken string) error {
	held := h.file.removeAccess(accessToken, h.primaryMayHold(string(removedAccess)+accessToken))
	err := h.viaPrimary("DeleteToken", func() error { return h.primary.DeleteToken(ctx, accessToken) })
	if err == nil {
		h.file.removed.setApplied(removedAccess, accessToken, h.now())
		return nil
	}
	if held == nil {
		return err
	}
	return nil
}

// SaveRefreshToken stores a refresh token in both stores.
func (h *HybridTokenStore) SaveRefreshToken(ctx context.Context, ti *TokenInfo) error {
	ferr := h.file.SaveRefreshToken(ctx, ti)
	perr := h.viaPrimary("SaveRefreshToken", func() error { return h.primary.SaveRefreshToken(ctx, ti) })
	h.noteWrite(string(removedRefresh)+ti.RefreshToken, ti.RefreshExpiry(), perr)
	return saved("SaveRefreshToken", ferr, perr)
}

// ConsumeRefreshToken hands a refresh token out once, whichever store holds
// it and whether or not the primary store can be asked. The request that
// takes the file store's copy is the one that gets the token; a copy the
// primary store hands out for a token that is on record as consumed is
// dropped, not honored.
func (h *HybridTokenStore) ConsumeRefreshToken(ctx context.Context, refreshToken string) (*TokenInfo, error) {
	held := h.file.removeRefresh(refreshToken, h.primaryMayHold(string(removedRefresh)+refreshToken))
	var ti *TokenInfo
	err := h.viaPrimary("ConsumeRefreshToken", func() (err error) {
		ti, err = h.primary.ConsumeRefreshToken(ctx, refreshToken)
		return err
	})
	if err == nil || errors.Is(err, ErrNotFound) {
		h.file.removed.setApplied(removedRefresh, refreshToken, h.now())
	}
	switch {
	case held != nil:
		return held, nil
	case err == nil && !h.file.isRemoved(removedRefresh, refreshToken):
		// A token only the primary store knew.
		return ti, nil
	}
	return nil, ErrNotFound
}
