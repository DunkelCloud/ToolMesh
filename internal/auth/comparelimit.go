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
	"fmt"
	"sync/atomic"
	"time"
)

// ErrCompareBusy is returned when a password-hash comparison could not start
// because every slot stayed taken. Nothing was compared: the credential is
// neither accepted nor rejected, and the caller should answer "try again"
// rather than "wrong credential".
var ErrCompareBusy = errors.New("password hash comparison capacity exhausted")

const (
	// compareMaxWait is how long a comparison waits for a free slot. It has to
	// cover a short burst of legitimate logins behind slow hashes (a bcrypt
	// cost of 14 takes about a second) without holding a request open for
	// long when the slots are under sustained load.
	compareMaxWait = 5 * time.Second

	// compareQueuePerSlot bounds how many comparisons may wait per slot.
	// Beyond that a request is turned away at once instead of parking a
	// goroutine and a connection for compareMaxWait, so a flood cannot pile
	// up waiters without limit.
	compareQueuePerSlot = 64
)

// CompareLimiter bounds how many password-hash comparisons run at the same
// time across the whole process. A bcrypt comparison occupies one CPU core
// for its full duration, and anyone who can reach the login form or send a
// bearer credential can ask for one, so without a bound the number of
// concurrent requests decides how many cores are busy hashing.
//
// Waiters are served in the order they arrived, and a slot that is given back
// goes to the longest waiter before anyone who arrives later can take it.
//
// A nil *CompareLimiter does not limit anything.
type CompareLimiter struct {
	slots      chan struct{}
	maxWait    time.Duration
	maxWaiting int64
	waiting    atomic.Int64
}

// NewCompareLimiter creates a limiter that lets maxConcurrent comparisons run
// at once. Values below 1 are treated as 1.
func NewCompareLimiter(maxConcurrent int) *CompareLimiter {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &CompareLimiter{
		slots:      make(chan struct{}, maxConcurrent),
		maxWait:    compareMaxWait,
		maxWaiting: int64(maxConcurrent) * compareQueuePerSlot,
	}
}

// Capacity returns how many comparisons may run at once; 0 for a nil limiter,
// which does not limit.
func (l *CompareLimiter) Capacity() int {
	if l == nil {
		return 0
	}
	return cap(l.slots)
}

// Do runs compare while holding one of the slots. If none becomes free in
// time, compare is not run and the error is ErrCompareBusy; if ctx has ended
// or ends first, the error wraps ctx.Err(). In both cases nothing was
// compared.
func (l *CompareLimiter) Do(ctx context.Context, compare func()) error {
	if l == nil {
		compare()
		return nil
	}
	_, err := l.do(ctx, l.maxWait, compare)
	return err
}

// do is Do with the wait for a slot limited to wait instead of the limiter's
// own maximum, and it reports how long the wait was. A caller that needs
// several comparisons for one request uses it to keep the waits of all of
// them within one allowance. With wait <= 0 it takes a slot only if one is
// free right now.
func (l *CompareLimiter) do(ctx context.Context, wait time.Duration, compare func()) (waited time.Duration, err error) {
	if l == nil {
		compare()
		return 0, nil
	}
	if waited, err = l.acquire(ctx, wait); err != nil {
		return waited, err
	}
	defer func() { <-l.slots }()
	compare()
	return waited, nil
}

func (l *CompareLimiter) acquire(ctx context.Context, wait time.Duration) (time.Duration, error) {
	// A request nobody waits for anymore gets no comparison, even if a slot
	// happens to be free.
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("password hash comparison not started: %w", err)
	}

	select {
	case l.slots <- struct{}{}:
		return 0, nil
	default:
	}
	if wait <= 0 {
		return 0, ErrCompareBusy
	}

	if l.waiting.Add(1) > l.maxWaiting {
		l.waiting.Add(-1)
		return 0, ErrCompareBusy
	}
	defer l.waiting.Add(-1)

	start := time.Now()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case l.slots <- struct{}{}:
		return time.Since(start), nil
	case <-timer.C:
		return time.Since(start), ErrCompareBusy
	case <-ctx.Done():
		return time.Since(start), fmt.Errorf("waiting for a password hash comparison slot: %w", ctx.Err())
	}
}
