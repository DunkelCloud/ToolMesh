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
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// holdSlot occupies one slot of the limiter until the returned function is
// called.
func holdSlot(t *testing.T, l *CompareLimiter) (release func()) {
	t.Helper()
	started, done, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_ = l.Do(context.Background(), func() {
			close(started)
			<-done
		})
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("could not take a slot")
	}
	var once sync.Once
	release = func() {
		once.Do(func() {
			close(done)
			<-finished
		})
	}
	t.Cleanup(release)
	return release
}

func TestNewCompareLimiter_Capacity(t *testing.T) {
	for in, want := range map[int]int{-3: 1, 0: 1, 1: 1, 4: 4} {
		if got := NewCompareLimiter(in).Capacity(); got != want {
			t.Errorf("NewCompareLimiter(%d).Capacity() = %d, want %d", in, got, want)
		}
	}
}

func TestCompareLimiter_NilDoesNotLimit(t *testing.T) {
	var l *CompareLimiter
	ran := false
	if err := l.Do(context.Background(), func() { ran = true }); err != nil || !ran {
		t.Errorf("nil limiter: err = %v, ran = %v; want the comparison to run", err, ran)
	}
	if got := l.Capacity(); got != 0 {
		t.Errorf("nil limiter: Capacity() = %d, want 0", got)
	}
}

func TestCompareLimiter_BoundsConcurrency(t *testing.T) {
	const capacity, callers = 2, 16
	l := NewCompareLimiter(capacity)

	var running, peak atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := l.Do(context.Background(), func() {
				n := running.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				time.Sleep(2 * time.Millisecond)
				running.Add(-1)
			})
			if err != nil {
				t.Errorf("Do: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := peak.Load(); got > capacity {
		t.Errorf("%d comparisons ran at once, want at most %d", got, capacity)
	}
}

func TestCompareLimiter_WaitsForAFreeSlot(t *testing.T) {
	l := NewCompareLimiter(1)
	release := holdSlot(t, l)

	result := make(chan error, 1)
	ran := make(chan struct{})
	go func() {
		result <- l.Do(context.Background(), func() { close(ran) })
	}()

	select {
	case <-ran:
		t.Fatal("the comparison ran although the only slot was taken")
	case <-time.After(20 * time.Millisecond):
	}

	release()
	select {
	case err := <-result:
		if err != nil {
			t.Errorf("Do after the slot was freed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting comparison did not run after the slot was freed")
	}
}

func TestCompareLimiter_BusyWhenNoSlotFreesUp(t *testing.T) {
	l := NewCompareLimiter(1)
	l.maxWait = 20 * time.Millisecond
	holdSlot(t, l)

	ran := false
	err := l.Do(context.Background(), func() { ran = true })
	if !errors.Is(err, ErrCompareBusy) {
		t.Errorf("err = %v, want ErrCompareBusy", err)
	}
	if ran {
		t.Error("the comparison ran without a slot")
	}
}

// Beyond the queue bound a comparison is turned away at once, instead of
// parking another goroutine for the full wait.
func TestCompareLimiter_QueueIsBounded(t *testing.T) {
	l := NewCompareLimiter(1)
	l.maxWait = time.Minute
	l.maxWaiting = 1
	holdSlot(t, l)

	ctx, cancel := context.WithCancel(context.Background())
	waiter := make(chan error, 1)
	go func() { waiter <- l.Do(ctx, func() {}) }()
	for deadline := time.Now().Add(5 * time.Second); l.waiting.Load() != 1; {
		if time.Now().After(deadline) {
			t.Fatal("the first caller never started waiting")
		}
		time.Sleep(time.Millisecond)
	}

	start := time.Now()
	err := l.Do(context.Background(), func() { t.Error("the comparison ran without a slot") })
	if !errors.Is(err, ErrCompareBusy) {
		t.Errorf("err = %v, want ErrCompareBusy", err)
	}
	if waited := time.Since(start); waited > 10*time.Second {
		t.Errorf("a caller beyond the queue bound waited %v, want an immediate answer", waited)
	}

	cancel()
	if err := <-waiter; !errors.Is(err, context.Canceled) {
		t.Errorf("waiter: err = %v, want context.Canceled", err)
	}
	if got := l.waiting.Load(); got != 0 {
		t.Errorf("waiting = %d after everyone left, want 0", got)
	}
}

// A request that has already ended gets no comparison, even with a slot free:
// nobody is waiting for the answer.
func TestCompareLimiter_EndedContextGetsNoComparison(t *testing.T) {
	l := NewCompareLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := l.Do(ctx, func() { t.Error("the comparison ran for a request that had ended") })
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	// The slot is still free for the next caller.
	if err := l.Do(context.Background(), func() {}); err != nil {
		t.Errorf("Do after the refused one: %v", err)
	}
}

// Without an allowance for waiting, a comparison takes a slot only if one is
// free right now.
func TestCompareLimiter_NoAllowanceMeansNoWaiting(t *testing.T) {
	l := NewCompareLimiter(1)
	l.maxWait = time.Minute

	ran := false
	if waited, err := l.do(context.Background(), 0, func() { ran = true }); err != nil || !ran || waited != 0 {
		t.Errorf("free slot: waited = %v, err = %v, ran = %v; want the comparison to run at once", waited, err, ran)
	}

	holdSlot(t, l)
	_, err := l.do(context.Background(), 0, func() { t.Error("the comparison ran without a slot") })
	if !errors.Is(err, ErrCompareBusy) {
		t.Errorf("taken slot: err = %v, want ErrCompareBusy", err)
	}
	if got := l.waiting.Load(); got != 0 {
		t.Errorf("waiting = %d, want 0: a caller without allowance must not queue", got)
	}
}

// A slot that is given back goes to whoever waits for it, not to a caller that
// arrives afterwards. The store for API keys relies on this: it is what keeps
// a stream of requests that take a slot one after the other from starving a
// login that waits for the same slot.
func TestCompareLimiter_WaiterIsServedBeforeLaterArrival(t *testing.T) {
	l := NewCompareLimiter(1)
	l.maxWait = time.Minute
	release := holdSlot(t, l)

	waiterRuns, waiterMayFinish := make(chan struct{}), make(chan struct{})
	waiterDone := make(chan error, 1)
	go func() {
		waiterDone <- l.Do(context.Background(), func() {
			close(waiterRuns)
			<-waiterMayFinish
		})
	}()
	for deadline := time.Now().Add(5 * time.Second); l.waiting.Load() != 1; {
		if time.Now().After(deadline) {
			t.Fatal("the waiter never started waiting")
		}
		time.Sleep(time.Millisecond)
	}

	// The slot comes back. Whether or not the waiter has run yet, it is the
	// waiter's now.
	release()
	_, err := l.do(context.Background(), 0, func() { t.Error("a later arrival took the slot the waiter was waiting for") })
	if !errors.Is(err, ErrCompareBusy) {
		t.Errorf("later arrival: err = %v, want ErrCompareBusy", err)
	}

	select {
	case <-waiterRuns:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter did not get the slot")
	}
	close(waiterMayFinish)
	if err := <-waiterDone; err != nil {
		t.Errorf("waiter: %v", err)
	}
}

func TestCompareLimiter_ContextEndsTheWait(t *testing.T) {
	l := NewCompareLimiter(1)
	l.maxWait = time.Minute
	holdSlot(t, l)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := l.Do(ctx, func() { t.Error("the comparison ran without a slot") })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
	if errors.Is(err, ErrCompareBusy) {
		t.Error("a caller that gave up must not be reported as ErrCompareBusy")
	}
}
