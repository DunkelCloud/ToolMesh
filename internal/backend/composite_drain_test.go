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

package backend

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	drainToolOld = "old_wait"
	drainToolNew = "new_wait"
)

// blockingBackend holds every call until the test lets it go: a call sends
// on entered when it arrives and returns once it receives from release.
type blockingBackend struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingBackend() *blockingBackend {
	return &blockingBackend{entered: make(chan struct{}), release: make(chan struct{})}
}

func (b *blockingBackend) Execute(_ context.Context, toolName string, _ map[string]any) (*ToolResult, error) {
	b.entered <- struct{}{}
	<-b.release
	return &ToolResult{Content: []any{toolName}}, nil
}

func (b *blockingBackend) ListTools(_ context.Context) ([]ToolDescriptor, error) {
	return []ToolDescriptor{{Name: "wait"}}, nil
}

func (b *blockingBackend) Healthy(_ context.Context) error { return nil }

// isClosed reports whether ch is closed, without waiting.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// The channel Swap returns is closed once the calls running on the replaced
// children have returned, and not before: whoever waits for it closes those
// children. Calls on the new children do not hold it up.
func TestCompositeBackend_SwapDrained(t *testing.T) {
	tests := []struct {
		name string
		// before is the number of calls on the replaced children that run
		// while the swap lands.
		before int
		// addNamed adds a backend between those calls and the swap; that
		// keeps the children, so it must not end the wait for the calls.
		addNamed bool
		// after is the number of calls on the new children that start after
		// the swap and are still running when the old ones have returned.
		after int
	}{
		{name: "no call running"},
		{name: "one call running", before: 1},
		{name: "two calls running", before: 2},
		{name: "call running across AddNamed", before: 1, addNamed: true},
		{name: "call on the new children only", after: 1},
		{name: "calls on both", before: 1, after: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			old, next := newBlockingBackend(), newBlockingBackend()
			c := NewCompositeBackend(map[string]ToolBackend{"old": old})
			results := make(chan error, tt.before+tt.after)
			start := func(tool string, b *blockingBackend) {
				go func() {
					_, err := c.Execute(ctx, tool, nil)
					results <- err
				}()
				<-b.entered
			}

			for range tt.before {
				start(drainToolOld, old)
			}
			if tt.addNamed {
				c.AddNamed("extra", &stubBackend{name: "extra"})
			}
			drained := c.Swap(map[string]ToolBackend{"new": next}, nil)
			for range tt.after {
				start(drainToolNew, next)
			}

			for i := range tt.before {
				if isClosed(drained) {
					t.Fatalf("drained is closed while %d call(s) still run on the replaced children", tt.before-i)
				}
				old.release <- struct{}{}
				if err := <-results; err != nil {
					t.Fatalf("call on the replaced children: %v", err)
				}
			}
			if !isClosed(drained) {
				t.Error("drained is not closed although no call runs on the replaced children any more")
			}

			for range tt.after {
				next.release <- struct{}{}
				if err := <-results; err != nil {
					t.Fatalf("call on the new children: %v", err)
				}
			}
		})
	}
}

// retirableBackend counts, in late, the calls that reach it after it was
// marked retired, or that are still running when it is.
type retirableBackend struct {
	retired atomic.Bool
	late    *atomic.Int64
}

func (b *retirableBackend) Execute(_ context.Context, _ string, _ map[string]any) (*ToolResult, error) {
	if b.retired.Load() {
		b.late.Add(1)
	}
	result := &ToolResult{Content: []any{}}
	if b.retired.Load() {
		b.late.Add(1)
	}
	return result, nil
}

func (b *retirableBackend) ListTools(_ context.Context) ([]ToolDescriptor, error) { return nil, nil }
func (b *retirableBackend) Healthy(_ context.Context) error                       { return nil }

// No call reaches a backend once the channel of the swap that replaced it is
// closed, with calls and swaps racing each other. A call that loaded the
// state just before a swap is counted on the new state instead (see enter).
// Run with -race for the data races as well.
func TestCompositeBackend_SwapDrainedNoLateCalls(t *testing.T) {
	const (
		callers = 8
		swaps   = 500
	)
	var late atomic.Int64
	cur := &retirableBackend{late: &late}
	c := NewCompositeBackend(map[string]ToolBackend{"b": cur})
	ctx := context.Background()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := c.Execute(ctx, "b_t", nil); err != nil {
					t.Errorf("Execute: %v", err)
					return
				}
			}
		}()
	}

	for range swaps {
		next := &retirableBackend{late: &late}
		drained := c.Swap(map[string]ToolBackend{"b": next}, nil)
		select {
		case <-drained:
		case <-time.After(5 * time.Second):
			close(stop)
			wg.Wait()
			t.Fatal("drained not closed within 5s of the swap")
		}
		cur.retired.Store(true)
		cur = next
	}
	close(stop)
	wg.Wait()

	if n := late.Load(); n > 0 {
		t.Errorf("%d time(s) a call ran on a backend after the channel of its swap was closed", n)
	}
}

// No call counted on a tracker runs while its drained channel is closed,
// with calls returning and entering while the tracker is retired. A call
// that returns as the last one, just as another call enters and a swap
// retires the tracker, must not close drained: the call that entered is
// still running on the replaced children.
func TestCallTracker_DrainedWhileCallRuns(t *testing.T) {
	const (
		callers = 8
		rounds  = 500
	)
	var cur atomic.Pointer[callTracker]
	cur.Store(newCallTracker())

	var early atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// As CompositeBackend.enter: count the call, then make
				// sure the tracker was not replaced in between.
				tr := cur.Load()
				tr.begin()
				if cur.Load() != tr {
					tr.done()
					continue
				}
				if isClosed(tr.drained) {
					early.Add(1)
				}
				tr.done()
			}
		}()
	}

	for range rounds {
		old := cur.Swap(newCallTracker())
		select {
		case <-old.retire():
		case <-time.After(5 * time.Second):
			close(stop)
			wg.Wait()
			t.Fatal("drained not closed within 5s of retiring the tracker")
		}
	}
	close(stop)
	wg.Wait()

	if n := early.Load(); n > 0 {
		t.Errorf("%d time(s) a call was running on a tracker whose drained channel was closed", n)
	}
}
