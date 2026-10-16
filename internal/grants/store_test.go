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

package grants

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// storeFactories build each Store implementation on a clock the test moves.
// The Redis store runs on miniredis, whose own key expiry is moved along.
var storeFactories = map[string]func(t *testing.T, clock *testClock) (Store, func(time.Duration)){
	"memory": func(_ *testing.T, clock *testClock) (Store, func(time.Duration)) {
		s := NewMemoryStore()
		s.now = clock.now
		return s, clock.advance
	},
	"redis": func(t *testing.T, clock *testClock) (Store, func(time.Duration)) {
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rdb.Close() })
		s := NewRedisStore(rdb)
		s.now = clock.now
		return s, func(d time.Duration) {
			clock.advance(d)
			mr.FastForward(d)
		}
	},
}

// testGrant returns a grant of the kit for bob as the caller, expiring
// after ttl.
func testGrant(id, state, kit, callerID string, ttl time.Duration) Grant {
	return Grant{
		ID: id, State: state, Kit: kit, UserID: testUser, CallerID: callerID,
		Reason: testReason, TTL: ttl, RequestedAt: t0, ExpiresAt: t0.Add(ttl),
	}
}

func ids(gs []Grant) []string {
	out := make([]string, len(gs))
	for i, g := range gs {
		out[i] = g.ID
	}
	return out
}

func TestStore(t *testing.T) {
	for name, factory := range storeFactories {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			clock := newTestClock()
			store, advance := factory(t, clock)

			for _, g := range []Grant{
				testGrant("p1", StatePending, testKitNetDiag, testCaller, time.Hour),
				testGrant("p2", StatePending, testKitAdmin, testOtherCall, 10*time.Minute),
				testGrant("a1", StateActive, testKitNetDiag, testCaller, 2*time.Hour),
			} {
				if err := store.Put(ctx, g); err != nil {
					t.Fatalf("Put(%s): %v", g.ID, err)
				}
			}

			if g, err := store.Get(ctx, StatePending, "p1"); err != nil || g.Kit != testKitNetDiag || g.Reason != testReason || !g.ExpiresAt.Equal(t0.Add(time.Hour)) {
				t.Errorf("Get(p1) = %+v, %v", g, err)
			}
			if _, err := store.Get(ctx, StateActive, "p1"); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(p1) as active: err = %v, want ErrNotFound: states are apart", err)
			}

			mine, err := store.ForSubject(ctx, StatePending, Subject{UserID: testUser, Binding: testCaller})
			if err != nil || !slices.Equal(ids(mine), []string{"p1"}) {
				t.Errorf("ForSubject = %v, %v; want only p1: the same user as another caller is another subject", ids(mine), err)
			}
			all, err := store.List(ctx, StatePending)
			if err != nil || !slices.Equal(ids(all), []string{"p1", "p2"}) {
				t.Errorf("List(pending) = %v, %v", ids(all), err)
			}

			// Take hands out a grant once.
			if g, err := store.Take(ctx, StateActive, "a1"); err != nil || g.ID != "a1" {
				t.Errorf("Take(a1) = %+v, %v", g, err)
			}
			if _, err := store.Take(ctx, StateActive, "a1"); !errors.Is(err, ErrNotFound) {
				t.Errorf("second Take(a1): err = %v, want ErrNotFound", err)
			}
			if active, _ := store.ForSubject(ctx, StateActive, Subject{UserID: testUser, Binding: testCaller}); len(active) != 0 {
				t.Errorf("a1 still listed after Take: %v", ids(active))
			}

			// p2 expires after 10 minutes, p1 stays.
			advance(10 * time.Minute)
			if _, err := store.Get(ctx, StatePending, "p2"); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get(p2) after expiry: err = %v, want ErrNotFound", err)
			}
			if _, err := store.Take(ctx, StatePending, "p2"); !errors.Is(err, ErrNotFound) {
				t.Errorf("Take(p2) after expiry: err = %v, want ErrNotFound", err)
			}
			if all, _ := store.List(ctx, StatePending); !slices.Equal(ids(all), []string{"p1"}) {
				t.Errorf("List after p2 expired = %v, want [p1]", ids(all))
			}
		})
	}
}

// A grant in a subject hash that outlives the others must not keep an
// expired one readable.
func TestStore_ExpiredGrantInLiveHash(t *testing.T) {
	for name, factory := range storeFactories {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, advance := factory(t, newTestClock())
			_ = store.Put(ctx, testGrant("short", StateActive, testKitAdmin, testCaller, 10*time.Minute))
			_ = store.Put(ctx, testGrant("long", StateActive, testKitNetDiag, testCaller, 4*time.Hour))
			advance(11 * time.Minute)
			got, err := store.ForSubject(ctx, StateActive, Subject{UserID: testUser, Binding: testCaller})
			if err != nil || !slices.Equal(ids(got), []string{"long"}) {
				t.Errorf("ForSubject = %v, %v; want [long]", ids(got), err)
			}
		})
	}
}

// A grant that is already over is not stored.
func TestStore_PutExpired(t *testing.T) {
	for name, factory := range storeFactories {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, _ := factory(t, newTestClock())
			g := testGrant("gone", StatePending, testKitAdmin, testCaller, time.Hour)
			g.ExpiresAt = t0
			_ = store.Put(ctx, g)
			if _, err := store.Get(ctx, StatePending, "gone"); !errors.Is(err, ErrNotFound) {
				t.Errorf("Get: err = %v, want ErrNotFound", err)
			}
		})
	}
}

func TestSubjectKey_Distinct(t *testing.T) {
	a := Subject{UserID: "a|b", Binding: "c"}.key()
	b := Subject{UserID: "a", Binding: "b|c"}.key()
	if a == b {
		t.Errorf("subjects share the key %q", a)
	}
	if strings.ContainsAny(Subject{UserID: "{x}", Binding: "*"}.key(), "{}*") {
		t.Error("a subject key must not contain hash-tag braces or glob characters")
	}
}

func TestNewID(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 10 || strings.ToLower(id) != id || seen[id] {
			t.Fatalf("id %q: want 10 lower-case characters, unique", id)
		}
		seen[id] = true
	}
}

func TestFormatTTL(t *testing.T) {
	tests := map[time.Duration]string{
		0:                       "",
		4 * time.Hour:           "4h",
		90 * time.Minute:        "90m",
		90*time.Second + 500000: "1m30.0005s",
	}
	for d, want := range tests {
		if got := FormatTTL(d); got != want {
			t.Errorf("FormatTTL(%s) = %q, want %q", d, got, want)
		}
	}
}

func TestParseTTL(t *testing.T) {
	tests := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},
		{" 4h ", 4 * time.Hour, false},
		{"45m", 45 * time.Minute, false},
		{"0s", 0, true},
		{"-1h", 0, true},
		{"4 hours", 0, true},
	}
	for _, tc := range tests {
		got, err := ParseTTL(tc.in)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("ParseTTL(%q) = %s, %v", tc.in, got, err)
		}
	}
}

func TestStore_AddPending(t *testing.T) {
	for name, factory := range storeFactories {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, advance := factory(t, newTestClock())
			first := testGrant("p1", StatePending, testKitNetDiag, testCaller, RequestTTL)
			if _, found, err := store.AddPending(ctx, first, 2); err != nil || found {
				t.Fatalf("AddPending(p1) = found %v, %v", found, err)
			}
			// The same kit again: the pending one, nothing stored.
			again := testGrant("p2", StatePending, testKitNetDiag, testCaller, RequestTTL)
			existing, found, err := store.AddPending(ctx, again, 2)
			if err != nil || !found || existing.ID != "p1" {
				t.Errorf("AddPending(same kit) = %+v found %v, %v; want p1", existing, found, err)
			}
			if _, err := store.Get(ctx, StatePending, "p2"); !errors.Is(err, ErrNotFound) {
				t.Errorf("the duplicate was stored: %v", err)
			}
			if _, _, err := store.AddPending(ctx, testGrant("p3", StatePending, testKitAdmin, testCaller, RequestTTL), 2); err != nil {
				t.Fatalf("AddPending(p3): %v", err)
			}
			if _, _, err := store.AddPending(ctx, testGrant("p4", StatePending, "third", testCaller, RequestTTL), 2); !errors.Is(err, ErrLimit) {
				t.Errorf("AddPending over the limit: err = %v, want ErrLimit", err)
			}
			// Another caller of the same user has a limit of its own.
			if _, _, err := store.AddPending(ctx, testGrant("o1", StatePending, "third", testOtherCall, RequestTTL), 2); err != nil {
				t.Errorf("AddPending for another caller: %v", err)
			}
			// Lapsed requests do not count.
			advance(RequestTTL)
			if _, found, err := store.AddPending(ctx, testGrant("p5", StatePending, testKitNetDiag, testCaller, RequestTTL), 2); err != nil || found {
				t.Errorf("AddPending after the others lapsed = found %v, %v", found, err)
			}
		})
	}
}

// Of concurrent requests, no more than the limit and one per kit get in.
func TestStore_AddPendingConcurrent(t *testing.T) {
	for name, factory := range storeFactories {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store, _ := factory(t, newTestClock())
			const callers = 20
			var wg sync.WaitGroup
			for i := range callers {
				wg.Add(2)
				go func() {
					defer wg.Done()
					_, _, _ = store.AddPending(ctx, testGrant(fmt.Sprintf("k%02d", i), StatePending, fmt.Sprintf("kit%02d", i), testCaller, RequestTTL), MaxPending)
				}()
				go func() {
					defer wg.Done()
					_, _, _ = store.AddPending(ctx, testGrant(fmt.Sprintf("s%02d", i), StatePending, testKitNetDiag, testOtherCall, RequestTTL), MaxPending)
				}()
			}
			wg.Wait()
			if got, _ := store.ForSubject(ctx, StatePending, Subject{UserID: testUser, Binding: testCaller}); len(got) != MaxPending {
				t.Errorf("%d requests got in for distinct kits, want %d", len(got), MaxPending)
			}
			if got, _ := store.ForSubject(ctx, StatePending, Subject{UserID: testUser, Binding: testOtherCall}); len(got) != 1 {
				t.Errorf("%d requests got in for one kit, want 1", len(got))
			}
		})
	}
}

// Writes remove the lapsed entries of a subject hash, so that a caller who
// asks again and again does not pile them up.
func TestRedisStore_PrunesLapsedEntries(t *testing.T) {
	ctx := context.Background()
	clock := newTestClock()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	store := NewRedisStore(rdb)
	store.now = clock.now

	subject := Subject{UserID: testUser, Binding: testCaller}
	hash := subjectKey(StatePending, subject.key())
	for i := range 4 {
		g := testGrant(fmt.Sprintf("r%d", i), StatePending, fmt.Sprintf("kit%d", i), testCaller, RequestTTL)
		g.ExpiresAt = clock.now().Add(RequestTTL)
		if _, _, err := store.AddPending(ctx, g, MaxPending); err != nil {
			t.Fatal(err)
		}
		clock.advance(RequestTTL) // the request lapses; the hash would live on
	}
	if n, _ := rdb.HLen(ctx, hash).Result(); n != 1 {
		t.Errorf("hash holds %d entries, want only the last one", n)
	}
	// A read removes what has lapsed since.
	if got, _ := store.ForSubject(ctx, StatePending, subject); len(got) != 0 {
		t.Errorf("ForSubject = %v, want none", ids(got))
	}
	if n, _ := rdb.HLen(ctx, hash).Result(); n != 0 {
		t.Errorf("hash holds %d entries after the read, want none", n)
	}
}
