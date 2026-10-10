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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const (
	testLoginIP      = "203.0.113.7"
	testLoginOtherIP = "198.51.100.9"
	testLoginAccount = "alice"
)

// quietRedisLog drops the Redis client's own log lines. The outage tests
// would otherwise fill the test output with its dial errors.
type quietRedisLog struct{}

func (quietRedisLog) Printf(context.Context, string, ...any) {}

func init() { redis.SetLogger(quietRedisLog{}) }

// throttleBackend builds a LoginThrottle on one of the two counter backends
// and moves that backend's clock, so every behavioral test runs against both.
type throttleBackend struct {
	name    string
	new     func(t *testing.T, cfg LoginThrottleConfig) *LoginThrottle
	advance func(d time.Duration)
}

func throttleBackends(t *testing.T) []throttleBackend {
	t.Helper()

	now := time.Unix(1_700_000_000, 0)
	local := throttleBackend{
		name: "local",
		new: func(_ *testing.T, cfg LoginThrottleConfig) *LoginThrottle {
			th := NewLoginThrottle(cfg, nil, discardLogger())
			th.now = func() time.Time { return now }
			return th
		},
		advance: func(d time.Duration) { now = now.Add(d) },
	}

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	shared := throttleBackend{
		name: "redis",
		new: func(_ *testing.T, cfg LoginThrottleConfig) *LoginThrottle {
			mr.FlushAll()
			return NewLoginThrottle(cfg, rdb, discardLogger())
		},
		advance: mr.FastForward,
	}

	return []throttleBackend{local, shared}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// fail records n failed login attempts and reports how many were let through
// to password verification.
func fail(th *LoginThrottle, account, ip string, n int) int {
	allowed := 0
	for range n {
		if th.Acquire(context.Background(), account, ip).Allowed {
			allowed++
		}
	}
	return allowed
}

func TestLoginThrottle_PerUserLimit(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute})
			ctx := context.Background()

			if got := fail(th, testLoginAccount, testLoginIP, 3); got != 3 {
				t.Fatalf("first 3 attempts: %d allowed, want 3", got)
			}

			// A different address does not help: the account itself is locked.
			blocked := th.Acquire(ctx, testLoginAccount, testLoginOtherIP)
			if blocked.Allowed {
				t.Fatal("4th attempt on the account was allowed")
			}
			if blocked.Scope != LoginScopeUser {
				t.Errorf("Scope = %q, want %q", blocked.Scope, LoginScopeUser)
			}
			if blocked.RetryAfter <= 0 || blocked.RetryAfter > time.Minute {
				t.Errorf("RetryAfter = %v, want within (0, 1m]", blocked.RetryAfter)
			}

			if !th.Acquire(ctx, "bob", testLoginIP).Allowed {
				t.Error("another account from the same address should not be locked")
			}

			be.advance(time.Minute + time.Second)
			if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
				t.Error("account should be usable again once the window has passed")
			}
		})
	}
}

func TestLoginThrottle_PerIPLimit(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: 100, MaxFailuresPerIP: 3, Window: time.Minute})
			ctx := context.Background()

			// Rotating the username does not evade the per-address limit.
			for i := range 3 {
				if !th.Acquire(ctx, fmt.Sprintf("user-%d", i), testLoginIP).Allowed {
					t.Fatalf("attempt %d should be allowed", i+1)
				}
			}
			blocked := th.Acquire(ctx, "user-new", testLoginIP)
			if blocked.Allowed {
				t.Fatal("4th attempt from the address was allowed")
			}
			if blocked.Scope != LoginScopeIP {
				t.Errorf("Scope = %q, want %q", blocked.Scope, LoginScopeIP)
			}

			if !th.Acquire(ctx, "user-new", testLoginOtherIP).Allowed {
				t.Error("another address should not be blocked")
			}
		})
	}
}

// A blocked attempt must not be charged to the other counter, or hammering a
// locked account would lock the address as well and extend nothing but noise.
func TestLoginThrottle_BlockedAttemptChargesNothing(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: 2, MaxFailuresPerIP: 5, Window: time.Minute})

			if got := fail(th, testLoginAccount, testLoginIP, 10); got != 2 {
				t.Fatalf("attempts on one account: %d allowed, want 2", got)
			}
			// The address was charged twice, so three slots are left.
			allowed := 0
			for i := range 10 {
				if th.Acquire(context.Background(), fmt.Sprintf("other-%d", i), testLoginIP).Allowed {
					allowed++
				}
			}
			if allowed != 3 {
				t.Errorf("remaining attempts from the address: %d allowed, want 3", allowed)
			}
		})
	}
}

// The window runs from the first failed attempt and is not pushed out by
// later ones, so a lockout always ends.
func TestLoginThrottle_WindowStartsAtFirstFailure(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: 2, Window: time.Minute})
			ctx := context.Background()

			fail(th, testLoginAccount, testLoginIP, 1)
			be.advance(40 * time.Second)
			fail(th, testLoginAccount, testLoginIP, 1)

			blocked := th.Acquire(ctx, testLoginAccount, testLoginIP)
			if blocked.Allowed {
				t.Fatal("3rd attempt was allowed")
			}
			if blocked.RetryAfter > 20*time.Second {
				t.Errorf("RetryAfter = %v, want at most the 20s left of the window", blocked.RetryAfter)
			}

			be.advance(10 * time.Second)
			if th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
				t.Fatal("blocked attempts must not end the lockout early")
			}
			be.advance(11 * time.Second)
			if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
				t.Error("lockout should end 60s after the first failure")
			}
		})
	}
}

func TestLoginThrottle_SuccessClearsUserAndRefundsIP(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 4, Window: time.Minute})
			ctx := context.Background()

			fail(th, testLoginAccount, testLoginIP, 2)

			ok := th.Acquire(ctx, testLoginAccount, testLoginIP)
			if !ok.Allowed {
				t.Fatal("3rd attempt should be allowed")
			}
			th.Success(ctx, ok)

			// The account starts over: three more attempts from a fresh address.
			if got := fail(th, testLoginAccount, testLoginOtherIP, 5); got != 3 {
				t.Errorf("after a successful login: %d attempts allowed, want 3", got)
			}

			// The address keeps its two failures; only the successful attempt
			// was refunded, so two of four slots are left.
			allowed := 0
			for i := range 5 {
				if th.Acquire(ctx, fmt.Sprintf("other-%d", i), testLoginIP).Allowed {
					allowed++
				}
			}
			if allowed != 2 {
				t.Errorf("attempts left for the address: %d, want 2 (a success must not erase earlier failures)", allowed)
			}
		})
	}
}

// An attempt whose password could not be checked is handed back with Cancel.
// It must leave no trace: neither a charge, however often that happens, nor
// the clean slate a successful login gives the account.
func TestLoginThrottle_CancelRefundsWithoutClearing(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUserIP: 2, MaxFailuresPerUser: 3, MaxFailuresPerIP: 4, Window: time.Minute})
			ctx := context.Background()

			fail(th, testLoginAccount, testLoginIP, 1)

			// Far more canceled attempts than any of the limits allows.
			for i := range 10 {
				attempt := th.Acquire(ctx, testLoginAccount, testLoginIP)
				if !attempt.Allowed {
					t.Fatalf("attempt %d was refused: canceled attempts were charged", i+1)
				}
				th.Cancel(ctx, attempt)
			}

			// The failure from before still counts: one more reaches the
			// limit of two for this account from this address.
			if got := fail(th, testLoginAccount, testLoginIP, 3); got != 1 {
				t.Errorf("after the canceled attempts: %d attempts allowed, want 1 (Cancel must not clear earlier failures)", got)
			}
		})
	}
}

func TestLoginThrottle_DisabledLimits(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			off := be.new(t, LoginThrottleConfig{Window: time.Minute})
			if got := fail(off, testLoginAccount, testLoginIP, 50); got != 50 {
				t.Errorf("both limits disabled: %d of 50 allowed", got)
			}

			ipOnly := be.new(t, LoginThrottleConfig{MaxFailuresPerIP: 2, Window: time.Minute})
			if got := fail(ipOnly, testLoginAccount, testLoginIP, 5); got != 2 {
				t.Errorf("per-IP only: %d allowed, want 2", got)
			}
			if !ipOnly.Acquire(context.Background(), testLoginAccount, testLoginOtherIP).Allowed {
				t.Error("per-IP only: the account must not be locked for other addresses")
			}

			// Success on an attempt that reserved nothing must be a no-op.
			off.Success(context.Background(), LoginAttempt{Allowed: true})
			off.Success(context.Background(), LoginAttempt{})
		})
	}
}

// Parallel guesses must not all pass a check made before any of them was
// recorded: with a limit of N, exactly N reach password verification.
func TestLoginThrottle_ConcurrentAttemptsCannotExceedLimit(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			const limit, attempts = 5, 60
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUser: limit, MaxFailuresPerIP: 1000, Window: time.Minute})

			var wg sync.WaitGroup
			var mu sync.Mutex
			allowed := 0
			for range attempts {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if th.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
						mu.Lock()
						allowed++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()

			if allowed != limit {
				t.Errorf("%d of %d concurrent attempts allowed, want exactly %d", allowed, attempts, limit)
			}
		})
	}
}

// syncBuffer lets the test read log output that handlers write concurrently.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A Redis outage must degrade to process-local throttling with a warning,
// never to unlimited attempts.
func TestLoginThrottle_RedisErrorFallsBackToLocal(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, logger)

	mr.Close()

	if got := fail(th, testLoginAccount, testLoginIP, 10); got != 3 {
		t.Fatalf("with Redis down: %d attempts allowed, want 3", got)
	}
	// The first attempt that cannot reach Redis says so. The ones after it are
	// decided by the local table without asking Redis again, since it now
	// holds charges Redis never saw.
	if n := strings.Count(logs.String(), "Redis unavailable"); n != 1 {
		t.Errorf("fallback warnings logged: %d, want 1\n%s", n, logs.String())
	}
	if !strings.Contains(logs.String(), "level=WARN") {
		t.Errorf("fallback must be logged at WARN:\n%s", logs.String())
	}

	// An attempt on counters the local table does not hold yet asks Redis
	// again, and reports the failure again.
	fail(th, "bob", testLoginOtherIP, 1)
	if n := strings.Count(logs.String(), "Redis unavailable"); n != 2 {
		t.Errorf("fallback warnings logged: %d, want 2 after an attempt on fresh counters", n)
	}
}

// A slot reserved in the process-local table during a Redis outage must not
// be refunded from the Redis counter once Redis is back: that would erase a
// failure another attempt put there.
func TestLoginThrottle_SuccessRefundsOnlyWhereReserved(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 5, MaxFailuresPerIP: 5, Window: time.Minute}, rdb, discardLogger())
	ctx := context.Background()

	fail(th, "mallory", testLoginIP, 2) // two failures recorded in Redis

	mr.Close()
	local := th.Acquire(ctx, testLoginAccount, testLoginIP)
	if !local.Allowed {
		t.Fatal("attempt during the outage should be allowed by the local table")
	}
	if err := mr.Restart(); err != nil {
		t.Fatalf("restart miniredis: %v", err)
	}
	th.Success(ctx, local)

	got, err := mr.Get(loginIPKey(testLoginIP))
	if err != nil {
		t.Fatalf("read IP counter: %v", err)
	}
	if got != "2" {
		t.Errorf("Redis IP counter = %s, want 2 (the slot was never reserved there)", got)
	}
}

// A counter that somehow lost its expiry must not lock an account forever.
func TestLoginThrottle_RedisCounterWithoutTTLIsRepaired(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, Window: time.Minute}, rdb, discardLogger())
	ctx := context.Background()

	key := loginUserKey(testLoginAccount)
	if err := mr.Set(key, "3"); err != nil {
		t.Fatal(err)
	}

	blocked := th.Acquire(ctx, testLoginAccount, testLoginIP)
	if blocked.Allowed {
		t.Fatal("exhausted counter should block")
	}
	if blocked.RetryAfter != time.Minute {
		t.Errorf("RetryAfter = %v, want the full window", blocked.RetryAfter)
	}
	if ttl := mr.TTL(key); ttl != time.Minute {
		t.Errorf("TTL after repair = %v, want 1m", ttl)
	}

	mr.FastForward(time.Minute + time.Second)
	if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Error("account should be usable again after the repaired window")
	}
}

func TestLoginThrottle_RedisCountersExpire(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 3, Window: 90 * time.Second}, rdb, discardLogger())
	fail(th, testLoginAccount, testLoginIP, 2)

	for _, key := range []string{loginUserKey(testLoginAccount), loginIPKey(testLoginIP)} {
		if ttl := mr.TTL(key); ttl != 90*time.Second {
			t.Errorf("TTL(%s) = %v, want 90s", key, ttl)
		}
	}
}

func TestLocalLoginCounters_CapEvictsAndReportsOnce(t *testing.T) {
	const capacity = 20
	now := time.Unix(1_700_000_000, 0)

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, Window: time.Minute}, nil, logger)
	th.local = newLocalLoginCounters(capacity)
	th.now = func() time.Time { return now }

	// Fill the table, let everything expire, and fill it again: expired
	// counters make room without any warning.
	for i := range capacity {
		fail(th, fmt.Sprintf("first-%d", i), testLoginIP, 1)
	}
	now = now.Add(2 * time.Minute)
	for i := range capacity {
		fail(th, fmt.Sprintf("second-%d", i), testLoginIP, 1)
	}
	if got := len(th.local.entries); got != capacity {
		t.Fatalf("entries after refill = %d, want %d", got, capacity)
	}
	if logs.String() != "" {
		t.Fatalf("sweeping expired counters must not warn:\n%s", logs.String())
	}

	// Now the table is full of live counters: new names evict, and the
	// warning appears once although the overflow repeats.
	for i := range 5 * capacity {
		fail(th, fmt.Sprintf("flood-%d", i), testLoginIP, 1)
		if got := len(th.local.entries); got > capacity {
			t.Fatalf("entries = %d, exceeds the cap of %d", got, capacity)
		}
	}
	if n := strings.Count(logs.String(), "counter table is full"); n != 1 {
		t.Errorf("eviction warnings = %d, want exactly 1 within the log interval\n%s", n, logs.String())
	}

	// After the interval the next eviction is reported again.
	now = now.Add(localEvictionLogInterval)
	for i := range 5 * capacity {
		fail(th, fmt.Sprintf("later-%d", i), testLoginIP, 1)
	}
	if n := strings.Count(logs.String(), "counter table is full"); n != 2 {
		t.Errorf("eviction warnings = %d, want 2 after the interval passed", n)
	}
}

func TestNormalizeLoginIP(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{testLoginIP, testLoginIP},
		{"::ffff:" + testLoginIP, testLoginIP},
		{"2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"fe80::1%eth0", "fe80::/64"},
		{"not-an-ip", loginIPUnknown},
		{"", loginIPUnknown},
	}
	for _, tt := range tests {
		if got := normalizeLoginIP(tt.in); got != tt.want {
			t.Errorf("normalizeLoginIP(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Two hosts in one IPv6 /64 share a counter; an attacker with a routed /64
// gets no more attempts than one with a single IPv4 address.
func TestLoginThrottle_IPv6CountsPerNetwork(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerIP: 2, Window: time.Minute})
			ctx := context.Background()

			if !th.Acquire(ctx, "a", "2001:db8:1:2::1").Allowed || !th.Acquire(ctx, "b", "2001:db8:1:2:ffff::2").Allowed {
				t.Fatal("first two attempts from the /64 should be allowed")
			}
			if th.Acquire(ctx, "c", "2001:db8:1:2:abcd::3").Allowed {
				t.Error("a third address in the same /64 must share the exhausted counter")
			}
			if !th.Acquire(ctx, "c", "2001:db8:1:3::1").Allowed {
				t.Error("a different /64 must not be blocked")
			}
		})
	}
}

func TestLoginUserKey_BoundedAndDistinct(t *testing.T) {
	long := strings.Repeat("x", 1<<20)
	if got := len(loginUserKey(long)); got > 128 {
		t.Errorf("key length for a 1 MiB username = %d, want a bounded key", got)
	}
	if loginUserKey("alice") == loginUserKey("Alice") {
		t.Error("distinct usernames must not share a counter")
	}
	if strings.Contains(loginUserKey("alice"), "alice") {
		t.Error("the username must not appear in the counter key")
	}
}

// A client that aborts its request must not be able to push its attempt onto
// the process-local counters: the Redis operation runs detached from the
// request's cancellation.
func TestLoginThrottle_CanceledRequestStillUsesRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, Window: time.Minute}, rdb, logger)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	allowed := 0
	for range 10 {
		if th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("attempts with a canceled request context: %d allowed, want 3", allowed)
	}
	if got, _ := mr.Get(loginUserKey(testLoginAccount)); got != "3" {
		t.Errorf("Redis counter = %q, want 3 (the attempts must be charged in Redis)", got)
	}
	if logs.String() != "" {
		t.Errorf("a canceled request must not be reported as a Redis outage:\n%s", logs.String())
	}
}

// What Redis decided for this process is mirrored locally, so an outage does
// not hand out a fresh set of attempts or lift a lockout.
func TestLoginThrottle_FallbackContinuesFromMirroredState(t *testing.T) {
	newThrottle := func(t *testing.T) (*LoginThrottle, *miniredis.Miniredis) {
		t.Helper()
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
		t.Cleanup(func() { _ = rdb.Close() })
		return NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, discardLogger()), mr
	}

	t.Run("partial count carries over", func(t *testing.T) {
		th, mr := newThrottle(t)
		fail(th, testLoginAccount, testLoginIP, 2)
		mr.Close()
		if got := fail(th, testLoginAccount, testLoginIP, 5); got != 1 {
			t.Errorf("after 2 failures with Redis up: %d more allowed during the outage, want 1", got)
		}
	})

	t.Run("lockout carries over", func(t *testing.T) {
		th, mr := newThrottle(t)
		fail(th, testLoginAccount, testLoginIP, 3)
		if th.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
			t.Fatal("4th attempt should be blocked by Redis")
		}
		mr.Close()
		if got := fail(th, testLoginAccount, testLoginIP, 5); got != 0 {
			t.Errorf("locked account: %d attempts allowed during the outage, want 0", got)
		}
	})

	// A replica that never saw the failures itself learns of the lockout from
	// Redis and must still hold it when Redis goes away.
	t.Run("lockout learned from Redis carries over", func(t *testing.T) {
		mr := miniredis.RunT(t)
		replica := func() *LoginThrottle {
			rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
			t.Cleanup(func() { _ = rdb.Close() })
			return NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, discardLogger())
		}
		first, second := replica(), replica()

		if got := fail(first, testLoginAccount, testLoginIP, 3); got != 3 {
			t.Fatalf("first replica: %d allowed, want 3", got)
		}
		if second.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
			t.Fatal("second replica should be told by Redis that the account is locked")
		}
		mr.Close()
		if got := fail(second, testLoginAccount, testLoginIP, 5); got != 0 {
			t.Errorf("second replica during the outage: %d allowed, want 0", got)
		}
	})

	t.Run("success clears the mirror too", func(t *testing.T) {
		th, mr := newThrottle(t)
		fail(th, testLoginAccount, testLoginIP, 2)
		ok := th.Acquire(context.Background(), testLoginAccount, testLoginIP)
		th.Success(context.Background(), ok)
		mr.Close()
		if got := fail(th, testLoginAccount, testLoginIP, 5); got != 3 {
			t.Errorf("after a successful login: %d allowed during the outage, want a fresh 3", got)
		}
	})
}

// Filling the table with made-up usernames must not lift an existing lockout,
// and making room must never drop the counters of the attempt being charged.
func TestLocalLoginCounters_EvictionSparesExhaustedCounters(t *testing.T) {
	const capacity = 20
	now := time.Unix(1_700_000_000, 0)
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, Window: time.Hour}, nil, discardLogger())
	th.local = newLocalLoginCounters(capacity)
	th.now = func() time.Time { return now }

	if got := fail(th, testLoginAccount, testLoginIP, 5); got != 3 {
		t.Fatalf("lock the account: %d allowed, want 3", got)
	}
	for i := range 50 * capacity {
		fail(th, fmt.Sprintf("flood-%d", i), testLoginIP, 1)
	}
	if th.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
		t.Error("the lockout was lifted by flooding the table with other usernames")
	}
	if got := len(th.local.entries); got > capacity {
		t.Errorf("entries = %d, exceeds the cap of %d", got, capacity)
	}
}

func TestLocalLoginCounters_MakeRoomKeepsCurrentAttempt(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLocalLoginCounters(4)
	user := loginCounter{scope: LoginScopeUser, key: "user", limit: 5}
	ip := loginCounter{scope: LoginScopeIP, key: "ip", limit: 5}

	// The user counter exists with two failures. Three unrelated counters fill
	// the rest of the table and are exhausted, so the user counter is the only
	// one the first eviction pass would pick — if it were not protected.
	l.acquire([]loginCounter{user}, time.Hour, now)
	l.acquire([]loginCounter{user}, time.Hour, now)
	for i := range 3 {
		l.acquire([]loginCounter{{scope: LoginScopeUser, key: fmt.Sprintf("other-%d", i), limit: 1}}, time.Hour, now)
	}

	// Charging user+ip needs room for the ip counter. Whatever is dropped, it
	// must not be the user counter, or its two failures would be forgotten.
	l.acquire([]loginCounter{user, ip}, time.Hour, now)
	if got := l.entries["user"].count; got != 3 {
		t.Errorf("user counter = %d, want 3 (it must survive making room for its own attempt)", got)
	}
	if got := len(l.entries); got > 4 {
		t.Errorf("entries = %d, exceeds the cap of 4", got)
	}
}

// When every counter in a full table is exhausted there is nothing harmless
// left to drop. The cap still holds, and the attempt being charged still gets
// its counter.
func TestLocalLoginCounters_CapHoldsWhenAllCountersAreExhausted(t *testing.T) {
	const capacity = 8
	now := time.Unix(1_700_000_000, 0)
	l := newLocalLoginCounters(capacity)

	for i := range 4 * capacity {
		c := loginCounter{scope: LoginScopeUser, key: fmt.Sprintf("locked-%d", i), limit: 1}
		if blocked, _, _ := l.acquire([]loginCounter{c}, time.Hour, now); blocked != -1 {
			t.Fatalf("first attempt on %s was blocked", c.key)
		}
		if got := len(l.entries); got > capacity {
			t.Fatalf("entries = %d after %d keys, exceeds the cap of %d", got, i+1, capacity)
		}
		if _, ok := l.entries[c.key]; !ok {
			t.Fatalf("the counter just charged (%s) is missing", c.key)
		}
	}
}

// Limits that cannot be enforced must not look like limits that are.
func TestNewLoginThrottle_WarnsWhenWindowMakesLimitsInert(t *testing.T) {
	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3}, nil, logger)
	if !strings.Contains(logs.String(), "NOT limited") {
		t.Errorf("no warning for limits without a window:\n%s", logs.String())
	}
	if got := fail(th, testLoginAccount, testLoginIP, 10); got != 10 {
		t.Errorf("%d of 10 attempts allowed without a window", got)
	}

	logs = syncBuffer{}
	NewLoginThrottle(LoginThrottleConfig{}, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, Window: time.Minute}, nil, slog.New(slog.NewTextHandler(&logs, nil)))
	if logs.String() != "" {
		t.Errorf("unexpected log output for a disabled or a valid configuration:\n%s", logs.String())
	}
}

// The limit for one account from one address must not be reachable from
// another address, and must not lock the account for the other address.
func TestLoginThrottle_PerUserIPLimit(t *testing.T) {
	for _, be := range throttleBackends(t) {
		t.Run(be.name, func(t *testing.T) {
			th := be.new(t, LoginThrottleConfig{MaxFailuresPerUserIP: 3, MaxFailuresPerUser: 100, MaxFailuresPerIP: 100, Window: time.Minute})
			ctx := context.Background()

			if got := fail(th, testLoginAccount, testLoginIP, 6); got != 3 {
				t.Fatalf("one account from one address: %d allowed, want 3", got)
			}
			blocked := th.Acquire(ctx, testLoginAccount, testLoginIP)
			if blocked.Allowed || blocked.Scope != LoginScopeUserIP {
				t.Errorf("blocked attempt: Allowed=%v Scope=%q, want false and %q", blocked.Allowed, blocked.Scope, LoginScopeUserIP)
			}

			if !th.Acquire(ctx, testLoginAccount, testLoginOtherIP).Allowed {
				t.Error("the same account from another address must not be locked")
			}
			if !th.Acquire(ctx, "bob", testLoginIP).Allowed {
				t.Error("another account from the same address must not be locked")
			}

			// A successful login from the other address clears the account's
			// counters there, not the first address's failures against it...
			ok := th.Acquire(ctx, testLoginAccount, testLoginOtherIP)
			th.Success(ctx, ok)
			if th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
				t.Error("a login from elsewhere must not lift the lockout of the address that was guessing")
			}
		})
	}
}

func TestLoginKeys_ShareOneClusterSlot(t *testing.T) {
	for _, key := range []string{loginUserKey("alice"), loginUserIPKey("alice", testLoginIP), loginIPKey(testLoginIP)} {
		if !strings.Contains(key, "{login}") {
			t.Errorf("key %q lacks the common hash tag the multi-key script needs", key)
		}
	}
	if loginUserIPKey("alice", testLoginIP) == loginUserIPKey("alice", testLoginOtherIP) {
		t.Error("the same account from two addresses must not share a counter")
	}
	if loginUserIPKey("alice", "2001:db8::1") != loginUserIPKey("alice", "2001:db8::2") {
		t.Error("two hosts in one IPv6 /64 must share the account+address counter")
	}
}

// Failures counted in process memory while Redis was away must still count
// when it is back: otherwise an outage would hand out a fresh set of attempts.
func TestLoginThrottle_OutageFailuresStillCountAfterRecovery(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, discardLogger())
	ctx := context.Background()

	mr.Close()
	if got := fail(th, testLoginAccount, testLoginIP, 5); got != 3 {
		t.Fatalf("during the outage: %d allowed, want 3", got)
	}
	if err := mr.Restart(); err != nil {
		t.Fatalf("restart miniredis: %v", err)
	}

	blocked := th.Acquire(ctx, testLoginAccount, testLoginIP)
	if blocked.Allowed {
		t.Fatal("the account was locked during the outage and must stay locked once Redis is back")
	}
	if blocked.Scope != LoginScopeUser || blocked.RetryAfter <= 0 {
		t.Errorf("blocked attempt: Scope=%q RetryAfter=%v, want %q and a positive wait", blocked.Scope, blocked.RetryAfter, LoginScopeUser)
	}
	// The attempt was decided in process memory; Redis was not charged for it.
	for _, key := range []string{loginUserKey(testLoginAccount), loginIPKey(testLoginIP)} {
		if mr.Exists(key) {
			got, _ := mr.Get(key)
			t.Errorf("Redis counter %s = %s, want none for an attempt the local table decided", key, got)
		}
	}

	// Another account is not affected.
	if !th.Acquire(ctx, "bob", testLoginOtherIP).Allowed {
		t.Error("an account without failures must not be blocked")
	}
}

// A lockout that only mirrors what Redis decided is Redis's to lift: deleting
// the counter there, as the documentation tells operators to, must work
// without restarting the process.
func TestLoginThrottle_DeletingRedisCounterLiftsLockout(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	th := NewLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, discardLogger())
	ctx := context.Background()

	fail(th, testLoginAccount, testLoginIP, 3)
	if th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Fatal("4th attempt should be blocked")
	}

	mr.Del(loginUserKey(testLoginAccount))
	if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Error("deleting the counter in Redis did not lift the lockout")
	}
}

// stalledRedis accepts connections and never answers, like a Redis host that
// is up but hung.
func stalledRedis(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var conns []net.Conn
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	return ln.Addr().String()
}

// A Redis that accepts the connection and then says nothing must not hold a
// login for the client library's own, much longer, socket timeout.
func TestLoginThrottle_StalledRedisIsBoundedByTimeout(t *testing.T) {
	const timeout = 100 * time.Millisecond
	// Client options as main builds them: library defaults, no retries or
	// timeouts tuned for the test.
	rdb := redis.NewClient(&redis.Options{Addr: stalledRedis(t), Protocol: 2})
	t.Cleanup(func() { _ = rdb.Close() })

	var logs syncBuffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	th := newLoginThrottle(LoginThrottleConfig{MaxFailuresPerUser: 2, MaxFailuresPerIP: 100, Window: time.Minute}, rdb, logger, timeout)

	start := time.Now()
	first := th.Acquire(context.Background(), testLoginAccount, testLoginIP)
	elapsed := time.Since(start)

	if !first.Allowed {
		t.Fatal("first attempt should be allowed by the process-local counters")
	}
	// Generous upper bound: the point is "about the timeout", not the three
	// seconds the client would otherwise wait for a reply.
	if elapsed > 10*timeout {
		t.Errorf("Acquire took %v with a stalled Redis, want about %v", elapsed, timeout)
	}
	if !strings.Contains(logs.String(), "Redis unavailable") {
		t.Errorf("the fallback was not logged:\n%s", logs.String())
	}

	// The limit is still enforced.
	th.Acquire(context.Background(), testLoginAccount, testLoginIP)
	if th.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
		t.Error("third attempt was allowed although the limit is 2")
	}
}

// outageThrottle returns a throttle on a miniredis whose clock and the
// throttle's own clock are moved together by advance.
func outageThrottle(t *testing.T, cfg LoginThrottleConfig) (th *LoginThrottle, mr *miniredis.Miniredis, advance func(time.Duration)) {
	t.Helper()
	mr = miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 20 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	now := time.Unix(1_700_000_000, 0)
	th = NewLoginThrottle(cfg, rdb, discardLogger())
	th.now = func() time.Time { return now }
	return th, mr, func(d time.Duration) {
		now = now.Add(d)
		mr.FastForward(d)
	}
}

func restart(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	if err := mr.Restart(); err != nil {
		t.Fatalf("restart miniredis: %v", err)
	}
}

// A count that was only partly run up during an outage carries on afterwards
// exactly where it stood.
func TestLoginThrottle_OutageCountContinuesAfterRecovery(t *testing.T) {
	th, mr, _ := outageThrottle(t, LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute})

	mr.Close()
	fail(th, testLoginAccount, testLoginIP, 2)
	restart(t, mr)

	if got := fail(th, testLoginAccount, testLoginIP, 5); got != 1 {
		t.Errorf("after 2 failures during the outage: %d more allowed, want 1", got)
	}
}

// One failure counted during an outage, then a burst of parallel attempts once
// Redis is back: the outage failure must count, and the burst must neither get
// more attempts than are left nor end with the account locked while fewer
// than the limit were ever let through.
func TestLoginThrottle_BurstAfterOutageFailure(t *testing.T) {
	const limit, burst = 5, 24
	th, mr, _ := outageThrottle(t, LoginThrottleConfig{MaxFailuresPerUser: limit, MaxFailuresPerIP: 1000, Window: time.Minute})

	mr.Close()
	fail(th, testLoginAccount, testLoginIP, 1)
	restart(t, mr)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowed := 0
	for range burst {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if th.Acquire(context.Background(), testLoginAccount, testLoginIP).Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed != limit-1 {
		t.Errorf("%d of %d parallel attempts allowed, want exactly %d (the limit less the outage failure)", allowed, burst, limit-1)
	}
}

// A lockout that comes from failures counted during an outage ends when its
// window ends. Attempts made while it lasts must not push that out.
func TestLoginThrottle_OutageLockoutIsNotExtendedByBlockedAttempts(t *testing.T) {
	th, mr, advance := outageThrottle(t, LoginThrottleConfig{MaxFailuresPerUser: 3, MaxFailuresPerIP: 100, Window: time.Minute})
	ctx := context.Background()

	mr.Close()
	fail(th, testLoginAccount, testLoginIP, 3)
	restart(t, mr)

	advance(50 * time.Second)
	if got := fail(th, testLoginAccount, testLoginIP, 6); got != 0 {
		t.Fatalf("during the lockout: %d attempts allowed, want 0", got)
	}
	advance(9 * time.Second)
	if th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Fatal("the lockout ended before its window did")
	}
	advance(2 * time.Second)
	if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Error("the lockout outlasted the 60s window that began with the first failure")
	}
}

// A login that succeeds during an outage hands its slot back in the local
// table and must not leave a charge behind there that Redis does not know:
// such a charge would keep the address with the local table, and deleting the
// Redis key would no longer lift a later lockout.
func TestLoginThrottle_SuccessDuringOutageLeavesNoLocalCharge(t *testing.T) {
	th, mr, _ := outageThrottle(t, LoginThrottleConfig{MaxFailuresPerIP: 3, Window: time.Minute})
	ctx := context.Background()

	fail(th, testLoginAccount, testLoginIP, 2)
	mr.Close()
	ok := th.Acquire(ctx, testLoginAccount, testLoginIP)
	if !ok.Allowed {
		t.Fatal("third attempt should be allowed during the outage")
	}
	th.Success(ctx, ok)
	restart(t, mr)

	if got := fail(th, testLoginAccount, testLoginIP, 3); got != 1 {
		t.Fatalf("after the outage: %d attempts allowed, want 1 (two failures stand)", got)
	}
	mr.Del(loginIPKey(testLoginIP))
	if !th.Acquire(ctx, testLoginAccount, testLoginIP).Allowed {
		t.Error("deleting the Redis counter did not lift the lockout: the successful login left a local charge behind")
	}
}

// The reverse: a successful login after the outage must not erase a failure
// that was counted during it.
func TestLoginThrottle_SuccessAfterRecoveryKeepsOutageFailures(t *testing.T) {
	th, mr, _ := outageThrottle(t, LoginThrottleConfig{MaxFailuresPerIP: 3, Window: time.Minute})
	ctx := context.Background()

	mr.Close()
	fail(th, testLoginAccount, testLoginIP, 1)
	restart(t, mr)

	ok := th.Acquire(ctx, testLoginAccount, testLoginIP)
	if !ok.Allowed {
		t.Fatal("second attempt should be allowed")
	}
	th.Success(ctx, ok)

	if got := fail(th, testLoginAccount, testLoginIP, 5); got != 2 {
		t.Errorf("after the successful login: %d attempts allowed, want 2 (the outage failure still counts)", got)
	}
}

// Redis reporting a counter exhausted must not rewrite a local counter that
// holds outage charges: its count and its window are its own.
func TestLocalLoginCounters_ExhaustLeavesOutageChargesAlone(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newLocalLoginCounters(10)
	c := loginCounter{scope: LoginScopeUser, key: "user", limit: 5}

	l.acquire([]loginCounter{c}, time.Minute, now)
	before := l.entries[c.key]

	l.exhaust(c, time.Hour, now.Add(10*time.Second))
	if got := l.entries[c.key]; got != before {
		t.Errorf("entry after exhaust = %+v, want it untouched (%+v)", got, before)
	}

	// Without outage charges the counter does take Redis's verdict.
	mirrored := loginCounter{scope: LoginScopeUser, key: "mirrored", limit: 5}
	l.mirrorCharge([]loginCounter{mirrored}, time.Minute, now)
	l.exhaust(mirrored, 30*time.Second, now)
	if got := l.entries[mirrored.key]; got.count != 5 || !got.expires.Equal(now.Add(30*time.Second)) {
		t.Errorf("mirrored entry after exhaust = %+v, want count 5 expiring in 30s", got)
	}
}

// loginModel is the behavior the throttle is meant to have, written down
// naively: every counter is a count with a window that starts at its first
// charge.
type loginModel struct {
	window time.Duration
	count  map[string]int
	start  map[string]time.Time
}

func (m *loginModel) expire(key string, now time.Time) {
	if m.count[key] > 0 && !now.Before(m.start[key].Add(m.window)) {
		delete(m.count, key)
	}
}

func (m *loginModel) acquire(counters []loginCounter, now time.Time) bool {
	for _, c := range counters {
		m.expire(c.key, now)
		if m.count[c.key] >= c.limit {
			return false
		}
	}
	for _, c := range counters {
		if m.count[c.key] == 0 {
			m.start[c.key] = now
		}
		m.count[c.key]++
	}
	return true
}

func (m *loginModel) cancel(counters []loginCounter) {
	for _, c := range counters {
		if m.count[c.key]--; m.count[c.key] <= 0 {
			delete(m.count, c.key)
		}
	}
}

func (m *loginModel) success(counters []loginCounter) {
	for _, c := range counters {
		if c.scope != LoginScopeIP {
			delete(m.count, c.key)
			continue
		}
		if m.count[c.key]--; m.count[c.key] <= 0 {
			delete(m.count, c.key)
		}
	}
}

// Random sequences of failed, successful and canceled logins for a few accounts and
// addresses, with Redis going away and coming back and time passing in
// between, must be decided exactly as the naive model decides them. The walk
// stops checking once a release could not reach Redis: from then on Redis may
// hold more than was really counted, which the throttle accepts as the safe
// side but the model does not know.
func TestLoginThrottle_RandomWalkMatchesModel(t *testing.T) {
	cfg := LoginThrottleConfig{MaxFailuresPerUserIP: 2, MaxFailuresPerUser: 3, MaxFailuresPerIP: 4, Window: time.Minute}
	accounts := []string{"alice", "bob"}
	addresses := []string{testLoginIP, testLoginOtherIP}
	ctx := context.Background()

	for seed := range uint64(120) {
		rng := rand.New(rand.NewPCG(seed, 1)) //nolint:gosec // reproducible test sequence, not a secret
		mr := miniredis.RunT(t)
		rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 2 * time.Millisecond})

		var logs syncBuffer
		now := time.Unix(1_700_000_000, 0)
		th := NewLoginThrottle(cfg, rdb, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
		th.now = func() time.Time { return now }
		model := &loginModel{window: cfg.Window, count: map[string]int{}, start: map[string]time.Time{}}

		up := true
		var trace []string
	walk:
		for range 60 {
			switch r := rng.IntN(20); {
			case r < 12: // a login attempt, mostly a failed one
				account, ip := accounts[rng.IntN(len(accounts))], addresses[rng.IntN(len(addresses))]
				outcome := rng.IntN(6)
				succeeds, canceled := outcome == 0, outcome == 1
				counters := th.counters(account, ip)

				want := model.acquire(counters, now)
				attempt := th.Acquire(ctx, account, ip)
				trace = append(trace, fmt.Sprintf("t=%ds %s@%s success=%v canceled=%v -> allowed=%v", now.Unix()-1_700_000_000, account, ip, succeeds, canceled, attempt.Allowed))
				if attempt.Allowed != want {
					t.Fatalf("seed %d: throttle allowed=%v, model allowed=%v\n%s", seed, attempt.Allowed, want, strings.Join(trace, "\n"))
				}
				if attempt.Allowed && (succeeds || canceled) {
					if succeeds {
						th.Success(ctx, attempt)
						model.success(counters)
					} else {
						th.Cancel(ctx, attempt)
						model.cancel(counters)
					}
					if strings.Contains(logs.String(), "could not release") {
						break walk
					}
				}
			case r < 17:
				d := time.Duration(1+rng.IntN(25)) * time.Second
				now = now.Add(d)
				mr.FastForward(d)
				trace = append(trace, fmt.Sprintf("+%v", d))
			case up:
				mr.Close()
				up = false
				trace = append(trace, "redis down")
			default:
				if err := mr.Restart(); err != nil {
					t.Fatalf("restart miniredis: %v", err)
				}
				up = true
				trace = append(trace, "redis up")
			}
		}
		_ = rdb.Close()
		mr.Close()
	}
}
