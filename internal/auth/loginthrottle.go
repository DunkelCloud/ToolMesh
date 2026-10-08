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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Scopes of the failed-login counters; LoginAttempt.Scope names the one that
// blocked an attempt.
const (
	// LoginScopeUserIP counts failures for one account from one source address.
	LoginScopeUserIP = "user_ip"
	// LoginScopeUser counts failures for one account from all addresses together.
	LoginScopeUser = "user"
	// LoginScopeIP counts failures from one source address across all accounts.
	LoginScopeIP = "ip"
)

const (
	// prefixLoginFailures carries a hash tag so that all counters share one
	// slot on a clustered Redis: the acquire script touches several keys.
	prefixLoginFailures = "auth:{login}:failures:"

	// maxLocalLoginCounters caps the process-local counter table. Usernames
	// are attacker-chosen, so without a cap a flood of distinct names from
	// distinct addresses would grow the table without bound.
	maxLocalLoginCounters = 50_000

	// localEvictionLogInterval spaces out the warning about a full table, so
	// the flood that fills it does not also flood the log.
	localEvictionLogInterval = time.Minute

	// loginThrottleRedisTimeout bounds one counter operation in Redis, so a
	// Redis that is unreachable or does not answer delays a login by at most
	// this much per operation before the process-local counters take over. A
	// failed login makes one such operation, a successful one two.
	loginThrottleRedisTimeout = time.Second

	// loginIPUnknown is the shared counter key for a source address that
	// cannot be parsed.
	loginIPUnknown = "unknown"
)

// LoginThrottleConfig sets the failed-login limits. Each limit counts failed
// attempts within Window; a limit of 0 disables that counter.
//
// The low limit belongs on MaxFailuresPerUserIP: it stops one source from
// guessing at an account without letting that source lock the account for
// everybody else. MaxFailuresPerUser is the ceiling that bounds guessing
// spread over many addresses, and MaxFailuresPerIP bounds one address trying
// many accounts.
type LoginThrottleConfig struct {
	MaxFailuresPerUserIP int
	MaxFailuresPerUser   int
	MaxFailuresPerIP     int
	Window               time.Duration
}

// LoginAttempt is the outcome of LoginThrottle.Acquire. When Allowed is true
// it also identifies the reserved slot, so a successful login can hand it back
// with LoginThrottle.Success.
type LoginAttempt struct {
	Allowed bool
	// Scope is the counter that blocked the attempt (one of the LoginScope
	// constants); empty when Allowed.
	Scope string
	// RetryAfter is how long the blocking counter still has to run.
	RetryAfter time.Duration

	counters []loginCounter
	shared   bool // the slot is reserved in Redis, not only in process memory
}

// loginCounter is one counter an attempt is charged to.
type loginCounter struct {
	scope string
	key   string
	limit int
}

// LoginThrottle bounds how many failed password logins an account, a source
// address, and the combination of the two may accumulate within a time window.
// Counters live in Redis when a client is given, so the limits hold across
// replicas, and in process memory otherwise.
//
// A Redis error never lifts the limits: the affected call falls back to the
// process-local counters and logs a warning. Those counters mirror every
// decision Redis made for this process, so the fallback starts from what this
// process has already seen rather than from zero. A counter that was charged
// locally during an outage then stays with the process-local table until its
// window ends, even after Redis answers again: Redis never saw those charges,
// so only the local table knows the full count.
//
// A slot is reserved before the password is verified and handed back only on
// success, so concurrent attempts cannot all slip past a check made before any
// of them was recorded.
type LoginThrottle struct {
	cfg          LoginThrottleConfig
	rdb          *redis.Client
	redisTimeout time.Duration
	local        *localLoginCounters
	logger       *slog.Logger
	now          func() time.Time
}

// NewLoginThrottle creates a login throttle. rdb may be nil, which keeps all
// counters in process memory.
func NewLoginThrottle(cfg LoginThrottleConfig, rdb *redis.Client, logger *slog.Logger) *LoginThrottle {
	return newLoginThrottle(cfg, rdb, logger, loginThrottleRedisTimeout)
}

func newLoginThrottle(cfg LoginThrottleConfig, rdb *redis.Client, logger *slog.Logger, redisTimeout time.Duration) *LoginThrottle {
	if cfg.Window <= 0 && (cfg.MaxFailuresPerUserIP > 0 || cfg.MaxFailuresPerUser > 0 || cfg.MaxFailuresPerIP > 0) {
		// Limits without a window cannot be enforced. Say so rather than
		// quietly allowing everything.
		logger.Warn("login throttle: limits are configured but the window is not positive, failed logins are NOT limited",
			"window", cfg.Window)
	}
	if rdb != nil {
		// A context deadline alone does not interrupt a command that is
		// already waiting for its reply; the socket timeouts of this clone
		// do. It shares the connection pool with the client it is made from.
		rdb = rdb.WithTimeout(redisTimeout)
	}
	return &LoginThrottle{
		cfg:          cfg,
		rdb:          rdb,
		redisTimeout: redisTimeout,
		local:        newLocalLoginCounters(maxLocalLoginCounters),
		logger:       logger,
		now:          time.Now,
	}
}

// loginAcquireScript checks every counter in KEYS against its limit
// (ARGV[2..]) and, only if none is exhausted, charges the attempt to all of
// them. ARGV[1] is the window in milliseconds; it starts with the first
// attempt charged to a counter and is not extended by later ones. Returns
// {index of the exhausted counter or 0, its remaining lifetime in ms}.
//
//nolint:dupword // consecutive Lua block terminators
var loginAcquireScript = redis.NewScript(`
	local window = tonumber(ARGV[1])
	for i, key in ipairs(KEYS) do
		local count = tonumber(redis.call("GET", key) or "0")
		if count >= tonumber(ARGV[i + 1]) then
			local ttl = redis.call("PTTL", key)
			if ttl < 0 then
				redis.call("PEXPIRE", key, window)
				ttl = window
			end
			return {i, ttl}
		end
	end
	for _, key in ipairs(KEYS) do
		redis.call("INCR", key)
		if redis.call("PTTL", key) < 0 then
			redis.call("PEXPIRE", key, window)
		end
	end
	return {0, 0}
`)

// loginReleaseScript releases the counters in KEYS after a successful login.
// ARGV[i] says how: "clear" deletes the counter, anything else hands one slot
// back without touching the expiry and never takes the counter below zero.
//
//nolint:dupword // consecutive Lua block terminators
var loginReleaseScript = redis.NewScript(`
	for i, key in ipairs(KEYS) do
		if ARGV[i] == "clear" then
			redis.call("DEL", key)
		else
			local count = tonumber(redis.call("GET", key) or "0")
			if count > 1 then
				redis.call("DECR", key)
			elseif count == 1 then
				redis.call("DEL", key)
			end
		end
	end
	return 0
`)

// Acquire reserves a slot for a login attempt on the given account from the
// given source address. If any counter is exhausted the attempt is not
// allowed and nothing is charged; the caller must then reject the login
// without verifying the password.
func (t *LoginThrottle) Acquire(ctx context.Context, account, ip string) LoginAttempt {
	counters := t.counters(account, ip)
	if len(counters) == 0 {
		return LoginAttempt{Allowed: true}
	}

	now := t.now()
	if t.rdb != nil && !t.local.holdsUnshared(counters, now) {
		attempt, err := t.acquireRedis(ctx, counters)
		if err == nil {
			t.mirror(ctx, attempt, counters, now)
			return attempt
		}
		t.logger.WarnContext(ctx, "login throttle: Redis unavailable, falling back to process-local counters", "error", err)
	}

	blocked, retryAfter, evicted := t.local.acquire(counters, t.cfg.Window, now)
	t.warnEvicted(ctx, evicted)
	if blocked >= 0 {
		return LoginAttempt{Scope: counters[blocked].scope, RetryAfter: retryAfter}
	}
	return LoginAttempt{Allowed: true, counters: counters}
}

// Success hands back the slot of an attempt whose password was correct: the
// account's counters are cleared and the address gets its slot back — only
// that one slot, so logging in with one account does not erase the failures
// the same address ran up against others. A failed attempt needs no call: it
// simply keeps its slot until the window expires.
func (t *LoginThrottle) Success(ctx context.Context, attempt LoginAttempt) {
	if !attempt.Allowed || len(attempt.counters) == 0 {
		return
	}

	if t.rdb != nil {
		if err := t.releaseRedis(ctx, attempt); err != nil {
			// The counters stay higher than they should be, which errs on the
			// side of throttling.
			t.logger.WarnContext(ctx, "login throttle: could not release counters in Redis", "error", err)
		}
	}
	t.local.release(attempt.counters, attempt.shared, t.now())
}

// counters lists the enabled counters an attempt is charged to.
func (t *LoginThrottle) counters(account, ip string) []loginCounter {
	if t.cfg.Window <= 0 {
		return nil
	}
	// Most specific first: when several counters are exhausted, the attempt
	// is reported against the narrowest one.
	counters := make([]loginCounter, 0, 3)
	if t.cfg.MaxFailuresPerUserIP > 0 {
		counters = append(counters, loginCounter{scope: LoginScopeUserIP, key: loginUserIPKey(account, ip), limit: t.cfg.MaxFailuresPerUserIP})
	}
	if t.cfg.MaxFailuresPerUser > 0 {
		counters = append(counters, loginCounter{scope: LoginScopeUser, key: loginUserKey(account), limit: t.cfg.MaxFailuresPerUser})
	}
	if t.cfg.MaxFailuresPerIP > 0 {
		counters = append(counters, loginCounter{scope: LoginScopeIP, key: loginIPKey(ip), limit: t.cfg.MaxFailuresPerIP})
	}
	return counters
}

func (t *LoginThrottle) acquireRedis(ctx context.Context, counters []loginCounter) (LoginAttempt, error) {
	keys := make([]string, len(counters))
	args := make([]any, 0, len(counters)+1)
	args = append(args, t.cfg.Window.Milliseconds())
	for i, c := range counters {
		keys[i] = c.key
		args = append(args, c.limit)
	}

	ctx, cancel := t.redisContext(ctx)
	defer cancel()
	res, err := loginAcquireScript.Run(ctx, t.rdb, keys, args...).Int64Slice()
	if err != nil {
		return LoginAttempt{}, fmt.Errorf("login throttle acquire: %w", err)
	}
	if len(res) != 2 || res[0] < 0 || res[0] > int64(len(counters)) {
		return LoginAttempt{}, fmt.Errorf("login throttle acquire: unexpected script reply %v", res)
	}
	if res[0] == 0 {
		return LoginAttempt{Allowed: true, counters: counters, shared: true}, nil
	}
	return LoginAttempt{
		Scope:      counters[res[0]-1].scope,
		RetryAfter: time.Duration(res[1]) * time.Millisecond,
		counters:   counters[res[0]-1 : res[0]],
	}, nil
}

// mirror repeats a decision Redis made in the process-local table, so that a
// later outage continues from it: an allowed attempt is charged there too, and
// an exhausted counter is marked exhausted for as long as Redis holds it.
// Nothing is enforced here.
func (t *LoginThrottle) mirror(ctx context.Context, attempt LoginAttempt, counters []loginCounter, now time.Time) {
	if !attempt.Allowed {
		t.warnEvicted(ctx, t.local.exhaust(attempt.counters[0], attempt.RetryAfter, now))
		return
	}
	t.warnEvicted(ctx, t.local.mirrorCharge(counters, t.cfg.Window, now))
}

func (t *LoginThrottle) warnEvicted(ctx context.Context, evicted int) {
	if evicted > 0 {
		t.logger.WarnContext(ctx, "login throttle: process-local counter table is full, dropped live counters",
			"dropped", evicted, "capacity", t.local.maxEntries)
	}
}

func (t *LoginThrottle) releaseRedis(ctx context.Context, attempt LoginAttempt) error {
	keys := make([]string, 0, len(attempt.counters))
	modes := make([]any, 0, len(attempt.counters))
	for _, c := range attempt.counters {
		switch {
		case c.scope != LoginScopeIP:
			keys = append(keys, c.key)
			modes = append(modes, "clear")
		case attempt.shared:
			// Refund only a slot that was actually reserved in Redis.
			keys = append(keys, c.key)
			modes = append(modes, "refund")
		}
	}
	if len(keys) == 0 {
		return nil
	}

	ctx, cancel := t.redisContext(ctx)
	defer cancel()
	if err := loginReleaseScript.Run(ctx, t.rdb, keys, modes...).Err(); err != nil {
		return fmt.Errorf("login throttle release: %w", err)
	}
	return nil
}

// redisContext detaches a counter operation from the request's cancellation
// and gives it its own deadline. A client that aborts its request must not be
// able to turn that into a "Redis error" and so move its attempt to the
// process-local counters.
func (t *LoginThrottle) redisContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), t.redisTimeout)
}

// The account name is attacker-chosen and may be arbitrarily long, so it only
// enters a key as a hash.
func loginUserKey(account string) string {
	sum := sha256.Sum256([]byte(account))
	return prefixLoginFailures + LoginScopeUser + ":" + hex.EncodeToString(sum[:])
}

func loginUserIPKey(account, ip string) string {
	// The address cannot contain a NUL byte, so the pair is unambiguous.
	sum := sha256.Sum256([]byte(normalizeLoginIP(ip) + "\x00" + account))
	return prefixLoginFailures + LoginScopeUserIP + ":" + hex.EncodeToString(sum[:])
}

func loginIPKey(ip string) string {
	return prefixLoginFailures + LoginScopeIP + ":" + normalizeLoginIP(ip)
}

// normalizeLoginIP maps an address to the unit the per-IP limit applies to: an
// IPv4 address counts on its own, an IPv6 address as its /64 network, since a
// single IPv6 host typically controls a whole /64 and could otherwise use a
// fresh address for every attempt.
func normalizeLoginIP(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return loginIPUnknown
	}
	addr = addr.Unmap().WithZone("")
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

// localLoginCounters is the process-local counter table, with the same
// semantics as the Redis scripts.
type localLoginCounters struct {
	mu          sync.Mutex
	entries     map[string]localLoginCounter
	maxEntries  int
	lastWarning time.Time
}

type localLoginCounter struct {
	count int
	// unshared is how many of the charges Redis does not know about, because
	// they were made while it could not be reached.
	unshared int
	limit    int
	expires  time.Time
}

func newLocalLoginCounters(maxEntries int) *localLoginCounters {
	return &localLoginCounters{
		entries:    make(map[string]localLoginCounter),
		maxEntries: maxEntries,
	}
}

// holdsUnshared reports whether any of the counters carries charges Redis
// never saw. Such an attempt is decided here: Redis would count too little.
func (l *localLoginCounters) holdsUnshared(counters []loginCounter, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, c := range counters {
		if e, ok := l.live(c.key, now); ok && e.unshared > 0 {
			return true
		}
	}
	return false
}

// acquire mirrors loginAcquireScript for an attempt this table decides: it
// returns the index of an exhausted counter with its remaining lifetime and
// charges nothing, or it charges the attempt to every counter and returns -1.
// evicted is the number of live counters dropped to make room, reported at
// most once per localEvictionLogInterval.
func (l *localLoginCounters) acquire(counters []loginCounter, window time.Duration, now time.Time) (blocked int, retryAfter time.Duration, evicted int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for i, c := range counters {
		if e, ok := l.live(c.key, now); ok && e.count >= c.limit {
			return i, e.expires.Sub(now), 0
		}
	}
	return -1, 0, l.charge(counters, window, now, true)
}

// mirrorCharge records an attempt Redis has allowed and counted. It does not
// check any limit: that was Redis's decision.
func (l *localLoginCounters) mirrorCharge(counters []loginCounter, window time.Duration, now time.Time) (evicted int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.charge(counters, window, now, false)
}

// charge adds one attempt to every counter, creating those that do not exist.
// The caller holds the lock.
func (l *localLoginCounters) charge(counters []loginCounter, window time.Duration, now time.Time, unshared bool) (evicted int) {
	missing := 0
	for _, c := range counters {
		if _, ok := l.live(c.key, now); !ok {
			missing++
		}
	}
	dropped := l.makeRoom(missing, counters, now)
	for _, c := range counters {
		e, ok := l.entries[c.key]
		if !ok {
			e = localLoginCounter{expires: now.Add(window)}
		}
		e.count++
		if unshared {
			e.unshared++
		}
		e.limit = c.limit
		l.entries[c.key] = e
	}
	return l.reportable(dropped, now)
}

// exhaust marks a counter as exhausted for the given remaining lifetime,
// because Redis reports it so. A counter that holds charges Redis never saw
// is left alone: it is decided here, and Redis's window is not its window.
func (l *localLoginCounters) exhaust(c loginCounter, remaining time.Duration, now time.Time) (evicted int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.live(c.key, now)
	if ok && e.unshared > 0 {
		return 0
	}
	dropped := 0
	if !ok {
		dropped = l.makeRoom(1, []loginCounter{c}, now)
	}
	l.entries[c.key] = localLoginCounter{count: c.limit, limit: c.limit, expires: now.Add(remaining)}
	return l.reportable(dropped, now)
}

// release mirrors Success on the Redis side: account counters are cleared and
// the address gets its slot back. shared says whether that slot was one Redis
// knows about.
func (l *localLoginCounters) release(counters []loginCounter, shared bool, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, c := range counters {
		if c.scope != LoginScopeIP {
			delete(l.entries, c.key)
			continue
		}
		e, ok := l.live(c.key, now)
		if !ok {
			continue
		}
		if e.count <= 1 {
			delete(l.entries, c.key)
			continue
		}
		e.count--
		if !shared && e.unshared > 0 {
			e.unshared--
		}
		l.entries[c.key] = e
	}
}

// live returns the counter for key, dropping it first if its window is over.
func (l *localLoginCounters) live(key string, now time.Time) (localLoginCounter, bool) {
	e, ok := l.entries[key]
	if ok && !now.Before(e.expires) {
		delete(l.entries, key)
		return localLoginCounter{}, false
	}
	return e, ok
}

// makeRoom ensures need more counters fit under the cap and returns how many
// live ones it had to drop. Expired counters go first. If the table is still
// full it drops a batch of live counters, preferring ones that are not
// exhausted so an active lockout survives the pressure, and never the ones
// the current attempt is charged to. Dropping a live counter loosens the
// limit for that key, which is why the caller logs it — the alternative,
// refusing every login the table cannot track, would let a flood of made-up
// usernames lock everyone out.
func (l *localLoginCounters) makeRoom(need int, keep []loginCounter, now time.Time) int {
	fits := func() bool { return len(l.entries)+need <= l.maxEntries }
	if fits() {
		return 0
	}
	for key, e := range l.entries {
		if !now.Before(e.expires) {
			delete(l.entries, key)
		}
	}
	if fits() {
		return 0
	}

	kept := func(key string) bool {
		for _, c := range keep {
			if c.key == key {
				return true
			}
		}
		return false
	}

	// A batch rather than just enough, so a sustained flood does not pay for
	// a full sweep on every single attempt.
	batch := max(l.maxEntries/10, need)
	dropped := 0
	for key, e := range l.entries {
		if dropped >= batch {
			break
		}
		if e.count < e.limit && !kept(key) {
			delete(l.entries, key)
			dropped++
		}
	}
	for key := range l.entries {
		if fits() {
			break
		}
		if !kept(key) {
			delete(l.entries, key)
			dropped++
		}
	}
	return dropped
}

// reportable rate-limits the eviction warning: it passes dropped through at
// most once per localEvictionLogInterval and returns 0 otherwise.
func (l *localLoginCounters) reportable(dropped int, now time.Time) int {
	if dropped == 0 || now.Sub(l.lastWarning) < localEvictionLogInterval {
		return 0
	}
	l.lastWarning = now
	return dropped
}
