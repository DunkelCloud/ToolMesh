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
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// prefixGrants starts every key of the Redis store. The hash tag puts all of
// them in one slot of a clustered Redis, as the scripts touch several keys.
//
// Per state there are two kinds of keys: a hash per subject that maps grant
// ids to grants (<prefix><state>:s:<subject>), which is what a check reads
// in one round trip, and a key per grant id that names the subject
// (<prefix><state>:id:<id>). Each key expires with the last grant it holds.
// A hash entry is "<expires at, Unix ms>|<kit>|<grant JSON>", so that the
// scripts can tell expired entries and the kit without decoding JSON. Every
// write removes the expired entries of its hash, and reads skip them.
const prefixGrants = "grants:{kits}:"

func subjectKey(state, subject string) string { return prefixGrants + state + ":s:" + subject }
func idKey(state, id string) string           { return prefixGrants + state + ":id:" + id }

// pruneLua removes the expired entries of the hash KEYS[1], given the time
// now in Unix milliseconds, and counts the others in count. An entry whose
// kit is the one in matchKit is returned from the script as
// {"existing", entry} when matchKit is set.
const pruneLua = `
local count = 0
local all = redis.call("HGETALL", KEYS[1])
for i = 1, #all, 2 do
	local exp, kit = string.match(all[i + 1], "^(%d+)|([^|]*)|")
	exp = tonumber(exp)
	if not exp or exp <= now then
		redis.call("HDEL", KEYS[1], all[i])
	elseif matchKit and kit == matchKit then
		return {"existing", all[i + 1]}
	else
		count = count + 1
	end
end
`

// insertLua stores the entry in its subject's hash, points its id there and
// lets the hash live as long as its longest-lived entry.
const insertLua = `
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
local ttl = tonumber(ARGV[3])
if redis.call("PTTL", KEYS[1]) < ttl then
	redis.call("PEXPIRE", KEYS[1], ttl)
end
redis.call("SET", KEYS[2], ARGV[4], "PX", ttl)
`

// putScript stores a grant after removing the expired entries of its hash.
//
// KEYS[1] subject hash, KEYS[2] id key; ARGV[1] id, ARGV[2] entry,
// ARGV[3] lifetime in milliseconds, ARGV[4] subject, ARGV[5] now in Unix
// milliseconds.
var putScript = redis.NewScript(`
local now = tonumber(ARGV[5])
local matchKit = nil
` + pruneLua + insertLua + `
return {"added"}
`)

// addPendingScript stores a pending request unless its subject has one for
// the same kit or has ARGV[7] requests pending.
//
// As putScript, and ARGV[6] the kit, ARGV[7] the limit.
var addPendingScript = redis.NewScript(`
local now = tonumber(ARGV[5])
local matchKit = ARGV[6]
` + pruneLua + `
if count >= tonumber(ARGV[7]) then
	return {"limit"}
end
` + insertLua + `
return {"added"}
`)

// takeScript removes a grant, if its id key still names the subject, and
// returns it.
//
// KEYS[1] subject hash, KEYS[2] id key; ARGV[1] id, ARGV[2] subject.
var takeScript = redis.NewScript(`
if redis.call("GET", KEYS[2]) ~= ARGV[2] then
	return false
end
local v = redis.call("HGET", KEYS[1], ARGV[1])
redis.call("HDEL", KEYS[1], ARGV[1])
redis.call("DEL", KEYS[2])
return v
`)

// RedisStore keeps grants in Redis (or KeyDB, Valkey), where they survive a
// restart of ToolMesh and are shared between its instances.
type RedisStore struct {
	rdb *redis.Client
	now func() time.Time
}

// NewRedisStore returns a store on the given client.
func NewRedisStore(rdb *redis.Client) *RedisStore {
	return &RedisStore{rdb: rdb, now: time.Now}
}

// Put stores g until g.ExpiresAt.
func (r *RedisStore) Put(ctx context.Context, g Grant) error {
	_, _, err := r.insert(ctx, putScript, g)
	return err
}

// AddPending stores the pending request g in one script, so that the checks
// and the insert are one step.
func (r *RedisStore) AddPending(ctx context.Context, g Grant, limit int) (Grant, bool, error) {
	return r.insert(ctx, addPendingScript, g, g.Kit, limit)
}

// insert runs putScript or addPendingScript for g, with extra arguments
// after the common ones.
func (r *RedisStore) insert(ctx context.Context, script *redis.Script, g Grant, extra ...any) (Grant, bool, error) {
	now := r.now()
	ttl := g.ExpiresAt.Sub(now)
	if ttl < time.Millisecond {
		return Grant{}, false, nil // already over: nothing to keep
	}
	entry, err := encodeEntry(g)
	if err != nil {
		return Grant{}, false, err
	}
	subject := g.Subject().key()
	args := append([]any{g.ID, entry, ttl.Milliseconds(), subject, now.UnixMilli()}, extra...)
	res, err := script.Run(ctx, r.rdb, []string{subjectKey(g.State, subject), idKey(g.State, g.ID)}, args...).StringSlice()
	if err != nil {
		return Grant{}, false, fmt.Errorf("store grant: %w", err)
	}
	switch {
	case len(res) == 2 && res[0] == "existing":
		existing, err := decodeEntry(res[1])
		return existing, err == nil, err
	case len(res) == 1 && res[0] == "limit":
		return Grant{}, false, ErrLimit
	}
	return Grant{}, false, nil
}

// Get returns the grant with the id in the state.
func (r *RedisStore) Get(ctx context.Context, state, id string) (Grant, error) {
	subject, err := r.subjectOf(ctx, state, id)
	if err != nil {
		return Grant{}, err
	}
	entry, err := r.rdb.HGet(ctx, subjectKey(state, subject), id).Result()
	if errors.Is(err, redis.Nil) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("read grant: %w", err)
	}
	return r.live(entry)
}

// Take removes the grant with the id in the state and returns it.
func (r *RedisStore) Take(ctx context.Context, state, id string) (Grant, error) {
	subject, err := r.subjectOf(ctx, state, id)
	if err != nil {
		return Grant{}, err
	}
	entry, err := takeScript.Run(ctx, r.rdb, []string{subjectKey(state, subject), idKey(state, id)}, id, subject).Text()
	if errors.Is(err, redis.Nil) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("take grant: %w", err)
	}
	return r.live(entry)
}

// ForSubject returns the subject's grants in the state, oldest first. The
// expired entries it comes across are removed.
func (r *RedisStore) ForSubject(ctx context.Context, state string, s Subject) ([]Grant, error) {
	key := subjectKey(state, s.key())
	m, err := r.rdb.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	out, expired := r.liveAll(m)
	if len(expired) > 0 {
		// Best effort: the next write removes them as well.
		_ = r.rdb.HDel(ctx, key, expired...).Err()
	}
	return out, nil
}

// List returns every grant in the state, oldest first.
func (r *RedisStore) List(ctx context.Context, state string) ([]Grant, error) {
	var keys []string
	iter := r.rdb.Scan(ctx, 0, subjectKey(state, "*"), 100).Iterator()
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	pipe := r.rdb.Pipeline()
	cmds := make([]*redis.MapStringStringCmd, len(keys))
	for i, k := range keys {
		cmds[i] = pipe.HGetAll(ctx, k)
	}
	if len(keys) > 0 {
		if _, err := pipe.Exec(ctx); err != nil {
			return nil, fmt.Errorf("list grants: %w", err)
		}
	}
	var out []Grant
	for _, c := range cmds {
		live, _ := r.liveAll(c.Val())
		out = append(out, live...)
	}
	sortGrants(out)
	return out, nil
}

// subjectOf returns the subject the id key of a grant names.
func (r *RedisStore) subjectOf(ctx context.Context, state, id string) (string, error) {
	subject, err := r.rdb.Get(ctx, idKey(state, id)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read grant: %w", err)
	}
	return subject, nil
}

// live decodes a stored entry; one that has expired counts as not found.
func (r *RedisStore) live(entry string) (Grant, error) {
	g, err := decodeEntry(entry)
	if err != nil {
		return Grant{}, err
	}
	if !r.now().Before(g.ExpiresAt) {
		return Grant{}, ErrNotFound
	}
	return g, nil
}

// liveAll decodes the entries of a subject hash, oldest first, and returns
// the fields of those that have expired or do not decode.
func (r *RedisStore) liveAll(m map[string]string) (live []Grant, expired []string) {
	live = make([]Grant, 0, len(m))
	for field, entry := range m {
		if g, err := r.live(entry); err == nil {
			live = append(live, g)
		} else {
			expired = append(expired, field)
		}
	}
	sortGrants(live)
	return live, expired
}

// encodeEntry renders g as a hash entry. Kit names cannot contain '|'.
func encodeEntry(g Grant) (string, error) {
	data, err := json.Marshal(g)
	if err != nil {
		return "", fmt.Errorf("marshal grant: %w", err)
	}
	return strconv.FormatInt(g.ExpiresAt.UnixMilli(), 10) + "|" + g.Kit + "|" + string(data), nil
}

// decodeEntry parses a hash entry.
func decodeEntry(entry string) (Grant, error) {
	parts := strings.SplitN(entry, "|", 3)
	if len(parts) != 3 {
		return Grant{}, errors.New("decode grant: malformed entry")
	}
	var g Grant
	if err := json.Unmarshal([]byte(parts[2]), &g); err != nil {
		return Grant{}, fmt.Errorf("decode grant: %w", err)
	}
	return g, nil
}
