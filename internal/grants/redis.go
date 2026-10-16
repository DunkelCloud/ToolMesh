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
// A hash can hold a grant that has expired while a later one keeps the hash
// alive; reads skip it.
const prefixGrants = "grants:{kits}:"

func subjectKey(state, subject string) string { return prefixGrants + state + ":s:" + subject }
func idKey(state, id string) string           { return prefixGrants + state + ":id:" + id }

// putScript stores a grant in its subject's hash and points its id there.
// The hash lives as long as its longest-lived grant.
//
// KEYS[1] subject hash, KEYS[2] id key; ARGV[1] id, ARGV[2] grant JSON,
// ARGV[3] lifetime in milliseconds, ARGV[4] subject.
var putScript = redis.NewScript(`
redis.call("HSET", KEYS[1], ARGV[1], ARGV[2])
local ttl = tonumber(ARGV[3])
if redis.call("PTTL", KEYS[1]) < ttl then
	redis.call("PEXPIRE", KEYS[1], ttl)
end
redis.call("SET", KEYS[2], ARGV[4], "PX", ttl)
return 1
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
	ttl := g.ExpiresAt.Sub(r.now())
	if ttl < time.Millisecond {
		return nil // already over: nothing to keep
	}
	data, err := json.Marshal(g)
	if err != nil {
		return fmt.Errorf("marshal grant: %w", err)
	}
	subject := g.Subject().key()
	err = putScript.Run(ctx, r.rdb, []string{subjectKey(g.State, subject), idKey(g.State, g.ID)},
		g.ID, data, ttl.Milliseconds(), subject).Err()
	if err != nil {
		return fmt.Errorf("store grant: %w", err)
	}
	return nil
}

// Get returns the grant with the id in the state.
func (r *RedisStore) Get(ctx context.Context, state, id string) (Grant, error) {
	subject, err := r.subjectOf(ctx, state, id)
	if err != nil {
		return Grant{}, err
	}
	data, err := r.rdb.HGet(ctx, subjectKey(state, subject), id).Bytes()
	if errors.Is(err, redis.Nil) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("read grant: %w", err)
	}
	return r.decode(data)
}

// Take removes the grant with the id in the state and returns it.
func (r *RedisStore) Take(ctx context.Context, state, id string) (Grant, error) {
	subject, err := r.subjectOf(ctx, state, id)
	if err != nil {
		return Grant{}, err
	}
	data, err := takeScript.Run(ctx, r.rdb, []string{subjectKey(state, subject), idKey(state, id)}, id, subject).Text()
	if errors.Is(err, redis.Nil) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, fmt.Errorf("take grant: %w", err)
	}
	return r.decode([]byte(data))
}

// ForSubject returns the subject's grants in the state, oldest first.
func (r *RedisStore) ForSubject(ctx context.Context, state string, s Subject) ([]Grant, error) {
	m, err := r.rdb.HGetAll(ctx, subjectKey(state, s.key())).Result()
	if err != nil {
		return nil, fmt.Errorf("read grants: %w", err)
	}
	return r.decodeAll(m), nil
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
		out = append(out, r.decodeAll(c.Val())...)
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

// decode parses a stored grant; one that has expired counts as not found.
func (r *RedisStore) decode(data []byte) (Grant, error) {
	var g Grant
	if err := json.Unmarshal(data, &g); err != nil {
		return Grant{}, fmt.Errorf("decode grant: %w", err)
	}
	if !r.now().Before(g.ExpiresAt) {
		return Grant{}, ErrNotFound
	}
	return g, nil
}

// decodeAll parses the grants of a subject hash, skipping those that have
// expired or do not parse, oldest first.
func (r *RedisStore) decodeAll(m map[string]string) []Grant {
	out := make([]Grant, 0, len(m))
	for _, v := range m {
		if g, err := r.decode([]byte(v)); err == nil {
			out = append(out, g)
		}
	}
	sortGrants(out)
	return out
}
