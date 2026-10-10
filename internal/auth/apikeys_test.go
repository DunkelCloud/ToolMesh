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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// bcryptKeyEntry is an apikeys.yaml entry in the form every file written for
// earlier versions has: the key as a bcrypt hash and nothing else.
func bcryptKeyEntry(tb testing.TB, key, userID string, cost int) string {
	tb.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(key), cost)
	if err != nil {
		tb.Fatalf("hash %s: %v", userID, err)
	}
	return fmt.Sprintf("  - key_hash: %q\n    user_id: %s\n", hash, userID)
}

// keyDigest is what `printf %s "$KEY" | sha256sum` prints for key.
func keyDigest(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func sha256KeyEntry(key, userID string) string {
	return fmt.Sprintf("  - key_sha256: %q\n    user_id: %s\n", keyDigest(key), userID)
}

func writeAPIKeysFile(tb testing.TB, entries ...string) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "apikeys.yaml")
	if err := os.WriteFile(path, []byte("keys:\n"+strings.Join(entries, "")), 0600); err != nil {
		tb.Fatal(err)
	}
	return path
}

// loadAPIKeys loads a store from the given entries and counts the bcrypt
// comparisons it runs from then on.
func loadAPIKeys(tb testing.TB, entries ...string) (*APIKeyStore, *atomic.Int64) {
	tb.Helper()
	store, err := NewAPIKeyStore(writeAPIKeysFile(tb, entries...), nil)
	if err != nil {
		tb.Fatalf("NewAPIKeyStore: %v", err)
	}
	comparisons := new(atomic.Int64)
	store.compare = func(hash, key []byte) error {
		comparisons.Add(1)
		return bcrypt.CompareHashAndPassword(hash, key)
	}
	return store, comparisons
}

// presentKey looks key up the way the server does, index first, and fails the
// test if a comparison could not be run.
func presentKey(tb testing.TB, store *APIKeyStore, key string) *APIKeyEntry {
	tb.Helper()
	if entry := store.Find(key); entry != nil {
		return entry
	}
	entry, err := store.Verify(context.Background(), key)
	if err != nil {
		tb.Fatalf("Verify: %v", err)
	}
	return entry
}

// The point of the index: a bearer that is no key at all is rejected without
// a single bcrypt comparison, however many keys are configured. For entries
// with a key_sha256 that holds from the start.
func TestAPIKeyStore_UnknownBearerCostsNoBcrypt(t *testing.T) {
	const keys = 25
	entries := make([]string, keys)
	for i := range entries {
		entries[i] = sha256KeyEntry(fmt.Sprintf("key-%d", i), fmt.Sprintf("user-%d", i))
	}
	store, comparisons := loadAPIKeys(t, entries...)

	for _, bearer := range []string{"not-a-key", "key-25", "KEY-0", "", strings.Repeat("f", 64), strings.Repeat("x", 4096)} {
		if entry := presentKey(t, store, bearer); entry != nil {
			t.Errorf("bearer %q matched the entry of %s", bearer, entry.UserID)
		}
	}
	if got := comparisons.Load(); got != 0 {
		t.Errorf("unknown bearers cost %d bcrypt comparisons against %d keys, want 0", got, keys)
	}

	for i := range keys {
		entry := presentKey(t, store, fmt.Sprintf("key-%d", i))
		if entry == nil || entry.UserID != fmt.Sprintf("user-%d", i) {
			t.Fatalf("key-%d: got %v, want the entry of user-%d", i, entry, i)
		}
	}
	if got := comparisons.Load(); got != 0 {
		t.Errorf("valid keys cost %d bcrypt comparisons, want 0", got)
	}
}

// A file written for an earlier version has only bcrypt hashes and must keep
// working as it is. Its entries cannot be indexed when the file is loaded;
// each joins the index the first time its key is presented. Once all have
// been seen, an unknown bearer costs no comparison here either.
func TestAPIKeyStore_BcryptOnlyFileIsIndexedOnFirstUse(t *testing.T) {
	keys := []string{"legacy-key-a", "legacy-key-b", "legacy-key-c"}
	entries := make([]string, len(keys))
	for i, key := range keys {
		entries[i] = bcryptKeyEntry(t, key, fmt.Sprintf("user-%d", i), bcrypt.MinCost)
	}
	store, comparisons := loadAPIKeys(t, entries...)

	if got := store.Summary(); got.Indexed != 0 || got.BcryptOnly != len(keys) || len(got.Unusable) != 0 {
		t.Errorf("Summary() = %+v, want %d bcrypt-only entries and nothing else", got, len(keys))
	}

	// Nothing has been seen yet, so the index cannot answer and an unknown
	// bearer is compared against every entry. This is the cost that remains
	// for such a file until its keys have been used.
	if store.Find(keys[1]) != nil {
		t.Fatal("a bcrypt-only entry was in the index before its key was ever presented")
	}
	if presentKey(t, store, "not-a-key") != nil {
		t.Fatal("unknown bearer matched")
	}
	if got := comparisons.Swap(0); got != int64(len(keys)) {
		t.Errorf("unknown bearer before any key was seen: %d comparisons, want %d", got, len(keys))
	}

	// The second key is found by comparison once ...
	if entry := presentKey(t, store, keys[1]); entry == nil || entry.UserID != "user-1" {
		t.Fatalf("first use of %s: got %v, want user-1", keys[1], entry)
	}
	if got := comparisons.Swap(0); got != 2 {
		t.Errorf("first use of the second key: %d comparisons, want 2 (entries are tried in file order)", got)
	}
	// ... and through the index from then on.
	for range 3 {
		if entry := store.Find(keys[1]); entry == nil || entry.UserID != "user-1" {
			t.Fatalf("Find(%s) = %v, want user-1", keys[1], entry)
		}
	}
	if got := comparisons.Load(); got != 0 {
		t.Errorf("a key that was seen before cost %d comparisons, want 0", got)
	}

	// An unknown bearer is now compared against the two entries left.
	presentKey(t, store, "not-a-key")
	if got := comparisons.Swap(0); got != 2 {
		t.Errorf("unknown bearer with two entries unseen: %d comparisons, want 2", got)
	}

	// After every key has been presented once, nothing is left to compare.
	for i, key := range keys {
		if entry := presentKey(t, store, key); entry == nil || entry.UserID != fmt.Sprintf("user-%d", i) {
			t.Fatalf("%s: got %v, want user-%d", key, entry, i)
		}
	}
	comparisons.Store(0)
	for _, bearer := range []string{"not-a-key", "legacy-key-d", strings.Repeat("0", 64)} {
		if presentKey(t, store, bearer) != nil {
			t.Errorf("bearer %q matched", bearer)
		}
	}
	for i, key := range keys {
		if entry := presentKey(t, store, key); entry == nil || entry.UserID != fmt.Sprintf("user-%d", i) {
			t.Errorf("%s after indexing: got %v, want user-%d", key, entry, i)
		}
	}
	if got := comparisons.Load(); got != 0 {
		t.Errorf("after every key was seen: %d comparisons, want 0", got)
	}
}

func TestAPIKeyStore_MixedFile(t *testing.T) {
	both := strings.Replace(bcryptKeyEntry(t, "key-both", "both", bcrypt.MinCost), "    user_id:", fmt.Sprintf("    key_sha256: %q\n    user_id:", keyDigest("key-both")), 1)
	store, comparisons := loadAPIKeys(t,
		sha256KeyEntry("key-digest", "digest"),
		bcryptKeyEntry(t, "key-bcrypt", "bcrypt", bcrypt.MinCost),
		both,
	)

	if got := store.Summary(); got.Indexed != 2 || got.BcryptOnly != 1 || len(got.Unusable) != 0 {
		t.Errorf("Summary() = %+v, want 2 indexed and 1 bcrypt-only", got)
	}

	// An entry that carries both fields is found through its digest.
	for key, user := range map[string]string{"key-digest": "digest", "key-both": "both"} {
		if entry := store.Find(key); entry == nil || entry.UserID != user {
			t.Errorf("Find(%s) = %v, want %s", key, entry, user)
		}
	}
	if got := comparisons.Load(); got != 0 {
		t.Errorf("entries with a key_sha256 cost %d comparisons, want 0", got)
	}

	if entry := presentKey(t, store, "key-bcrypt"); entry == nil || entry.UserID != "bcrypt" {
		t.Errorf("bcrypt-only entry: got %v", entry)
	}
	if got := comparisons.Load(); got != 1 {
		t.Errorf("first use of the bcrypt-only key: %d comparisons, want 1 (only the unseen entry is compared)", got)
	}
}

func TestAPIKeyStore_KeySHA256Format(t *testing.T) {
	digest := keyDigest("the-key")

	// Case and surrounding whitespace do not matter.
	store, _ := loadAPIKeys(t, fmt.Sprintf("  - key_sha256: %q\n    user_id: spaced\n", "  "+strings.ToUpper(digest)+" "))
	if entry := store.Find("the-key"); entry == nil || entry.UserID != "spaced" {
		t.Errorf("upper-case digest with whitespace: Find = %v, want the entry", entry)
	}

	// What cannot be a SHA-256 stops the load: the entry would never match.
	invalid := map[string]string{
		"too short":   digest[:63],
		"too long":    digest + "0",
		"not hex":     strings.Repeat("z", 64),
		"bcrypt hash": "$2a$10$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012",
		"with prefix": "sha256:" + digest,
	}
	for name, value := range invalid {
		t.Run(name, func(t *testing.T) {
			path := writeAPIKeysFile(t, fmt.Sprintf("  - key_sha256: %q\n    user_id: broken\n", value))
			store, err := NewAPIKeyStore(path, nil)
			if err == nil || store != nil {
				t.Fatalf("NewAPIKeyStore accepted key_sha256 %q", value)
			}
			if !strings.Contains(err.Error(), "key_sha256") || !strings.Contains(err.Error(), "broken") {
				t.Errorf("error %q should name the field and the entry", err)
			}
			if strings.Contains(err.Error(), value) {
				t.Errorf("error %q repeats the configured value", err)
			}
		})
	}

	t.Run("duplicate", func(t *testing.T) {
		path := writeAPIKeysFile(t, sha256KeyEntry("the-key", "first"), sha256KeyEntry("the-key", "second"))
		if _, err := NewAPIKeyStore(path, nil); err == nil || !strings.Contains(err.Error(), "first") || !strings.Contains(err.Error(), "second") {
			t.Errorf("two entries for one key: err = %v, want an error naming both", err)
		}
	})
}

// An entry nothing can match is reported, and it does not cost a comparison:
// bcrypt would refuse the hash at once, so it never counts as unseen.
func TestAPIKeyStore_UnusableEntries(t *testing.T) {
	store, comparisons := loadAPIKeys(t,
		"  - key_hash: \"$2a$10$...\"\n    user_id: placeholder\n",
		"  - user_id: empty\n",
		sha256KeyEntry("good-key", "good"),
	)

	got := store.Summary()
	if got.Indexed != 1 || got.BcryptOnly != 0 || len(got.Unusable) != 2 || got.Unusable[0] != "placeholder" || got.Unusable[1] != "empty" {
		t.Errorf("Summary() = %+v, want 1 indexed and [placeholder empty] unusable", got)
	}
	for _, bearer := range []string{"$2a$10$...", "", "anything"} {
		if presentKey(t, store, bearer) != nil {
			t.Errorf("bearer %q matched an unusable entry", bearer)
		}
	}
	if n := comparisons.Load(); n != 0 {
		t.Errorf("unusable entries cost %d comparisons, want 0", n)
	}
}

// bcrypt reads only the first 72 bytes of what it hashes, so several values
// longer than that can match one hash. The entry belongs to the first of them
// that is presented; without that rule it would have to stay open to
// comparison forever.
func TestAPIKeyStore_EntryIsBoundToFirstKeySeen(t *testing.T) {
	base := strings.Repeat("k", 72)
	first, second := base+"-first", base+"-second"

	entry := bcryptKeyEntry(t, base, "long", bcrypt.MinCost)
	hash := strings.Split(strings.SplitN(entry, "\"", 2)[1], "\"")[0]
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(second)); err != nil {
		t.Skipf("this bcrypt does not match values that differ beyond 72 bytes (%v); nothing to pin", err)
	}

	store, comparisons := loadAPIKeys(t, entry)
	if got := presentKey(t, store, first); got == nil || got.UserID != "long" {
		t.Fatalf("first value: got %v, want the entry", got)
	}
	comparisons.Store(0)
	if got := presentKey(t, store, second); got != nil {
		t.Error("a second value was accepted for an entry that already has its key")
	}
	if got := presentKey(t, store, first); got == nil {
		t.Error("the first value stopped working")
	}
	if n := comparisons.Load(); n != 0 {
		t.Errorf("%d comparisons after the entry was seen, want 0", n)
	}
}

func TestAPIKeyStore_ConcurrentFirstUse(t *testing.T) {
	store, _ := loadAPIKeys(t,
		bcryptKeyEntry(t, "key-a", "a", bcrypt.MinCost),
		bcryptKeyEntry(t, "key-b", "b", bcrypt.MinCost),
	)

	var wg sync.WaitGroup
	for i := range 32 {
		key, user := "key-a", "a"
		if i%2 == 1 {
			key, user = "key-b", "b"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry, err := store.Verify(context.Background(), key)
			if err != nil || entry == nil || entry.UserID != user {
				t.Errorf("Verify(%s) = %v, %v; want the entry of %s", key, entry, err, user)
			}
		}()
	}
	wg.Wait()

	for key, user := range map[string]string{"key-a": "a", "key-b": "b"} {
		if entry := store.Find(key); entry == nil || entry.UserID != user {
			t.Errorf("Find(%s) = %v after concurrent first use, want %s", key, entry, user)
		}
	}
	if left := store.unseenEntries(); len(left) != 0 {
		t.Errorf("%d entries still unseen", len(left))
	}
}

// A comparison that cannot be started is an error, not a rejection: the key
// was never checked.
func TestAPIKeyStore_VerifyReportsBusyLimiter(t *testing.T) {
	limiter := NewCompareLimiter(1)
	store, err := NewAPIKeyStore(writeAPIKeysFile(t,
		bcryptKeyEntry(t, "key-a", "a", bcrypt.MinCost),
		sha256KeyEntry("key-b", "b"),
	), limiter)
	if err != nil {
		t.Fatalf("NewAPIKeyStore: %v", err)
	}
	release := holdSlot(t, limiter)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if entry, err := store.Verify(ctx, "key-a"); err == nil || entry != nil {
		t.Errorf("Verify with every slot taken = %v, %v; want an error", entry, err)
	}
	// What the index answers needs no slot.
	if entry := store.Find("key-b"); entry == nil || entry.UserID != "b" {
		t.Errorf("Find(key-b) with every slot taken = %v, want the entry", entry)
	}

	release()
	if entry, err := store.Verify(context.Background(), "key-a"); err != nil || entry == nil || entry.UserID != "a" {
		t.Errorf("Verify after the slot was freed = %v, %v; want the entry", entry, err)
	}
}

// waitFor polls until cond holds and fails the test if it does not in time.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting until %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// Anyone can send bearer credentials, as many as they like. Those that have
// to be compared must not be able to take the comparison slots away from the
// password login, nor fill the queue it waits in: they are admitted one at a
// time and wait in a queue of their own.
func TestAPIKeyStore_ComparisonsForBearersDoNotCrowdOutOthers(t *testing.T) {
	const flood = 40

	for _, capacity := range []int{1, 2} {
		t.Run(fmt.Sprintf("capacity %d", capacity), func(t *testing.T) {
			limiter := NewCompareLimiter(capacity)
			limiter.maxWait = time.Minute
			store, err := NewAPIKeyStore(writeAPIKeysFile(t, bcryptKeyEntry(t, "never-used-key", "dormant", bcrypt.MinCost)), limiter)
			if err != nil {
				t.Fatalf("NewAPIKeyStore: %v", err)
			}
			store.scans.maxWait = time.Minute

			// Every comparison for a bearer stops here until the test lets
			// it go on, and the order of what ran is recorded.
			var mu sync.Mutex
			var order []string
			var running, peak atomic.Int32
			proceed := make(chan struct{})
			started := make(chan struct{}, flood)
			store.compare = func(hash, key []byte) error {
				if n := running.Add(1); n > peak.Load() {
					peak.Store(n)
				}
				mu.Lock()
				order = append(order, "bearer")
				mu.Unlock()
				started <- struct{}{}
				<-proceed
				running.Add(-1)
				return bcrypt.ErrMismatchedHashAndPassword
			}

			var wg sync.WaitGroup
			for i := range flood {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if entry, err := store.Verify(context.Background(), fmt.Sprintf("unknown-bearer-%d", i)); err != nil || entry != nil {
						t.Errorf("Verify(unknown bearer %d) = %v, %v; want no match and no error", i, entry, err)
					}
				}()
			}
			<-started
			waitFor(t, "the other bearers wait for their turn", func() bool { return store.scans.waiting.Load() == flood-1 })

			if got := running.Load(); got != 1 {
				t.Errorf("%d comparisons for bearers run at once, want 1", got)
			}
			if got := limiter.waiting.Load(); got != 0 {
				t.Errorf("%d bearers wait in the queue of the shared limiter, want 0", got)
			}

			// A password login asks the shared limiter for a comparison.
			login := make(chan error, 1)
			go func() {
				login <- limiter.Do(context.Background(), func() {
					mu.Lock()
					order = append(order, "login")
					mu.Unlock()
				})
			}()
			if capacity > 1 {
				// A slot is free for it, whatever the bearers do.
				select {
				case err := <-login:
					if err != nil {
						t.Errorf("login with a slot free: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the login did not get the free slot")
				}
			} else {
				// The only slot is held by one comparison for a bearer. The
				// login waits for exactly that one and is served before the
				// next bearer.
				waitFor(t, "the login waits for the slot", func() bool { return limiter.waiting.Load() == 1 })
				proceed <- struct{}{}
				select {
				case err := <-login:
					if err != nil {
						t.Errorf("login behind one comparison: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("the login was not served after the comparison ahead of it")
				}
				mu.Lock()
				got := strings.Join(order[:min(len(order), 2)], ",")
				mu.Unlock()
				if got != "bearer,login" {
					t.Errorf("order = %s, want the login right after the one comparison it had to wait for", got)
				}
			}

			close(proceed)
			wg.Wait()
			if got := peak.Load(); got != apiKeyScanConcurrency {
				t.Errorf("at most %d comparisons for bearers ran at once, want %d", got, apiKeyScanConcurrency)
			}
		})
	}
}

// A bearer that has to be compared against several entries waits for a slot
// before each comparison. All those waits together are held to what a single
// comparison may wait, so that the number of entries does not multiply the
// time a request can be kept waiting.
func TestAPIKeyStore_WaitsOfOneRequestShareOneAllowance(t *testing.T) {
	const (
		allowance  = 1000 * time.Millisecond
		firstHold  = 600 * time.Millisecond // the first wait uses up at least this much of the allowance
		secondHold = 700 * time.Millisecond // more than what is left of it, less than a fresh one
	)
	limiter := NewCompareLimiter(1)
	limiter.maxWait = allowance
	store, err := NewAPIKeyStore(writeAPIKeysFile(t,
		bcryptKeyEntry(t, "key-a", "a", bcrypt.MinCost),
		bcryptKeyEntry(t, "key-b", "b", bcrypt.MinCost),
	), limiter)
	if err != nil {
		t.Fatalf("NewAPIKeyStore: %v", err)
	}

	// Someone else holds the slot while the request waits for its first
	// comparison, and takes it again while that comparison runs.
	release := holdSlot(t, limiter)
	again := make(chan struct{})
	var comparisons atomic.Int64
	store.compare = func(_, _ []byte) error {
		if comparisons.Add(1) == 1 {
			go func() {
				_ = limiter.Do(context.Background(), func() {
					close(again)
					time.Sleep(secondHold)
				})
			}()
			for deadline := time.Now().Add(5 * time.Second); limiter.waiting.Load() != 1 && time.Now().Before(deadline); {
				time.Sleep(time.Millisecond)
			}
		}
		return bcrypt.ErrMismatchedHashAndPassword
	}

	result := make(chan error, 1)
	go func() {
		_, err := store.Verify(context.Background(), "not-a-key")
		result <- err
	}()
	waitFor(t, "the request waits for its first comparison", func() bool { return limiter.waiting.Load() == 1 })
	time.Sleep(firstHold)
	release()

	select {
	case err := <-result:
		if !errors.Is(err, ErrCompareBusy) {
			t.Errorf("Verify = %v, want ErrCompareBusy once the allowance is used up", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Verify did not return")
	}
	if got := comparisons.Load(); got != 1 {
		t.Errorf("%d comparisons ran, want 1: the second had no allowance left to wait for the slot", got)
	}
	<-again
}

// BenchmarkAPIKeyStore_UnknownBearer measures what it costs to reject a value
// that is no key. With an index the cost is a SHA-256 and a table lookup
// whatever the number of keys. For bcrypt-only entries that have not been
// seen it is one bcrypt comparison per entry, which is what every request
// with a bearer credential used to cost.
//
//	go test ./internal/auth -run '^$' -bench APIKeyStore_UnknownBearer
func BenchmarkAPIKeyStore_UnknownBearer(b *testing.B) {
	for _, keys := range []int{1, 4, 16} {
		digests, hashes := make([]string, keys), make([]string, keys)
		for i := range keys {
			key, user := fmt.Sprintf("bench-key-%d", i), fmt.Sprintf("user-%d", i)
			digests[i] = sha256KeyEntry(key, user)
			hashes[i] = bcryptKeyEntry(b, key, user, bcrypt.DefaultCost)
		}

		reject := func(b *testing.B, store *APIKeyStore) {
			b.Helper()
			b.ResetTimer()
			for range b.N {
				if presentKey(b, store, "bench-key-unknown") != nil {
					b.Fatal("unknown bearer matched")
				}
			}
		}

		b.Run(fmt.Sprintf("key_sha256/keys=%d", keys), func(b *testing.B) {
			store, _ := loadAPIKeys(b, digests...)
			reject(b, store)
		})
		b.Run(fmt.Sprintf("bcrypt_seen/keys=%d", keys), func(b *testing.B) {
			store, _ := loadAPIKeys(b, hashes...)
			for i := range keys {
				if presentKey(b, store, fmt.Sprintf("bench-key-%d", i)) == nil {
					b.Fatal("key did not match")
				}
			}
			reject(b, store)
		})
		b.Run(fmt.Sprintf("bcrypt_unseen/keys=%d", keys), func(b *testing.B) {
			store, _ := loadAPIKeys(b, hashes...)
			reject(b, store)
		})
	}
}
