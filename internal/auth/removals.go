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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// removedKind is the kind of entry a removal is remembered for.
type removedKind string

// Kinds of entries whose removal is remembered. The value starts the key
// under which the removal is persisted.
const (
	removedAccess  removedKind = "access:"
	removedRefresh removedKind = "refresh:"
	removedCode    removedKind = "code:"
)

// removedKinds lists the kinds, for walking them.
var removedKinds = []removedKind{removedAccess, removedRefresh, removedCode}

// removal is one remembered removal.
type removal struct {
	// until is when the entry expires, and with it the copy another store
	// may hold. The removal is remembered that long.
	until time.Time
	// applied reports that the other store has been told since. The
	// removal stays remembered all the same: a request may have fetched
	// the copy before it was removed there. It is not persisted, so a
	// restart tells the other store again.
	applied bool
}

// pendingRemoval names a removal the other store has not been told about.
type pendingRemoval struct {
	kind  removedKind
	token string
}

// removals remembers entries that were deleted or consumed in the file
// store while another store, which holds a copy of them, could not be
// told. Until the entry expires, the removal has to stand against that
// copy: see HybridTokenStore.
//
// It has a lock of its own. The token check of every request asks it, and
// must not wait for the file store, which holds its lock while it writes
// its state to disk. A check for a kind without removals takes no lock at
// all.
type removals struct {
	mu     sync.RWMutex
	byKind map[removedKind]map[string]*removal
	// counts holds the number of removals per kind, readable without mu.
	counts map[removedKind]*atomic.Int64
	// pending counts the removals that are not applied yet.
	pending atomic.Int64
}

func newRemovals() *removals {
	r := &removals{
		byKind: make(map[removedKind]map[string]*removal, len(removedKinds)),
		counts: make(map[removedKind]*atomic.Int64, len(removedKinds)),
	}
	for _, k := range removedKinds {
		r.byKind[k] = make(map[string]*removal)
		r.counts[k] = new(atomic.Int64)
	}
	return r
}

// mark remembers the removal of the entry until the time until and reports
// whether that changed anything. A time that is not after now is not
// remembered: the copy has expired with it.
func (r *removals) mark(kind removedKind, token string, until, now time.Time) bool {
	if !until.After(now) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byKind[kind][token]; ok {
		if !until.After(old.until) {
			return false
		}
		old.until = until
		return true
	}
	r.byKind[kind][token] = &removal{until: until}
	r.counts[kind].Add(1)
	r.pending.Add(1)
	return true
}

// has reports whether a removal of the entry is remembered at now.
func (r *removals) has(kind removedKind, token string, now time.Time) bool {
	if r.counts[kind].Load() == 0 {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	rm, ok := r.byKind[kind][token]
	return ok && rm.until.After(now)
}

// drop forgets the removal of the entry and reports whether one was
// remembered. Use it only where no copy of the entry can be left or in
// flight; otherwise the removal has to stay until it expires.
func (r *removals) drop(kind removedKind, token string) bool {
	if r.counts[kind].Load() == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropLocked(kind, token)
}

func (r *removals) dropLocked(kind removedKind, token string) bool {
	rm, ok := r.byKind[kind][token]
	if !ok {
		return false
	}
	delete(r.byKind[kind], token)
	r.counts[kind].Add(-1)
	if !rm.applied {
		r.pending.Add(-1)
	}
	return true
}

// setApplied records that the other store has been told about the removal.
func (r *removals) setApplied(kind removedKind, token string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rm, ok := r.byKind[kind][token]; ok && !rm.applied {
		rm.applied = true
		r.pending.Add(-1)
	}
}

// hasPending reports whether the other store has not been told about some
// removal.
func (r *removals) hasPending() bool {
	return r.pending.Load() > 0
}

// pendingList returns the removals the other store has not been told about.
func (r *removals) pendingList() []pendingRemoval {
	if !r.hasPending() {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []pendingRemoval
	for kind, entries := range r.byKind {
		for token, rm := range entries {
			if !rm.applied {
				out = append(out, pendingRemoval{kind: kind, token: token})
			}
		}
	}
	return out
}

// expire forgets the removals whose entry has expired at now and reports
// whether there were any.
func (r *removals) expire(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	changed := false
	for kind, entries := range r.byKind {
		for token, rm := range entries {
			if !rm.until.After(now) {
				r.dropLocked(kind, token)
				changed = true
			}
		}
	}
	return changed
}

// size returns the number of remembered removals.
func (r *removals) size() int {
	n := 0
	for _, c := range r.counts {
		n += int(c.Load())
	}
	return n
}

// snapshot returns the removals in the form they are persisted in: the
// kind followed by the token, and the time the entry expires.
func (r *removals) snapshot() map[string]time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out map[string]time.Time
	for kind, entries := range r.byKind {
		for token, rm := range entries {
			if out == nil {
				out = make(map[string]time.Time)
			}
			out[string(kind)+token] = rm.until
		}
	}
	return out
}

// load takes over persisted removals that have not expired at now. None of
// them counts as applied: after a restart the other store is told again.
func (r *removals) load(persisted map[string]time.Time, now time.Time) {
	for key, until := range persisted {
		for _, kind := range removedKinds {
			if token, ok := strings.CutPrefix(key, string(kind)); ok {
				r.mark(kind, token, until, now)
				break
			}
		}
	}
}
