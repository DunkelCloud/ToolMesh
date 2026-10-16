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
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned for a grant that does not exist in the state asked
// for, or no longer: it expired or was taken.
var ErrNotFound = errors.New("grant not found")

// Store keeps pending requests and active grants until they expire. No
// method returns what has expired.
type Store interface {
	// Put stores g under its id and state until g.ExpiresAt.
	Put(ctx context.Context, g Grant) error
	// Get returns the grant with the id in the state.
	Get(ctx context.Context, state, id string) (Grant, error)
	// Take removes the grant with the id in the state and returns it. Of two
	// calls for the same grant, only one gets it; the other gets ErrNotFound.
	Take(ctx context.Context, state, id string) (Grant, error)
	// ForSubject returns the subject's grants in the state.
	ForSubject(ctx context.Context, state string, s Subject) ([]Grant, error)
	// List returns every grant in the state.
	List(ctx context.Context, state string) ([]Grant, error)
}

// MemoryStore keeps grants in process memory. They end with the process:
// after a restart, every caller holds what its steady-state rights allow and
// nothing more. Use the Redis store to keep grants across restarts and share
// them between instances.
type MemoryStore struct {
	mu      sync.Mutex
	now     func() time.Time
	byState map[string]map[string]Grant
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{now: time.Now, byState: map[string]map[string]Grant{}}
}

// prune drops what has expired in the state. The caller holds mu.
func (m *MemoryStore) prune(state string) map[string]Grant {
	now := m.now()
	byID := m.byState[state]
	if byID == nil {
		byID = map[string]Grant{}
		m.byState[state] = byID
	}
	for id, g := range byID {
		if !now.Before(g.ExpiresAt) {
			delete(byID, id)
		}
	}
	return byID
}

// Put stores g until g.ExpiresAt.
func (m *MemoryStore) Put(_ context.Context, g Grant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prune(g.State)[g.ID] = g
	return nil
}

// Get returns the grant with the id in the state.
func (m *MemoryStore) Get(_ context.Context, state, id string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.prune(state)[id]
	if !ok {
		return Grant{}, ErrNotFound
	}
	return g, nil
}

// Take removes the grant with the id in the state and returns it.
func (m *MemoryStore) Take(_ context.Context, state, id string) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := m.prune(state)
	g, ok := byID[id]
	if !ok {
		return Grant{}, ErrNotFound
	}
	delete(byID, id)
	return g, nil
}

// ForSubject returns the subject's grants in the state, oldest first.
func (m *MemoryStore) ForSubject(_ context.Context, state string, s Subject) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Grant
	for _, g := range m.prune(state) {
		if g.Subject() == s {
			out = append(out, g)
		}
	}
	sortGrants(out)
	return out, nil
}

// List returns every grant in the state, oldest first.
func (m *MemoryStore) List(_ context.Context, state string) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byID := m.prune(state)
	out := make([]Grant, 0, len(byID))
	for _, g := range byID {
		out = append(out, g)
	}
	sortGrants(out)
	return out, nil
}

// sortGrants orders grants by request time, then id.
func sortGrants(gs []Grant) {
	slices.SortFunc(gs, func(a, b Grant) int {
		if c := a.RequestedAt.Compare(b.RequestedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
}
