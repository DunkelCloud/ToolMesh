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

package gate

import (
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Phase represents the evaluation phase in the gate pipeline.
type Phase string

const (
	// PhasePre runs before backend execution to validate input parameters.
	PhasePre Phase = "pre"
	// PhasePost runs after backend execution to filter/mask output.
	PhasePost Phase = "post"
)

// GateContext is the context passed to gate policies for evaluation.
type GateContext struct {
	User     userctx.UserContext `json:"user"`
	Tool     string              `json:"tool"`
	Params   map[string]any      `json:"params"`
	Phase    Phase               `json:"phase"`
	Response *backend.ToolResult `json:"response"`
}

// RateLimiter tracks per-user request counts with a sliding window.
type RateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		windows: make(map[string][]time.Time),
	}
}

// Check returns true if the user has exceeded the given limit per hour.
// This is a read-only check that does not record a request.
func (rl *RateLimiter) Check(userID string, limit int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Hour)

	// Prune expired entries
	entries := rl.windows[userID]
	pruned := entries[:0]
	for _, t := range entries {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	rl.windows[userID] = pruned

	return len(pruned) > limit
}

// Record adds a request timestamp for the given user.
// Call this once per actual request, separate from Check to prevent
// policy scripts from inflating the counter by calling Check in a loop.
func (rl *RateLimiter) Record(userID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	rl.windows[userID] = append(rl.windows[userID], now)

	// Remove stale users to prevent unbounded memory growth
	if len(rl.windows) > 1000 {
		cutoff := now.Add(-time.Hour)
		for uid, w := range rl.windows {
			if len(w) == 0 || w[len(w)-1].Before(cutoff) {
				delete(rl.windows, uid)
			}
		}
	}
}
