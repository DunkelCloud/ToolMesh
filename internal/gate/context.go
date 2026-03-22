package gate

import (
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// GateContext is the context passed to gate policies for evaluation.
type GateContext struct {
	User     userctx.UserContext `json:"user"`
	Tool     string              `json:"tool"`
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

	// Record this request
	pruned = append(pruned, now)
	rl.windows[userID] = pruned

	// Remove stale users to prevent unbounded memory growth
	if len(rl.windows) > 1000 {
		for uid, w := range rl.windows {
			if len(w) == 0 || w[len(w)-1].Before(cutoff) {
				delete(rl.windows, uid)
			}
		}
	}

	return len(pruned) > limit
}
