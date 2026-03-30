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
	"fmt"
	"testing"
	"time"
)

func TestRateLimiter_Check_BasicLimit(t *testing.T) {
	rl := NewRateLimiter()

	tests := []struct {
		name    string
		userID  string
		limit   int
		calls   int
		wantExc bool // whether the last call should exceed
	}{
		{
			name:    "under limit returns false",
			userID:  "user-a",
			limit:   10,
			calls:   5,
			wantExc: false,
		},
		{
			name:    "exactly at limit returns false",
			userID:  "user-b",
			limit:   3,
			calls:   3,
			wantExc: false,
		},
		{
			name:    "over limit returns true",
			userID:  "user-c",
			limit:   3,
			calls:   4,
			wantExc: true,
		},
		{
			name:    "limit of 1 exceeded on second call",
			userID:  "user-d",
			limit:   1,
			calls:   2,
			wantExc: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var exceeded bool
			for i := 0; i < tt.calls; i++ {
				exceeded = rl.Check(tt.userID, tt.limit)
			}
			if exceeded != tt.wantExc {
				t.Errorf("after %d calls with limit %d: exceeded = %v, want %v",
					tt.calls, tt.limit, exceeded, tt.wantExc)
			}
		})
	}
}

func TestRateLimiter_Check_IndependentUsers(t *testing.T) {
	rl := NewRateLimiter()

	// User A makes 5 requests with limit 5
	for i := 0; i < 5; i++ {
		rl.Check("user-x", 5)
	}

	// User B should still be under limit
	if rl.Check("user-y", 5) {
		t.Error("user-y should not be rate limited by user-x's requests")
	}
}

func TestRateLimiter_Check_StaleUserCleanup(t *testing.T) {
	rl := NewRateLimiter()

	// Populate more than 1000 users to trigger cleanup
	for i := 0; i < 1005; i++ {
		userID := fmt.Sprintf("stale-user-%d", i)
		rl.Check(userID, 100)
	}

	// Manually expire some entries to test cleanup path
	rl.mu.Lock()
	cutoff := time.Now().Add(-2 * time.Hour)
	for i := 0; i < 500; i++ {
		userID := fmt.Sprintf("stale-user-%d", i)
		rl.windows[userID] = []time.Time{cutoff}
	}
	rl.mu.Unlock()

	// Next check should trigger cleanup of stale users
	rl.Check("trigger-cleanup-user", 100)

	rl.mu.Lock()
	remaining := len(rl.windows)
	rl.mu.Unlock()

	// After cleanup, the 500 stale users should be removed
	if remaining > 600 {
		t.Errorf("expected stale users to be cleaned up, but %d users remain", remaining)
	}
}

func TestRateLimiter_Check_EmptyWindowCleanup(t *testing.T) {
	rl := NewRateLimiter()

	// Create more than 1000 users with empty windows
	rl.mu.Lock()
	for i := 0; i < 1005; i++ {
		userID := fmt.Sprintf("empty-user-%d", i)
		rl.windows[userID] = []time.Time{}
	}
	rl.mu.Unlock()

	// Trigger cleanup
	rl.Check("new-user", 100)

	rl.mu.Lock()
	remaining := len(rl.windows)
	rl.mu.Unlock()

	// Empty windows should be cleaned up
	if remaining > 100 {
		t.Errorf("expected empty window users to be cleaned up, but %d remain", remaining)
	}
}
