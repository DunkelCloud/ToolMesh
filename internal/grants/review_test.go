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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Concurrent requests through the service stay within the limit, and one
// kit gets one request.
func TestRequest_Concurrent(t *testing.T) {
	env := newTestEnv(t)
	for i := range 3 * MaxPending {
		env.cat.kits = append(env.cat.kits, authz.Kit{Name: fmt.Sprintf("k%02d", i), Description: "generated kit", Grants: []string{"*"}})
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	var ok, limited atomic.Int32
	ids := make(chan string, 10)
	for i := range 3 * MaxPending {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := env.svc.Request(ctx, caller(testCaller), RequestInput{Kit: fmt.Sprintf("k%02d", i), Reason: testReason})
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrInvalid):
				limited.Add(1)
			default:
				t.Errorf("Request: %v", err)
			}
		}()
	}
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := env.svc.Request(ctx, caller(testOtherCall), RequestInput{Kit: testKitNetDiag, Reason: testReason})
			if err != nil {
				t.Errorf("Request(same kit): %v", err)
				return
			}
			ids <- res.Grant.ID
		}()
	}
	wg.Wait()
	close(ids)
	if ok.Load() != MaxPending || limited.Load() != 2*MaxPending {
		t.Errorf("%d requests accepted, %d refused; want %d and %d", ok.Load(), limited.Load(), MaxPending, 2*MaxPending)
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Errorf("concurrent requests for one kit created %d requests, want 1", len(seen))
	}
}

func TestRequest_CallerNameCleaned(t *testing.T) {
	env := newTestEnv(t)
	uc := caller(testCaller)
	uc.CallerName = "Claude\u202e edoC\u200b\n" + strings.Repeat("x", 2*MaxCallerNameLen)
	res, err := env.svc.Request(context.Background(), uc, RequestInput{Kit: testKitNetDiag, Reason: testReason})
	if err != nil {
		t.Fatal(err)
	}
	name := res.Grant.CallerName
	if !strings.HasPrefix(name, "Claude edoC x") || utf8.RuneCountInString(name) != MaxCallerNameLen || strings.ContainsAny(name, "\u202e\u200b\n") {
		t.Errorf("caller name = %q (%d characters)", name, utf8.RuneCountInString(name))
	}
}

func TestCleanText_FormatCharacters(t *testing.T) {
	in := "approve\u202e\u2066 this\u2069\u200b\u200d\ufeff now\x07"
	if got := cleanText(in); got != "approve this now" {
		t.Errorf("cleanText(%q) = %q", in, got)
	}
}

// An approval is capped at the kit's maximum as it is when approved.
func TestApprove_CappedAtCurrentKitMax(t *testing.T) {
	env := newTestEnv(t)
	id := env.request(t, testKitNetDiag, "4h").Grant.ID
	env.cat.kits[1].TTLMax = time.Hour
	env.cat.kits[1].TTLDefault = time.Hour
	g, err := env.svc.Approve(context.Background(), testApprover, id, 0)
	if err != nil || g.TTL != time.Hour || !g.ExpiresAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("Approve = %+v, %v; want 1h, the kit's maximum now", g, err)
	}
}

// A kit without ttl_max is granted for MaxTTL at most, even with a longer
// ttl_default (which the config file rejects).
func TestKitTTL_NoMaxCapsDefault(t *testing.T) {
	ttl, capped := kitTTL(authz.Kit{TTLDefault: 48 * time.Hour}, 0)
	if ttl != MaxTTL || capped {
		t.Errorf("kitTTL = %s, %v; want %s", ttl, capped, MaxTTL)
	}
}

// Two API keys of one user without caller_id share the caller id but not
// their grants.
func TestGrantKey_BindsToTheKey(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	keyA := &userctx.UserContext{UserID: testUser, CallerID: testUser, Authenticated: true, GrantKey: "key-a"}
	keyB := &userctx.UserContext{UserID: testUser, CallerID: testUser, Authenticated: true, GrantKey: "key-b"}

	res, err := env.svc.Request(ctx, keyA, RequestInput{Kit: testKitNetDiag, Reason: testReason})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grant.CallerID != testUser || res.Grant.GrantKey != "key-a" {
		t.Errorf("request = %+v, want the caller id kept and the key bound", res.Grant)
	}
	// Key B asks for the same kit on its own.
	if other, err := env.svc.Request(ctx, keyB, RequestInput{Kit: testKitNetDiag, Reason: testReason}); err != nil || other.Existing {
		t.Errorf("request of key B = %+v, %v; want a request of its own", other, err)
	}
	if _, err := env.svc.Approve(ctx, testApprover, res.Grant.ID, 0); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		binding string
		want    int
	}{{keyA.GrantBinding(), 1}, {keyB.GrantBinding(), 0}, {testUser, 0}} {
		if got := heldWhole(ctx, env.svc, tc.binding); len(got) != tc.want {
			t.Errorf("HeldKits(%s) = %v, want %d kits", tc.binding, got, tc.want)
		}
	}
}

// countingStore counts the reads of each state.
type countingStore struct {
	Store
	reads map[string]*atomic.Int32
}

func (c countingStore) ForSubject(ctx context.Context, state string, s Subject) ([]Grant, error) {
	c.reads[state].Add(1)
	return c.Store.ForSubject(ctx, state, s)
}

// The check path reads the active grants only.
func TestHeldKits_ReadsActiveOnly(t *testing.T) {
	env := newTestEnv(t)
	store := countingStore{Store: env.svc.store, reads: map[string]*atomic.Int32{StatePending: {}, StateActive: {}}}
	env.svc.store = store
	heldWhole(context.Background(), env.svc, testCaller)
	if store.reads[StatePending].Load() != 0 || store.reads[StateActive].Load() != 1 {
		t.Errorf("reads: pending %d, active %d; want 0 and 1", store.reads[StatePending].Load(), store.reads[StateActive].Load())
	}
}
