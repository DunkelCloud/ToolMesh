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
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

func TestRequest_Invalid(t *testing.T) {
	tests := []struct {
		name string
		uc   *userctx.UserContext
		in   RequestInput
		want string
	}{
		{"no caller", nil, RequestInput{Kit: testKitNetDiag, Reason: testReason}, "authenticated"},
		{"unauthenticated", &userctx.UserContext{UserID: "anonymous"}, RequestInput{Kit: testKitNetDiag, Reason: testReason}, "authenticated"},
		{"no kit", caller(testCaller), RequestInput{Reason: testReason}, "name the kit"},
		{"unknown kit", caller(testCaller), RequestInput{Kit: "nope", Reason: testReason}, `no kit "nope"`},
		{"no reason", caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: " \n\t "}, "give a reason"},
		{"long reason", caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: strings.Repeat("x", MaxReasonLen+1)}, "more than"},
		{"bad ttl", caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: testReason, TTL: "soon"}, "positive duration"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			_, err := env.svc.Request(context.Background(), tc.uc, tc.in)
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want ErrInvalid containing %q", err, tc.want)
			}
			if e := env.audit.last(t); e.Tool != ToolRequestGrant || e.Status != statusError {
				t.Errorf("audit = %+v, want an error entry of %s", e, ToolRequestGrant)
			}
		})
	}
}

func TestRequest_NoApprovers(t *testing.T) {
	env := newTestEnv(t)
	env.cat.approvers = nil
	_, err := env.svc.Request(context.Background(), caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: testReason})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "no approver") {
		t.Fatalf("err = %v, want the missing approvers named", err)
	}
}

func TestRequest_TTL(t *testing.T) {
	wide := authz.Kit{Name: "wide", Description: "No durations set", Grants: []string{"*"}}
	tests := []struct {
		name       string
		kit        string
		ttl        string
		want       time.Duration
		wantCapped bool
	}{
		{"kit default", testKitNetDiag, "", 4 * time.Hour, false},
		{"asked", testKitNetDiag, "90m", 90 * time.Minute, false},
		{"capped at the kit maximum", testKitAdmin, "2h", 30 * time.Minute, true},
		{"package default", wide.Name, "", DefaultTTL, false},
		{"package maximum", wide.Name, "48h", MaxTTL, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t)
			env.cat.kits = append(env.cat.kits, wide)
			res := env.request(t, tc.kit, tc.ttl)
			if res.Grant.TTL != tc.want || res.Capped != tc.wantCapped {
				t.Errorf("ttl = %s (capped %v), want %s (capped %v)", res.Grant.TTL, res.Capped, tc.want, tc.wantCapped)
			}
		})
	}
}

func TestRequest_Pending(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	res := env.request(t, testKitNetDiag, "")
	g := res.Grant
	if res.Existing || g.State != StatePending || g.UserID != testUser || g.CallerID != testCaller ||
		g.Reason != testReason || !g.ExpiresAt.Equal(t0.Add(RequestTTL)) || len(g.ID) != 10 {
		t.Fatalf("request = %+v", res)
	}
	if e := env.audit.last(t); e.Status != statusSuccess || e.UserID != testUser || e.CallerID != testCaller ||
		e.Metadata["grant_id"] != g.ID || e.Metadata["kit"] != testKitNetDiag || e.Metadata["ttl"] != "4h" {
		t.Errorf("audit = %+v", e)
	}

	// The same kit again: the pending request, unchanged.
	again := env.request(t, testKitNetDiag, "1h")
	if !again.Existing || again.Grant.ID != g.ID || again.Grant.TTL != 4*time.Hour {
		t.Errorf("second request = %+v, want the first one, unchanged", again)
	}
	// Another caller of the same user asks on its own.
	other, err := env.svc.Request(ctx, caller(testOtherCall), RequestInput{Kit: testKitNetDiag, Reason: testReason})
	if err != nil || other.Existing || other.Grant.ID == g.ID {
		t.Errorf("request from another caller = %+v, %v; want a request of its own", other, err)
	}
	// The request lapses unanswered.
	env.clock.advance(RequestTTL)
	if _, err := env.svc.Lookup(ctx, g.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup after RequestTTL: err = %v, want ErrNotFound", err)
	}
}

func TestRequest_MaxPending(t *testing.T) {
	env := newTestEnv(t)
	for i := range MaxPending {
		env.cat.kits = append(env.cat.kits, authz.Kit{Name: fmt.Sprintf("k%d", i), Description: "kit", Grants: []string{"*"}})
		env.request(t, fmt.Sprintf("k%d", i), "")
	}
	_, err := env.svc.Request(context.Background(), caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: testReason})
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "waiting") {
		t.Fatalf("err = %v, want the pending limit", err)
	}
}

func TestRequest_ReasonCleaned(t *testing.T) {
	env := newTestEnv(t)
	res, err := env.svc.Request(context.Background(), caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: "  line one\nline\x00 two\x1b[31m  "})
	if err != nil {
		t.Fatal(err)
	}
	if res.Grant.Reason != "line one line two[31m" {
		t.Errorf("reason = %q", res.Grant.Reason)
	}
}

func TestApprove(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	id := env.request(t, testKitNetDiag, "").Grant.ID
	if kits := env.svc.HeldKits(ctx, testUser, testCaller); len(kits) != 0 {
		t.Fatalf("held before approval: %v", kits)
	}

	env.clock.advance(5 * time.Minute)
	g, err := env.svc.Approve(ctx, testApprover, id, 0)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	approvedAt := t0.Add(5 * time.Minute)
	if g.State != StateActive || g.ApprovedBy != testApprover || !g.ApprovedAt.Equal(approvedAt) || !g.ExpiresAt.Equal(approvedAt.Add(4*time.Hour)) {
		t.Errorf("grant = %+v", g)
	}
	if e := env.audit.last(t); e.Tool != auditApprove || e.Status != statusSuccess || e.UserID != testUser || e.Metadata["approver"] != testApprover || e.Metadata["grant_id"] != id {
		t.Errorf("audit = %+v", e)
	}

	// Held by the caller that asked, not by another caller of the same user.
	if kits := env.svc.HeldKits(ctx, testUser, testCaller); !slices.Equal(kits, []string{testKitNetDiag}) {
		t.Errorf("HeldKits = %v", kits)
	}
	if kits := env.svc.HeldKits(ctx, testUser, testOtherCall); len(kits) != 0 {
		t.Errorf("HeldKits of another caller = %v, want none", kits)
	}
	// Approved once only.
	if _, err := env.svc.Approve(ctx, testApprover, id, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Approve: err = %v, want ErrNotFound", err)
	}
	// The grant ends by itself.
	env.clock.advance(4 * time.Hour)
	if kits := env.svc.HeldKits(ctx, testUser, testCaller); len(kits) != 0 {
		t.Errorf("HeldKits after expiry = %v", kits)
	}
}

func TestApprove_TTL(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	id := env.request(t, testKitNetDiag, "2h").Grant.ID
	if _, err := env.svc.Approve(ctx, testApprover, id, 3*time.Hour); !errors.Is(err, ErrInvalid) {
		t.Fatalf("approval longer than requested: err = %v, want ErrInvalid", err)
	}
	g, err := env.svc.Approve(ctx, testApprover, id, 30*time.Minute)
	if err != nil || g.TTL != 30*time.Minute || !g.ExpiresAt.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("shortened approval = %+v, %v", g, err)
	}
}

func TestApprove_ReplacesHeldGrant(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	first, _ := env.svc.Approve(ctx, testApprover, env.request(t, testKitNetDiag, "1h").Grant.ID, 0)
	second, err := env.svc.Approve(ctx, testApprover, env.request(t, testKitNetDiag, "3h").Grant.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, active, _ := env.svc.ForCaller(ctx, testUser, testCaller)
	if !slices.Equal(ids(active), []string{second.ID}) {
		t.Errorf("active = %v, want only %s (replacing %s)", ids(active), second.ID, first.ID)
	}
}

func TestApprove_KitRemoved(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	id := env.request(t, testKitNetDiag, "").Grant.ID
	env.cat.kits = env.cat.kits[:1] // only admin-10min is left
	if _, err := env.svc.Approve(ctx, testApprover, id, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("Approve of a removed kit: err = %v, want ErrInvalid", err)
	}
}

func TestHeldKits_KitRemovedAfterApproval(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	if _, err := env.svc.Approve(ctx, testApprover, env.request(t, testKitNetDiag, "").Grant.ID, 0); err != nil {
		t.Fatal(err)
	}
	env.cat.kits = env.cat.kits[:1]
	if kits := env.svc.HeldKits(ctx, testUser, testCaller); len(kits) != 0 {
		t.Errorf("HeldKits = %v, want none: the kit is no longer defined", kits)
	}
}

func TestDenyAndRevoke(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	denied := env.request(t, testKitAdmin, "").Grant.ID
	if g, err := env.svc.Deny(ctx, testApprover, denied); err != nil || g.Kit != testKitAdmin {
		t.Fatalf("Deny = %+v, %v", g, err)
	}
	if e := env.audit.last(t); e.Tool != auditDeny || e.Status != statusSuccess || e.Metadata["approver"] != testApprover {
		t.Errorf("audit = %+v", e)
	}
	if _, err := env.svc.Approve(ctx, testApprover, denied, 0); !errors.Is(err, ErrNotFound) {
		t.Errorf("Approve after Deny: err = %v, want ErrNotFound", err)
	}

	id := env.request(t, testKitNetDiag, "").Grant.ID
	if _, err := env.svc.Revoke(ctx, testApprover, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("Revoke of a pending request: err = %v, want ErrNotFound", err)
	}
	if _, err := env.svc.Approve(ctx, testApprover, id, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := env.svc.Revoke(ctx, testApprover, id); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if e := env.audit.last(t); e.Tool != auditRevoke || e.Status != statusSuccess {
		t.Errorf("audit = %+v", e)
	}
	if kits := env.svc.HeldKits(ctx, testUser, testCaller); len(kits) != 0 {
		t.Errorf("HeldKits after Revoke = %v", kits)
	}
	if _, err := env.svc.Revoke(ctx, testApprover, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Revoke: err = %v, want ErrNotFound", err)
	}
	if e := env.audit.last(t); e.Status != statusError || e.Metadata["grant_id"] != id {
		t.Errorf("failed revoke not audited as an error: %+v", e)
	}
}

func TestList(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	pendingID := env.request(t, testKitAdmin, "").Grant.ID
	activeID := env.request(t, testKitNetDiag, "").Grant.ID
	if _, err := env.svc.Approve(ctx, testApprover, activeID, 0); err != nil {
		t.Fatal(err)
	}
	pending, active, err := env.svc.List(ctx)
	if err != nil || !slices.Equal(ids(pending), []string{pendingID}) || !slices.Equal(ids(active), []string{activeID}) {
		t.Errorf("List = %v, %v, %v", ids(pending), ids(active), err)
	}
	if g, err := env.svc.Lookup(ctx, activeID); err != nil || g.State != StateActive {
		t.Errorf("Lookup(active) = %+v, %v", g, err)
	}
}

// A store that fails grants nothing and refuses requests.
func TestStoreFailure(t *testing.T) {
	cat := newTestCatalog()
	svc := New(Options{Store: failingStore{}, Kits: cat, Approvers: cat, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ctx := context.Background()
	if kits := svc.HeldKits(ctx, testUser, testCaller); kits != nil {
		t.Errorf("HeldKits = %v, want none", kits)
	}
	if _, err := svc.Request(ctx, caller(testCaller), RequestInput{Kit: testKitNetDiag, Reason: testReason}); !errors.Is(err, errStoreDown) {
		t.Errorf("Request: err = %v, want the store error", err)
	}
}

func TestApprover(t *testing.T) {
	env := newTestEnv(t)
	if a, ok := env.svc.Approver(testApproverKey); !ok || a.Name != testApprover {
		t.Errorf("Approver(key) = %+v, %v", a, ok)
	}
	for _, key := range []string{"", "wrong", keySum(testApproverKey)} {
		if _, ok := env.svc.Approver(key); ok {
			t.Errorf("Approver(%q) accepted", key)
		}
	}
}
