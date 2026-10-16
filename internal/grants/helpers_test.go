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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names shared by the tests of this package.
const (
	testKitNetDiag = "net-diag-read"
	testKitAdmin   = "admin-10min"
	testUser       = "bob"
	testCaller     = "claude-code"
	testOtherCall  = "claude-desktop"
	testApprover   = "alice"
	testReason     = "Debug the UniFi outage, ticket 4711"
	// testApproverKey is the key of the approver alice in these tests.
	testApproverKey = "approver-key-for-tests" //nolint:gosec // test fixture, not a credential
)

// t0 is when every test clock starts.
var t0 = time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)

// testClock is a clock tests move by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock { return &testClock{t: t0} }

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// testCatalog is the kit catalog and approver registry of the tests.
type testCatalog struct {
	kits      []authz.Kit
	approvers []authz.Approver
}

func (c *testCatalog) Kits() []authz.Kit           { return c.kits }
func (c *testCatalog) Approvers() []authz.Approver { return c.approvers }

// keySum returns the key_sha256 of a key.
func keySum(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// newTestCatalog has two kits and the approver alice.
func newTestCatalog() *testCatalog {
	return &testCatalog{
		kits: []authz.Kit{
			{Name: testKitAdmin, Description: "Full access", Warning: "Production systems.", Grants: []string{"*"}, TTLDefault: 10 * time.Minute, TTLMax: 30 * time.Minute},
			{Name: testKitNetDiag, Description: "Network diagnosis (read-only)", Grants: []string{"graylog:read", "unifi:read"}, TTLDefault: 4 * time.Hour, TTLMax: 24 * time.Hour},
		},
		approvers: []authz.Approver{{Name: testApprover, KeySHA256: keySum(testApproverKey)}},
	}
}

// memAudit keeps every recorded entry.
type memAudit struct {
	mu      sync.Mutex
	entries []audit.AuditEntry
}

func (a *memAudit) Record(_ context.Context, e audit.AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, e)
	return nil
}

func (a *memAudit) Query(_ context.Context, _ audit.AuditFilter) ([]audit.AuditEntry, error) {
	return nil, audit.ErrQueryNotSupported
}

func (a *memAudit) Healthy(_ context.Context) error { return nil }

// last returns the entry recorded last.
func (a *memAudit) last(t *testing.T) audit.AuditEntry {
	t.Helper()
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.entries) == 0 {
		t.Fatal("nothing was audited")
	}
	return a.entries[len(a.entries)-1]
}

// failingStore fails every call.
type failingStore struct{}

var errStoreDown = errors.New("store down")

func (failingStore) Put(context.Context, Grant) error { return errStoreDown }
func (failingStore) Get(context.Context, string, string) (Grant, error) {
	return Grant{}, errStoreDown
}
func (failingStore) Take(context.Context, string, string) (Grant, error) {
	return Grant{}, errStoreDown
}
func (failingStore) ForSubject(context.Context, string, Subject) ([]Grant, error) {
	return nil, errStoreDown
}
func (failingStore) List(context.Context, string) ([]Grant, error) { return nil, errStoreDown }

// testEnv is a service on a memory store with a hand-moved clock.
type testEnv struct {
	svc   *Service
	cat   *testCatalog
	clock *testClock
	audit *memAudit
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	clock := newTestClock()
	store := NewMemoryStore()
	store.now = clock.now
	cat := newTestCatalog()
	rec := &memAudit{}
	svc := New(Options{Store: store, Kits: cat, Approvers: cat, Audit: rec, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	svc.now = clock.now
	return &testEnv{svc: svc, cat: cat, clock: clock, audit: rec}
}

// caller returns the authenticated caller bob, connected as callerID.
func caller(callerID string) *userctx.UserContext {
	return &userctx.UserContext{UserID: testUser, CallerID: callerID, CallerName: callerID, Authenticated: true}
}

// request asks for a kit as bob from Claude Code and fails the test on an
// error.
func (e *testEnv) request(t *testing.T, kit, ttl string) RequestResult {
	t.Helper()
	res, err := e.svc.Request(context.Background(), caller(testCaller), RequestInput{Kit: kit, Reason: testReason, TTL: ttl})
	if err != nil {
		t.Fatalf("Request(%s): %v", kit, err)
	}
	return res
}
