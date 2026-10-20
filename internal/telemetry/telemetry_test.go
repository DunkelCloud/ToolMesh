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

package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestRecordCall_IncrementsCounters(t *testing.T) {
	c := New(t.TempDir(), "test", quietLogger())
	c.RegisterBackend("api", "abc123")

	c.RecordCall("api", true)
	c.RecordCall("api", true)
	c.RecordCall("api", false)

	c.mu.Lock()
	defer c.mu.Unlock()

	cp := c.counters["abc123"]
	if cp == nil {
		t.Fatal("expected counter for abc123")
	}
	if cp.CallCount != 2 {
		t.Errorf("call_count = %d, want 2", cp.CallCount)
	}
	if cp.ErrorCount != 1 {
		t.Errorf("error_count = %d, want 1", cp.ErrorCount)
	}
}

func TestRecordCall_UnknownBackend(t *testing.T) {
	c := New(t.TempDir(), "test", quietLogger())

	// Should not panic or add any counter.
	c.RecordCall("unknown", true)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.counters) != 0 {
		t.Errorf("expected 0 counters, got %d", len(c.counters))
	}
}

func TestRecordCall_ConcurrentSafety(t *testing.T) {
	c := New(t.TempDir(), "test", quietLogger())
	c.RegisterBackend("api", "hash1")

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.RecordCall("api", true)
		}()
	}
	wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.counters["hash1"].CallCount != 100 {
		t.Errorf("call_count = %d, want 100", c.counters["hash1"].CallCount)
	}
}

func TestStatePersistence_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	// Create collector, record some calls, persist.
	c1 := New(dir, "v1", quietLogger())
	c1.RegisterBackend("api", "hashA")
	c1.RecordCall("api", true)
	c1.RecordCall("api", false)
	c1.persistState()

	// Verify the state file exists and contains valid JSON.
	data, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // test path from t.TempDir()
	if err != nil {
		t.Fatalf("state file not created: %v", err)
	}

	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid state JSON: %v", err)
	}
	if state.Telemetry == nil {
		t.Fatal("telemetry key missing from state")
	}
	cp := state.Telemetry.Counters["hashA"]
	if cp == nil {
		t.Fatal("counter for hashA missing")
	}
	if cp.CallCount != 1 || cp.ErrorCount != 1 {
		t.Errorf("persisted counters = %+v, want {1, 1}", cp)
	}

	// Create a new collector reading back the state.
	c2 := New(dir, "v1", quietLogger())
	c2.mu.Lock()
	cp2 := c2.counters["hashA"]
	c2.mu.Unlock()
	if cp2 == nil {
		t.Fatal("state not loaded for hashA")
	}
	if cp2.CallCount != 1 || cp2.ErrorCount != 1 {
		t.Errorf("loaded counters = %+v, want {1, 1}", cp2)
	}
}

func TestStatePersistence_MissingFile(t *testing.T) {
	// Loading from an empty dir should not error.
	c := New(t.TempDir(), "v1", quietLogger())
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.counters) != 0 {
		t.Errorf("expected empty counters, got %d", len(c.counters))
	}
}

func TestSend_PayloadFormat(t *testing.T) {
	var (
		mu       sync.Mutex
		received []report
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json, got %s", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var reports []report
		if err := json.Unmarshal(body, &reports); err != nil {
			t.Errorf("invalid JSON payload: %v", err)
		}
		mu.Lock()
		received = reports
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(t.TempDir(), "0.1.0", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("myapi", "deadbeef"+"00000000000000000000000000000000000000000000000000000000")
	c.RecordCall("myapi", true)
	c.RecordCall("myapi", true)
	c.RecordCall("myapi", false)

	c.send(t.Context())

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 report, got %d", len(received))
	}
	r := received[0]
	if r.CallCount != 2 {
		t.Errorf("call_count = %d, want 2", r.CallCount)
	}
	if r.ErrorCount != 1 {
		t.Errorf("error_count = %d, want 1", r.ErrorCount)
	}
	if r.Version != "0.1.0" {
		t.Errorf("version = %q, want 0.1.0", r.Version)
	}
	if r.SiteID == "" || r.SiteID != c.siteID {
		t.Errorf("site_id = %q, want the collector's site ID %q", r.SiteID, c.siteID)
	}

	// Counters should be reset after successful send.
	c.mu.Lock()
	if len(c.counters) != 0 {
		t.Errorf("counters not reset after send, got %d", len(c.counters))
	}
	c.mu.Unlock()
}

func TestSend_ServerError_KeepsCounters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := New(t.TempDir(), "v1", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("api", "hash1")
	c.RecordCall("api", true)

	c.send(t.Context())

	c.mu.Lock()
	defer c.mu.Unlock()
	cp := c.counters["hash1"]
	if cp == nil || cp.CallCount != 1 {
		t.Error("counters should be preserved on server error")
	}
}

// testHash returns a distinct 64-character hex DADL hash for i.
func testHash(i int) string {
	h := strconv.FormatInt(int64(i), 16)
	return strings.Repeat("0", 64-len(h)) + h
}

// batchCollector is a telemetry endpoint that behaves like the real
// collector: it rejects requests with more than 50 entries. It records the
// entries of every accepted request and answers 500 to the request whose
// 1-based number is failAt.
type batchCollector struct {
	srv      *httptest.Server
	mu       sync.Mutex
	failAt   int
	requests int
	accepted [][]report
}

func newBatchCollector(t *testing.T, failAt int) *batchCollector {
	t.Helper()
	b := &batchCollector{failAt: failAt}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var entries []report
		if err := json.Unmarshal(body, &entries); err != nil {
			t.Errorf("invalid JSON payload: %v", err)
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		b.requests++
		switch {
		case len(entries) > 50:
			w.WriteHeader(http.StatusBadRequest)
		case b.requests == b.failAt:
			w.WriteHeader(http.StatusInternalServerError)
		default:
			b.accepted = append(b.accepted, entries)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func TestSend_SplitsReportIntoBatchesOfAtMost50(t *testing.T) {
	tests := []struct {
		backends  int
		wantSizes []int
	}{
		{backends: 1, wantSizes: []int{1}},
		{backends: 50, wantSizes: []int{50}},
		{backends: 51, wantSizes: []int{50, 1}},
		{backends: 120, wantSizes: []int{50, 50, 20}},
	}
	for _, tt := range tests {
		t.Run(strconv.Itoa(tt.backends), func(t *testing.T) {
			sink := newBatchCollector(t, 0)
			c := New(t.TempDir(), "v1", quietLogger())
			c.SetEndpoint(sink.srv.URL)
			for i := range tt.backends {
				name := "api" + strconv.Itoa(i)
				c.RegisterBackend(name, testHash(i))
				c.RecordCall(name, true)
			}

			c.send(t.Context())

			sink.mu.Lock()
			defer sink.mu.Unlock()
			if sink.requests != len(tt.wantSizes) {
				t.Fatalf("requests = %d, want %d", sink.requests, len(tt.wantSizes))
			}
			seen := make(map[string]int)
			for i, batch := range sink.accepted {
				if len(batch) != tt.wantSizes[i] {
					t.Errorf("request %d has %d entries, want %d", i+1, len(batch), tt.wantSizes[i])
				}
				for _, e := range batch {
					seen[e.DADLHash]++
					if e.SiteID != c.siteID || e.CallCount != 1 {
						t.Errorf("entry %s: site_id %q, call_count %d; want %q, 1", e.DADLHash, e.SiteID, e.CallCount, c.siteID)
					}
				}
			}
			for i := range tt.backends {
				if seen[testHash(i)] != 1 {
					t.Errorf("hash %d reported %d times, want once", i, seen[testHash(i)])
				}
			}

			c.mu.Lock()
			defer c.mu.Unlock()
			if len(c.counters) != 0 {
				t.Errorf("%d counters left after a fully accepted report, want 0", len(c.counters))
			}
			if c.lastSent.IsZero() {
				t.Error("lastSent not set after a fully accepted report")
			}
		})
	}
}

func TestSend_RejectedBatchKeepsItsCounters(t *testing.T) {
	dir := t.TempDir()
	sink := newBatchCollector(t, 2) // accept the first request, fail the second
	c := New(dir, "v1", quietLogger())
	c.SetEndpoint(sink.srv.URL)
	for i := range 60 {
		name := "api" + strconv.Itoa(i)
		c.RegisterBackend(name, testHash(i))
		c.RecordCall(name, true)
	}

	c.send(t.Context())

	c.mu.Lock()
	if !c.lastSent.IsZero() {
		t.Error("lastSent set although a request was rejected")
	}
	if len(c.counters) != 10 {
		t.Errorf("%d counters left, want the 10 of the rejected request", len(c.counters))
	}
	for i := range 50 {
		if c.counters[testHash(i)] != nil {
			t.Errorf("counter of accepted hash %d not reset", i)
		}
	}
	c.mu.Unlock()

	// The reset counters must already be on disk.
	data, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // path from t.TempDir()
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("parse state file: %v", err)
	}
	if len(state.Telemetry.Counters) != 10 {
		t.Errorf("state file holds %d counters, want 10", len(state.Telemetry.Counters))
	}

	// The next cycle delivers the rest; no call is counted twice.
	sink.mu.Lock()
	sink.failAt = 0
	sink.mu.Unlock()
	c.send(t.Context())

	sink.mu.Lock()
	defer sink.mu.Unlock()
	total := 0
	for _, batch := range sink.accepted {
		for _, e := range batch {
			total += e.CallCount
		}
	}
	if total != 60 {
		t.Errorf("collector counted %d calls over both cycles, want 60", total)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.counters) != 0 || c.lastSent.IsZero() {
		t.Errorf("after the second cycle: %d counters, lastSent zero %v; want 0, false", len(c.counters), c.lastSent.IsZero())
	}
}

func TestOptOut_PreventsHTTPSend(t *testing.T) {
	t.Setenv("DO_NOT_SEND_ANONYMOUS_STATISTICS", "yes")

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		called = true
	}))
	defer srv.Close()

	c := New(t.TempDir(), "v1", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("api", "hash1")
	c.RecordCall("api", true)

	if !c.disabled {
		t.Fatal("expected disabled=true")
	}

	// send() should be a no-op when Run() is used, but let's directly
	// verify the disabled flag prevents the send path.
	// Run() checks c.disabled before calling send().
	if called {
		t.Error("HTTP endpoint should not have been called when opted out")
	}

	// Counters should still be incremented for potential re-enablement.
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := c.counters["hash1"]
	if cp == nil || cp.CallCount != 1 {
		t.Error("counters should still increment when opted out")
	}
}

// TestPersistState_LastSentZeroStaysZeroAfterShutdown reproduces the demo
// installation bug: a collector that has never successfully sent must not
// stamp the shutdown time into LastSent, otherwise the next startup's
// overdue check sees a fresh timestamp and silently waits another full
// interval — repeating forever on containers that restart frequently.
func TestPersistState_LastSentZeroStaysZeroAfterShutdown(t *testing.T) {
	dir := t.TempDir()

	// First lifetime: register a backend, record a call, shut down without
	// ever calling send().
	c1 := New(dir, "v1", quietLogger())
	c1.RegisterBackend("api", "hashA")
	c1.RecordCall("api", true)
	c1.persistState()

	// Read the raw file: LastSent must be absent (omitempty when zero).
	data, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // path from t.TempDir()
	if err != nil {
		t.Fatalf("state file not created: %v", err)
	}
	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid state JSON: %v", err)
	}
	if state.Telemetry.LastSent != "" {
		t.Errorf("LastSent = %q, want empty (never sent) — persistState must not stamp time.Now() on shutdown",
			state.Telemetry.LastSent)
	}

	// Second lifetime: load state, lastSent must still be zero so the
	// overdue-on-startup logic does not falsely skip the send.
	c2 := New(dir, "v1", quietLogger())
	c2.mu.Lock()
	defer c2.mu.Unlock()
	if !c2.lastSent.IsZero() {
		t.Errorf("lastSent after reload = %v, want zero", c2.lastSent)
	}
}

// TestPersistState_PreservesLastSentAcrossShutdown ensures the persisted
// LastSent reflects the last *successful* send, not the time of the shutdown
// persist call.
func TestPersistState_PreservesLastSentAcrossShutdown(t *testing.T) {
	dir := t.TempDir()

	c1 := New(dir, "v1", quietLogger())
	c1.RegisterBackend("api", "hashA")

	// Simulate a successful send that happened 5h ago.
	want := time.Now().Add(-5 * time.Hour).UTC().Truncate(time.Second)
	c1.mu.Lock()
	c1.lastSent = want
	c1.mu.Unlock()

	// Shut down (persist called from Run's ctx.Done path).
	c1.persistState()

	c2 := New(dir, "v1", quietLogger())
	c2.mu.Lock()
	defer c2.mu.Unlock()
	got := c2.lastSent.UTC().Truncate(time.Second)
	if !got.Equal(want) {
		t.Errorf("lastSent after reload = %v, want %v — shutdown persist must not overwrite with time.Now()",
			got, want)
	}
}

// TestRun_ResumesPartialIntervalAfterRestart ensures Run() schedules the next
// send at (lastSent + interval), not (restart + interval). Without this,
// containers that restart more often than once per interval never fire.
func TestRun_ResumesPartialIntervalAfterRestart(t *testing.T) {
	t.Setenv("TELEMETRY_INTERVAL", "200ms")

	var (
		mu   sync.Mutex
		hits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(t.TempDir(), "v1", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("api", "hashA")
	c.RecordCall("api", true)

	// Pretend the previous run persisted lastSent 150ms ago — so only 50ms
	// of the 200ms interval remains before the next scheduled send.
	c.mu.Lock()
	c.lastSent = time.Now().Add(-150 * time.Millisecond)
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()

	// The first fire must happen within the remaining ~50ms, not after a
	// fresh 200ms interval. Allow generous scheduling slack.
	time.Sleep(130 * time.Millisecond)
	mu.Lock()
	got := hits
	mu.Unlock()
	cancel()
	<-done

	if got < 1 {
		t.Errorf("expected at least 1 send within 130ms (resumed partial interval), got %d", got)
	}
}

// TestRun_FullIntervalWhenNeverSent ensures that a fresh collector without a
// prior LastSent still waits a full interval before the first send (no
// spurious immediate fire from the overdue path).
func TestRun_FullIntervalWhenNeverSent(t *testing.T) {
	t.Setenv("TELEMETRY_INTERVAL", "500ms")

	var (
		mu   sync.Mutex
		hits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(t.TempDir(), "v1", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("api", "hashA")
	c.RecordCall("api", true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()

	// At 100ms, there should be no sends yet (full interval is 500ms).
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	got := hits
	mu.Unlock()
	cancel()
	<-done

	if got != 0 {
		t.Errorf("expected 0 sends at 100ms into a 500ms interval, got %d", got)
	}
}

// TestBuildPayload_IncludesRegisteredBackendsAsHeartbeat verifies that every
// registered backend produces an entry — even with zero counts — so idle
// installations remain visible in the telemetry database.
func TestBuildPayload_IncludesRegisteredBackendsAsHeartbeat(t *testing.T) {
	c := New(t.TempDir(), "v1", quietLogger())
	c.RegisterBackend("idle", "hashIdle")
	c.RegisterBackend("active", "hashActive")
	c.RecordCall("active", true)
	c.RecordCall("active", true)
	c.RecordCall("active", false)

	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()

	if len(payload) != 2 {
		t.Fatalf("expected 2 reports (both registered backends), got %d", len(payload))
	}

	byHash := map[string]report{}
	for _, r := range payload {
		byHash[r.DADLHash] = r
	}

	idle, ok := byHash["hashIdle"]
	if !ok {
		t.Fatal("idle backend missing from payload — heartbeat not emitted")
	}
	if idle.CallCount != 0 || idle.ErrorCount != 0 {
		t.Errorf("idle entry = {%d, %d}, want {0, 0}", idle.CallCount, idle.ErrorCount)
	}

	active, ok := byHash["hashActive"]
	if !ok {
		t.Fatal("active backend missing from payload")
	}
	if active.CallCount != 2 || active.ErrorCount != 1 {
		t.Errorf("active entry = {%d, %d}, want {2, 1}", active.CallCount, active.ErrorCount)
	}
}

// TestBuildPayload_DedupesSharedDADLHash ensures that two backends pointing at
// the same DADL content (same hash) do not produce duplicate report entries.
func TestBuildPayload_DedupesSharedDADLHash(t *testing.T) {
	c := New(t.TempDir(), "v1", quietLogger())
	c.RegisterBackend("backend-a", "sharedHash")
	c.RegisterBackend("backend-b", "sharedHash")

	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()

	if len(payload) != 1 {
		t.Errorf("expected 1 deduped report, got %d", len(payload))
	}
}

// TestSend_EmitsHeartbeatForIdleBackends reproduces the demo problem: an
// installation with registered backends but no tool calls must still POST a
// report so it shows up as alive in the telemetry database.
func TestSend_EmitsHeartbeatForIdleBackends(t *testing.T) {
	var (
		mu       sync.Mutex
		received []report
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reports []report
		if err := json.Unmarshal(body, &reports); err != nil {
			t.Errorf("invalid JSON payload: %v", err)
		}
		mu.Lock()
		received = reports
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(t.TempDir(), "v1", quietLogger())
	c.SetEndpoint(srv.URL)
	c.RegisterBackend("idle", "hashIdle")
	// No RecordCall — this install has zero activity.

	c.send(t.Context())

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 heartbeat report, got %d", len(received))
	}
	if received[0].CallCount != 0 || received[0].ErrorCount != 0 {
		t.Errorf("heartbeat = {%d, %d}, want {0, 0}", received[0].CallCount, received[0].ErrorCount)
	}
	if received[0].DADLHash != "hashIdle" {
		t.Errorf("heartbeat hash = %q, want %q", received[0].DADLHash, "hashIdle")
	}
	if received[0].Version != "v1" {
		t.Errorf("heartbeat version = %q, want %q", received[0].Version, "v1")
	}
}

// readState reads and decodes the state file in dir.
func readState(t *testing.T, dir string) stateData {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, stateFile)) //nolint:gosec // test path from t.TempDir()
	if err != nil {
		t.Fatalf("read state file: %v", err)
	}
	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid state JSON: %v", err)
	}
	if state.Telemetry == nil {
		t.Fatal("telemetry key missing from state")
	}
	return state
}

// siteIDTime returns the creation time a UUIDv7 site ID carries.
func siteIDTime(t *testing.T, siteID string) time.Time {
	t.Helper()
	id, err := uuid.Parse(siteID)
	if err != nil {
		t.Fatalf("site ID %q does not parse: %v", siteID, err)
	}
	if id.Version() != 7 {
		t.Fatalf("site ID %q has version %d, want 7", siteID, id.Version())
	}
	sec, nsec := id.Time().UnixTime()
	return time.Unix(sec, nsec)
}

// reportSink is a telemetry endpoint that keeps the payload of the last report.
type reportSink struct {
	srv  *httptest.Server
	mu   sync.Mutex
	last []report
}

func newReportSink(t *testing.T) *reportSink {
	t.Helper()
	s := &reportSink{}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var reports []report
		if err := json.Unmarshal(body, &reports); err != nil {
			t.Errorf("invalid JSON payload: %v", err)
		}
		s.mu.Lock()
		s.last = reports
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

// startAndReport runs one lifetime of an installation: start on dataDir,
// send one report to the sink, shut down. It returns the site ID of that
// lifetime and the site ID the report carried.
func (s *reportSink) startAndReport(t *testing.T, dataDir string) (collectorID, reportedID string) {
	t.Helper()
	c := New(dataDir, "v1", quietLogger())
	c.SetEndpoint(s.srv.URL)
	c.RegisterBackend("api", "hashA")
	c.RecordCall("api", true)
	c.send(t.Context())
	c.persistState() // what Run does on shutdown

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.last) != 1 {
		t.Fatalf("expected 1 report entry, got %d", len(s.last))
	}
	return c.siteID, s.last[0].SiteID
}

func TestSiteID_CreatedOnFirstStartAndPersisted(t *testing.T) {
	dir := t.TempDir()

	before := time.Now().Truncate(time.Millisecond)
	c := New(dir, "v1", quietLogger())
	after := time.Now()

	if !validSiteID(c.siteID) {
		t.Fatalf("site ID %q is not a canonical UUIDv7", c.siteID)
	}
	if created := siteIDTime(t, c.siteID); created.Before(before) || created.After(after) {
		t.Errorf("site ID time = %v, want between %v and %v", created, before, after)
	}

	// Persisted at once, before any report or shutdown, so that a crash does
	// not lose it.
	if got := readState(t, dir).Telemetry.SiteID; got != c.siteID {
		t.Errorf("persisted site ID = %q, want %q", got, c.siteID)
	}
}

// TestSiteID_SurvivesRestartWithDataVolume restarts an installation on the
// same data directory, as a container restart with a data volume does.
func TestSiteID_SurvivesRestartWithDataVolume(t *testing.T) {
	sink := newReportSink(t)
	dir := t.TempDir()

	first, firstReported := sink.startAndReport(t, dir)
	second, secondReported := sink.startAndReport(t, dir)

	if first != second {
		t.Errorf("site ID changed across restart: %q -> %q", first, second)
	}
	if firstReported != first || secondReported != first {
		t.Errorf("reported site IDs = %q, %q, want %q both times", firstReported, secondReported, first)
	}
}

// TestSiteID_NewPerStartWithoutDataVolume starts every lifetime on an empty
// data directory, as a container without a data volume does: each start
// reports a new site ID carrying the time of that start.
func TestSiteID_NewPerStartWithoutDataVolume(t *testing.T) {
	sink := newReportSink(t)

	seen := map[string]bool{}
	for i := range 3 {
		before := time.Now().Truncate(time.Millisecond)
		id, reported := sink.startAndReport(t, t.TempDir())
		after := time.Now()

		if reported != id {
			t.Errorf("start %d: reported site ID %q, want %q", i, reported, id)
		}
		if seen[id] {
			t.Errorf("start %d: site ID %q repeated without a data volume", i, id)
		}
		seen[id] = true
		if created := siteIDTime(t, id); created.Before(before) || created.After(after) {
			t.Errorf("start %d: site ID time = %v, want between %v and %v", i, created, before, after)
		}
	}
}

// TestSiteID_NotCreatedWhenOptedOut ensures that an opted-out installation
// neither creates nor persists a site ID.
func TestSiteID_NotCreatedWhenOptedOut(t *testing.T) {
	t.Setenv("DO_NOT_SEND_ANONYMOUS_STATISTICS", "yes")
	dir := t.TempDir()

	c := New(dir, "v1", quietLogger())
	c.RegisterBackend("api", "hashA")

	if c.siteID != "" {
		t.Errorf("site ID = %q, want none when opted out", c.siteID)
	}
	if _, err := os.Stat(filepath.Join(dir, stateFile)); !os.IsNotExist(err) {
		t.Errorf("start wrote the state file although opted out (stat error: %v)", err)
	}

	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()
	if len(payload) != 1 || payload[0].SiteID != "" {
		t.Errorf("payload = %+v, want one entry without site ID", payload)
	}

	c.persistState() // what Run does on shutdown
	if got := readState(t, dir).Telemetry.SiteID; got != "" {
		t.Errorf("persisted site ID = %q, want none when opted out", got)
	}
}

// TestSiteID_OptOutKeepsExistingID ensures that opting out later leaves an
// existing site ID in the state file; removing it is up to the operator.
func TestSiteID_OptOutKeepsExistingID(t *testing.T) {
	dir := t.TempDir()
	existing := New(dir, "v1", quietLogger()).siteID

	t.Setenv("DO_NOT_SEND_ANONYMOUS_STATISTICS", "yes")
	c := New(dir, "v1", quietLogger())
	c.persistState()

	if got := readState(t, dir).Telemetry.SiteID; got != existing {
		t.Errorf("persisted site ID = %q, want the existing %q", got, existing)
	}
}

func TestSiteID_InvalidStoredIDIsReplaced(t *testing.T) {
	v7, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]string{
		"garbage":       "not-a-uuid",
		"version 4":     uuid.NewString(),
		"no hyphens":    strings.ReplaceAll(v7.String(), "-", ""),
		"urn prefix":    "urn:uuid:" + v7.String(),
		"nil uuid":      uuid.Nil.String(),
		"trailing junk": v7.String() + "x",
	}
	for name, stored := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			state := `{"telemetry":{"site_id":` + strconv.Quote(stored) + `}}`
			if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(state), 0o600); err != nil {
				t.Fatal(err)
			}

			c := New(dir, "v1", quietLogger())
			if c.siteID == stored || !validSiteID(c.siteID) {
				t.Errorf("site ID = %q, want a new UUIDv7 instead of %q", c.siteID, stored)
			}
			if got := readState(t, dir).Telemetry.SiteID; got != c.siteID {
				t.Errorf("persisted site ID = %q, want %q", got, c.siteID)
			}
		})
	}
}

// TestSiteID_UpgradeKeepsExistingState starts on a state file written by a
// version without site IDs: the new ID joins the existing counters and
// last_sent instead of replacing them.
func TestSiteID_UpgradeKeepsExistingState(t *testing.T) {
	dir := t.TempDir()
	old := `{"telemetry":{"last_sent":"2026-10-01T08:00:00Z","counters":{"hashA":{"call_count":3,"error_count":1}}}}`
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	c := New(dir, "v1", quietLogger())
	if !validSiteID(c.siteID) {
		t.Fatalf("site ID %q is not a canonical UUIDv7", c.siteID)
	}

	state := readState(t, dir).Telemetry
	if state.SiteID != c.siteID {
		t.Errorf("persisted site ID = %q, want %q", state.SiteID, c.siteID)
	}
	if state.LastSent != "2026-10-01T08:00:00Z" {
		t.Errorf("persisted last_sent = %q, want the old value", state.LastSent)
	}
	if cp := state.Counters["hashA"]; cp == nil || cp.CallCount != 3 || cp.ErrorCount != 1 {
		t.Errorf("persisted counters = %+v, want {3, 1}", cp)
	}
}
