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
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// testStartDelay stands in for the random delay of a report that is due at
// start. No other scheduling rule yields this value by accident.
const testStartDelay = 3*time.Minute + 7*time.Second

// scheduleHarness drives Run without waiting. It fixes the clock and the
// random start delay of a collector and hands every timer Run asks for to the
// test, which fires it by hand.
type scheduleHarness struct {
	mu     sync.Mutex
	now    time.Time
	timers chan fakeTimer
}

// fakeTimer is one timer Run asked for.
type fakeTimer struct {
	delay time.Duration
	fire  chan time.Time
}

func newScheduleHarness(now time.Time) *scheduleHarness {
	return &scheduleHarness{now: now, timers: make(chan fakeTimer, 8)}
}

func (h *scheduleHarness) clock() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.now
}

func (h *scheduleHarness) set(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.now = now
}

// install makes c use the clock, the start delay and the timers of h.
func (h *scheduleHarness) install(c *Collector) {
	c.now = h.clock
	c.startDelay = func() time.Duration { return testStartDelay }
	c.after = func(d time.Duration) <-chan time.Time {
		ft := fakeTimer{delay: d, fire: make(chan time.Time, 1)}
		h.timers <- ft
		return ft.fire
	}
}

// nextTimer waits until Run asks for its next timer.
func (h *scheduleHarness) nextTimer(t *testing.T) fakeTimer {
	t.Helper()
	select {
	case ft := <-h.timers:
		return ft
	case <-time.After(5 * time.Second):
		t.Fatal("Run scheduled no report")
	}
	return fakeTimer{}
}

// fire advances the clock to the end of ft, lets ft go off and returns the
// time it went off.
func (h *scheduleHarness) fire(ft fakeTimer) time.Time {
	h.mu.Lock()
	h.now = h.now.Add(ft.delay)
	now := h.now
	h.mu.Unlock()
	ft.fire <- now
	return now
}

// startRun runs c in the background. The returned stop cancels Run and
// waits until it has returned; it also runs when the test ends.
func startRun(t *testing.T, c *Collector) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx)
	}()
	stop = func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return stop
}

// TestRun_FirstReportAfterStart shows when a freshly started installation
// sends its first report, depending on the state file it starts with: a
// report that is due goes out after the start delay, any other at the last
// report plus one interval.
func TestRun_FirstReportAfterStart(t *testing.T) {
	start := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	siteID := uuid.Must(uuid.NewV7()).String()
	stateWith := func(lastSent time.Time) string {
		return `{"telemetry":{"site_id":"` + siteID + `","last_sent":"` + lastSent.Format(time.RFC3339) + `"}}`
	}

	tests := []struct {
		name      string
		state     string        // toolmesh.json at start; empty: no file
		interval  time.Duration // zero: the default interval
		optOut    bool
		wantFirst time.Duration // delay of the first report after start
	}{
		{name: "no state file", wantFirst: testStartDelay},
		{name: "last report 2h ago", state: stateWith(start.Add(-2 * time.Hour)), wantFirst: 22 * time.Hour},
		{name: "last report 30h ago", state: stateWith(start.Add(-30 * time.Hour)), wantFirst: testStartDelay},
		{name: "last report one interval ago", state: stateWith(start.Add(-sendInterval)), wantFirst: testStartDelay},
		{name: "last report in the future", state: stateWith(start.Add(time.Hour)), wantFirst: testStartDelay},
		{
			name:      "state file without last_sent",
			state:     `{"telemetry":{"site_id":"` + siteID + `","counters":{"hashA":{"call_count":3,"error_count":1}}}}`,
			wantFirst: testStartDelay,
		},
		{name: "interval shorter than the start delay", interval: 30 * time.Second, wantFirst: 30 * time.Second},
		{name: "opted out", optOut: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.optOut {
				t.Setenv("DO_NOT_SEND_ANONYMOUS_STATISTICS", "yes")
			}
			dir := t.TempDir()
			if tt.state != "" {
				if err := os.WriteFile(filepath.Join(dir, stateFile), []byte(tt.state), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			interval := sendInterval
			if tt.interval > 0 {
				interval = tt.interval
			}

			sink := newBatchCollector(t, 0)
			h := newScheduleHarness(start)
			c := New(dir, "v1", quietLogger())
			c.SetEndpoint(sink.srv.URL)
			c.interval = interval
			h.install(c)
			c.RegisterBackend("api", "hashA")
			wantSiteID := c.siteID
			if tt.state != "" && wantSiteID != siteID {
				t.Errorf("site ID %q after loading the state file, want %q", wantSiteID, siteID)
			}

			stop := startRun(t, c)

			if tt.optOut {
				stop()
				if n := len(h.timers); n != 0 {
					t.Errorf("Run scheduled %d reports although opted out", n)
				}
				if n := sink.count(); n != 0 {
					t.Errorf("%d requests to the endpoint although opted out", n)
				}
				return
			}

			first := h.nextTimer(t)
			if first.delay != tt.wantFirst {
				t.Errorf("first report %v after start, want %v", first.delay, tt.wantFirst)
			}
			if n := sink.count(); n != 0 {
				t.Errorf("%d reports right at start, want none before the first timer", n)
			}

			sentAt := h.fire(first)
			next := h.nextTimer(t)
			stop()

			if n := sink.count(); n != 1 {
				t.Fatalf("%d reports after the first timer, want 1", n)
			}
			if next.delay != interval {
				t.Errorf("report after the first one scheduled %v later, want %v", next.delay, interval)
			}
			state := readState(t, dir).Telemetry
			if want := sentAt.Format(time.RFC3339); state.LastSent != want {
				t.Errorf("persisted last_sent = %q, want %q", state.LastSent, want)
			}
			if state.SiteID != wantSiteID {
				t.Errorf("persisted site ID = %q, want %q", state.SiteID, wantSiteID)
			}
		})
	}
}

// TestRun_RestartLoopKeepsSchedule restarts an installation every ten minutes
// for a day on the same data directory, as a crash loop or frequent updates
// do. It reports shortly after its first start and once more one interval
// later, not once per restart, and keeps its site ID throughout.
func TestRun_RestartLoopKeepsSchedule(t *testing.T) {
	start := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	const lifetime = 10 * time.Minute
	sink := newBatchCollector(t, 0)
	dir := t.TempDir()
	h := newScheduleHarness(start)

	var (
		siteID  string
		reports []string
	)
	for i := range 24*6 + 1 {
		begin := start.Add(time.Duration(i) * lifetime)
		h.set(begin)
		c := New(dir, "v1", quietLogger())
		c.SetEndpoint(sink.srv.URL)
		h.install(c)
		c.RegisterBackend("api", "hashA")
		if i == 0 {
			siteID = c.siteID
		} else if c.siteID != siteID {
			t.Fatalf("start %d: site ID %q, want %q", i, c.siteID, siteID)
		}

		stop := startRun(t, c)
		for ft := h.nextTimer(t); h.clock().Add(ft.delay).Before(begin.Add(lifetime)); ft = h.nextTimer(t) {
			reports = append(reports, h.fire(ft).Format(time.RFC3339))
		}
		stop()
	}

	want := []string{
		start.Add(testStartDelay).Format(time.RFC3339),
		start.Add(sendInterval + testStartDelay).Format(time.RFC3339),
	}
	if !slices.Equal(reports, want) {
		t.Errorf("reports at %v over %d restarts, want %v", reports, 24*6, want)
	}
	if n := sink.count(); n != len(want) {
		t.Errorf("endpoint received %d requests, want %d", n, len(want))
	}
}

// TestRun_UnwritableDataDir starts on a data directory that cannot be
// written. The start goes through, the report goes out after the start
// delay, its time is kept in memory for the next one, and the failed write
// is logged as a warning that names the changing site ID.
func TestRun_UnwritableDataDir(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocker, "data") // below a regular file: never writable

	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	start := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	sink := newBatchCollector(t, 0)
	h := newScheduleHarness(start)
	c := New(dir, "v1", logger)
	c.SetEndpoint(sink.srv.URL)
	h.install(c)
	c.RegisterBackend("api", "hashA")

	stop := startRun(t, c)
	first := h.nextTimer(t)
	sentAt := h.fire(first)
	next := h.nextTimer(t)
	stop()

	if first.delay != testStartDelay {
		t.Errorf("first report %v after start, want %v", first.delay, testStartDelay)
	}
	if n := sink.count(); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
	if next.delay != sendInterval {
		t.Errorf("next report scheduled %v later, want %v", next.delay, sendInterval)
	}
	c.mu.Lock()
	lastSent := c.lastSent
	c.mu.Unlock()
	if !lastSent.Equal(sentAt) {
		t.Errorf("last report in memory = %v, want %v", lastSent, sentAt)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "site ID changes on every restart") {
		t.Errorf("no warning about the changing site ID for an unwritable data directory:\n%s", logs.String())
	}
}

func TestRandomStartDelay_WithinBounds(t *testing.T) {
	for range 1000 {
		if d := randomStartDelay(); d < startDelayMin || d >= startDelayMax {
			t.Fatalf("random start delay %v, want within [%v, %v)", d, startDelayMin, startDelayMax)
		}
	}
}
