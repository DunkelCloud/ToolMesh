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

package health

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

// Backend names of the monitor tests.
const (
	testBackendTailscale = "tailscale"
	testBackendGitLab    = "gitlab"
)

// testNow is the fixed clock of the monitor tests.
var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

// fakeChecker returns a passing or failing result and counts its calls.
type fakeChecker struct {
	mu       sync.Mutex
	ok       bool
	calls    int
	expires  time.Time
	observer backend.HealthObserver
}

func (f *fakeChecker) HasHealthCheck() bool { return true }

func (f *fakeChecker) CheckHealth(_ context.Context) backend.HealthResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	res := backend.HealthResult{OK: f.ok, CheckedAt: testNow, AuthExpiresAt: f.expires}
	if !f.ok {
		res.HTTPStatus, res.Reason = 401, "unauthorized (HTTP 401)"
	}
	return res
}

func (f *fakeChecker) SetHealthObserver(o backend.HealthObserver) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.observer = o
}

func (f *fakeChecker) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func newTestMonitor(m *metrics.Registry) *Monitor {
	mon := NewMonitor(slog.New(slog.NewTextHandler(io.Discard, nil)), m)
	mon.now = func() time.Time { return testNow }
	return mon
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func failed(at time.Time) backend.HealthResult {
	return backend.HealthResult{CheckedAt: at, HTTPStatus: 401, Reason: "unauthorized (HTTP 401)"}
}

func passed(at time.Time) backend.HealthResult {
	return backend.HealthResult{OK: true, CheckedAt: at}
}

func TestMonitor_DegradeAfterAndRecovery(t *testing.T) {
	mon := newTestMonitor(nil)
	mon.policies = map[string]Policy{testBackendTailscale: {DegradeAfter: 2, WarnBefore: DefaultWarnBefore}}

	first := testNow.Add(-30 * time.Minute)
	mon.Observe(testBackendTailscale, failed(first))
	if rep := mon.Report(); rep.Status != StatusOK || len(rep.Backends) != 0 {
		t.Fatalf("after one failure with degrade_after 2: %+v, want ok", rep)
	}

	mon.Observe(testBackendTailscale, failed(testNow.Add(-15*time.Minute)))
	rep := mon.Report()
	bs, ok := rep.Backends[testBackendTailscale]
	if rep.Status != StatusDegraded || !ok || bs.Status != StatusDegraded {
		t.Fatalf("after two failures: %+v, want degraded", rep)
	}
	wantReason := "health check failing since 2026-10-30T11:30:00Z (2 consecutive): unauthorized (HTTP 401)"
	if bs.Reason != wantReason || bs.FailingSince != "2026-10-30T11:30:00Z" {
		t.Errorf("entry = %+v, want reason %q", bs, wantReason)
	}

	mon.Observe(testBackendTailscale, passed(testNow))
	if rep := mon.Report(); rep.Status != StatusOK || rep.Backends != nil {
		t.Errorf("after a pass: %+v, want ok without entries", rep)
	}

	mon.Observe("not-watched", failed(testNow))
	if rep := mon.Report(); rep.Status != StatusOK {
		t.Errorf("a result for an unwatched backend changed the report: %+v", rep)
	}
}

func TestMonitor_ExpiryWarning(t *testing.T) {
	tests := []struct {
		name       string
		expires    time.Time
		ok         bool
		wantStatus string
		wantReason string
	}{
		{name: "far away", expires: testNow.Add(30 * 24 * time.Hour), ok: true, wantStatus: StatusOK},
		{name: "inside the window", expires: testNow.Add(3 * 24 * time.Hour), ok: true, wantStatus: StatusWarning,
			wantReason: "credential expires at 2026-11-02T12:00:00Z"},
		{name: "already past", expires: testNow.Add(-time.Hour), ok: true, wantStatus: StatusWarning,
			wantReason: "credential expired at 2026-10-30T11:00:00Z"},
		{name: "unknown", ok: true, wantStatus: StatusOK},
		{name: "degraded outranks the warning", expires: testNow.Add(time.Hour), wantStatus: StatusDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mon := newTestMonitor(nil)
			mon.policies = map[string]Policy{testBackendGitLab: {DegradeAfter: 1, WarnBefore: DefaultWarnBefore}}
			res := passed(testNow)
			if !tt.ok {
				res = failed(testNow)
			}
			res.AuthExpiresAt = tt.expires
			mon.Observe(testBackendGitLab, res)

			rep := mon.Report()
			if rep.Status != tt.wantStatus {
				t.Fatalf("status = %q, want %q (%+v)", rep.Status, tt.wantStatus, rep)
			}
			if tt.wantReason != "" && rep.Backends[testBackendGitLab].Reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", rep.Backends[testBackendGitLab].Reason, tt.wantReason)
			}
		})
	}
}

// The warning window opens with the passage of time alone: the report is
// evaluated against the clock, not only when a check runs.
func TestMonitor_WarningWithoutNewCheck(t *testing.T) {
	mon := newTestMonitor(nil)
	mon.policies = map[string]Policy{testBackendGitLab: {DegradeAfter: 1, WarnBefore: 7 * 24 * time.Hour}}
	res := passed(testNow)
	res.AuthExpiresAt = testNow.Add(10 * 24 * time.Hour)
	mon.Observe(testBackendGitLab, res)
	if got := mon.Report().Status; got != StatusOK {
		t.Fatalf("status = %q, want ok ten days before expiry", got)
	}
	mon.now = func() time.Time { return testNow.Add(4 * 24 * time.Hour) }
	if got := mon.Report().Status; got != StatusWarning {
		t.Errorf("status = %q, want warning six days before expiry", got)
	}
}

func TestMonitor_ReportJSON(t *testing.T) {
	var nilMon *Monitor
	got, _ := json.Marshal(nilMon.Report())
	if string(got) != `{"status":"ok"}` {
		t.Errorf("nil monitor report = %s, want the plain ok", got)
	}

	mon := newTestMonitor(nil)
	mon.policies = map[string]Policy{testBackendTailscale: {}}
	mon.Observe(testBackendTailscale, failed(testNow))
	got, _ = json.Marshal(mon.Report())
	want := `{"status":"degraded","backends":{"tailscale":{"status":"degraded","reason":"health check failing since 2026-10-30T12:00:00Z (1 consecutive): unauthorized (HTTP 401)","checked_at":"2026-10-30T12:00:00Z","failing_since":"2026-10-30T12:00:00Z"}}}`
	if string(got) != want {
		t.Errorf("report = %s\nwant     %s", got, want)
	}
}

func TestMonitor_ReplaceChecksPollsAndObserves(t *testing.T) {
	reg := metrics.New(metrics.Options{})
	mon := newTestMonitor(reg)
	defer mon.Stop()

	once := &fakeChecker{ok: false, expires: testNow.Add(24 * time.Hour)}
	polled := &fakeChecker{ok: true}
	mon.Replace(context.Background(), []Target{
		{Name: testBackendTailscale, Checker: once, Policy: Policy{DegradeAfter: 1, WarnBefore: DefaultWarnBefore}},
		{Name: testBackendGitLab, Checker: polled, Policy: Policy{Interval: 10 * time.Millisecond, DegradeAfter: 1}},
	})

	waitFor(t, "the startup check", func() bool { return mon.Report().Status == StatusDegraded })
	waitFor(t, "polling", func() bool { return polled.callCount() >= 3 })
	if n := once.callCount(); n != 1 {
		t.Errorf("unpolled backend checked %d times, want once", n)
	}

	if v := metricsGauge(t, reg, "toolmesh_backend_health_up", testBackendTailscale); v != 0 {
		t.Errorf("health_up{tailscale} = %v, want 0", v)
	}
	if v := metricsGauge(t, reg, "toolmesh_backend_health_degraded", testBackendTailscale); v != 1 {
		t.Errorf("health_degraded{tailscale} = %v, want 1", v)
	}
	if v := metricsGauge(t, reg, "toolmesh_backend_auth_expiry_timestamp_seconds", testBackendTailscale); v != float64(testNow.Add(24*time.Hour).Unix()) {
		t.Errorf("auth_expiry{tailscale} = %v", v)
	}

	// An on-demand check through the synthetic tool reaches the monitor via
	// the observer Replace installed.
	once.mu.Lock()
	observe := once.observer
	once.mu.Unlock()
	if observe == nil {
		t.Fatal("Replace installed no observer")
	}
	onDemand := passed(testNow)
	onDemand.AuthExpiresAt = testNow.Add(24 * time.Hour)
	observe(testBackendTailscale, onDemand)
	if got := mon.Report().Status; got != StatusWarning {
		t.Errorf("after an on-demand pass: %q, want the expiry warning left", got)
	}

	// A reload that drops tailscale stops its series and its report entry;
	// gitlab keeps being polled by the new generation only.
	mon.Replace(context.Background(), []Target{
		{Name: testBackendGitLab, Checker: polled, Policy: Policy{Interval: 10 * time.Millisecond, DegradeAfter: 1}},
	})
	if rep := mon.Report(); rep.Status != StatusOK || rep.Backends != nil {
		t.Errorf("after dropping tailscale: %+v, want ok", rep)
	}
	if n := seriesCount(t, reg, "toolmesh_backend_health_up"); n != 1 {
		t.Errorf("health_up series = %d, want only gitlab's", n)
	}

	mon.Stop()
	time.Sleep(30 * time.Millisecond)
	after := polled.callCount()
	time.Sleep(50 * time.Millisecond)
	if polled.callCount() != after {
		t.Error("polling continued after Stop")
	}
}

// A reload keeps the failure streak of a backend that stays.
func TestMonitor_ReplaceKeepsState(t *testing.T) {
	mon := newTestMonitor(nil)
	defer mon.Stop()
	mon.policies = map[string]Policy{testBackendTailscale: {DegradeAfter: 2}}
	mon.Observe(testBackendTailscale, failed(testNow.Add(-time.Hour)))

	checker := &fakeChecker{ok: false}
	mon.Replace(context.Background(), []Target{{Name: testBackendTailscale, Checker: checker, Policy: Policy{DegradeAfter: 2}}})
	waitFor(t, "the post-reload check", func() bool { return checker.callCount() == 1 })
	waitFor(t, "the degraded state", func() bool { return mon.Report().Status == StatusDegraded })
	if r := mon.Report().Backends[testBackendTailscale].Reason; !strings.Contains(r, "since 2026-10-30T11:00:00Z (2 consecutive)") {
		t.Errorf("reason = %q, want the streak carried over the reload", r)
	}
}

// seriesCount returns how many series of a metric family the registry holds.
func seriesCount(t *testing.T, reg *metrics.Registry, name string) int {
	t.Helper()
	families, err := reg.PrometheusRegistry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() == name {
			return len(f.GetMetric())
		}
	}
	return 0
}

// metricsGauge reads the value of one labeled gauge series.
func metricsGauge(t *testing.T, reg *metrics.Registry, name, backendName string) float64 {
	t.Helper()
	families, err := reg.PrometheusRegistry().Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "backend" && l.GetValue() == backendName {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	t.Fatalf("series %s{backend=%q} not found", name, backendName)
	return 0
}
