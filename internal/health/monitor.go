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
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

// Status values of a backend and of the aggregate report.
const (
	StatusOK       = "ok"
	StatusWarning  = "warning"
	StatusDegraded = "degraded"
)

// maxConcurrentChecks bounds how many checks run at once, so a startup or
// reload with many backends does not fire every check in the same instant.
const maxConcurrentChecks = 8

// Target is one backend the monitor watches.
type Target struct {
	// Name is the backend's configured name.
	Name string
	// Checker runs the backend's check.
	Checker backend.HealthChecker
	// Policy drives polling and the degraded / warning states.
	Policy Policy
}

// observable is implemented by checkers that also run checks on demand
// (the synthetic health tool) and can report those results.
type observable interface {
	SetHealthObserver(o backend.HealthObserver)
}

// Monitor runs backend health checks and keeps the state the aggregate
// report is built from. Every check result counts — startup, polling and
// on-demand calls of the health tool alike. The zero value is not usable;
// create one with NewMonitor.
type Monitor struct {
	logger  *slog.Logger
	metrics *metrics.Registry
	now     func() time.Time
	sem     chan struct{}

	mu       sync.Mutex
	cancel   context.CancelFunc
	policies map[string]Policy
	states   map[string]*state
}

// state is what the monitor remembers about one backend.
type state struct {
	last          backend.HealthResult
	failures      int       // consecutive failed checks
	failingSince  time.Time // start of the current failure streak
	authExpiresAt time.Time // from the latest result; zero = unknown
	status        string    // status after the latest result, for transition logs
}

// NewMonitor creates a monitor. The metrics registry is optional; nil
// records nothing.
func NewMonitor(logger *slog.Logger, m *metrics.Registry) *Monitor {
	return &Monitor{
		logger:   logger,
		metrics:  m,
		now:      time.Now,
		sem:      make(chan struct{}, maxConcurrentChecks),
		policies: map[string]Policy{},
		states:   map[string]*state{},
	}
}

// Replace makes targets the watched set: checks of the previous set stop,
// state of backends that are gone is dropped, and every target is checked
// right away and then polled per its policy. State of a backend that stays
// is kept, so a reload does not reset a failure streak. Call it at startup
// and after every backends.yaml reload.
func (m *Monitor) Replace(ctx context.Context, targets []Target) {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	runCtx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	policies := make(map[string]Policy, len(targets))
	for _, t := range targets {
		policies[t.Name] = t.Policy
	}
	for name := range m.states {
		if _, keep := policies[name]; !keep {
			delete(m.states, name)
			m.metrics.DeleteBackendHealth(name)
		}
	}
	m.policies = policies
	m.mu.Unlock()

	for _, t := range targets {
		if o, ok := t.Checker.(observable); ok {
			o.SetHealthObserver(m.Observe)
		}
		go m.run(runCtx, t)
	}
}

// Stop ends all checks.
func (m *Monitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

// run checks a target once, then on every polling tick until ctx ends.
func (m *Monitor) run(ctx context.Context, t Target) {
	m.check(ctx, t)
	if t.Policy.Interval <= 0 {
		return
	}
	ticker := time.NewTicker(t.Policy.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.check(ctx, t)
		}
	}
}

// check runs one check within the concurrency bound and records it. A check
// cut short because its generation was replaced is not recorded: its
// failure would describe the cancellation, not the backend.
func (m *Monitor) check(ctx context.Context, t Target) {
	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		return
	}
	res := t.Checker.CheckHealth(ctx)
	<-m.sem
	if ctx.Err() != nil {
		return
	}
	m.Observe(t.Name, res)
}

// Observe records a check result for a watched backend; results for other
// names are ignored. It is the HealthObserver installed on every target.
func (m *Monitor) Observe(name string, res backend.HealthResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	policy, ok := m.policies[name]
	if !ok {
		return
	}
	st, ok := m.states[name]
	if !ok {
		st = &state{status: StatusOK}
		m.states[name] = st
	}
	st.last = res
	st.authExpiresAt = res.AuthExpiresAt
	if res.OK {
		st.failures = 0
		st.failingSince = time.Time{}
	} else {
		if st.failures == 0 {
			st.failingSince = res.CheckedAt
		}
		st.failures++
	}

	cur := evaluate(st, policy, m.now())
	m.logResult(name, st, policy, cur.Status, res)
	st.status = cur.Status
	m.metrics.SetBackendHealth(name, res.OK, cur.Status == StatusDegraded)
	m.metrics.SetBackendAuthExpiry(name, st.authExpiresAt)
}

// logResult logs a check result: transitions into and out of degraded and
// warning at warn/info, a failure below the degrade threshold at info, a
// pass at debug.
func (m *Monitor) logResult(name string, st *state, policy Policy, status string, res backend.HealthResult) {
	switch {
	case status == StatusDegraded && st.status != StatusDegraded:
		m.logger.Warn("backend health check failing",
			"backend", name, "since", st.failingSince.Format(time.RFC3339),
			"failures", st.failures, "reason", res.Reason)
	case status != StatusDegraded && st.status == StatusDegraded:
		m.logger.Info("backend health check recovered", "backend", name, "latency_ms", res.Latency.Milliseconds())
	case !res.OK:
		m.logger.Info("backend health check failed",
			"backend", name, "failures", st.failures, "degrade_after", policy.degradeAfter(), "reason", res.Reason)
	default:
		m.logger.Debug("backend health check passed", "backend", name, "latency_ms", res.Latency.Milliseconds())
	}
	if status == StatusWarning && st.status != StatusWarning {
		m.logger.Warn("backend credential expires soon",
			"backend", name, "auth_expires_at", st.authExpiresAt.Format(time.RFC3339))
	}
}

// Report is the aggregate backend health ToolMesh's /health endpoint
// returns. Backends is limited to those not ok, so an all-clear report is
// exactly {"status":"ok"}.
type Report struct {
	// Status is degraded when any backend is degraded, warning when any
	// has a warning, ok otherwise.
	Status string `json:"status"`
	// Backends lists the backends with a warning or degraded, by name.
	Backends map[string]BackendStatus `json:"backends,omitempty"`
}

// BackendStatus is one backend's entry in a Report. It carries no response
// content: the endpoint it is served on is unauthenticated.
type BackendStatus struct {
	Status        string `json:"status"`
	Reason        string `json:"reason"`
	CheckedAt     string `json:"checked_at"`
	FailingSince  string `json:"failing_since,omitempty"`
	AuthExpiresAt string `json:"auth_expires_at,omitempty"`
}

// Report builds the aggregate status from the latest results. The warning
// window is evaluated against the current time, so a backend enters it
// without a new check. A nil monitor reports ok.
func (m *Monitor) Report() Report {
	rep := Report{Status: StatusOK}
	if m == nil {
		return rep
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for name, st := range m.states {
		bs := evaluate(st, m.policies[name], now)
		if bs.Status == StatusOK {
			continue
		}
		if rep.Backends == nil {
			rep.Backends = map[string]BackendStatus{}
		}
		rep.Backends[name] = bs
		if bs.Status == StatusDegraded || rep.Status == StatusOK {
			rep.Status = bs.Status
		}
	}
	return rep
}

// evaluate derives a backend's status from its state at time now.
func evaluate(st *state, policy Policy, now time.Time) BackendStatus {
	bs := BackendStatus{
		Status:    StatusOK,
		CheckedAt: st.last.CheckedAt.UTC().Format(time.RFC3339),
	}
	if !st.authExpiresAt.IsZero() {
		bs.AuthExpiresAt = st.authExpiresAt.UTC().Format(time.RFC3339)
	}
	switch {
	case st.failures >= policy.degradeAfter():
		bs.Status = StatusDegraded
		bs.FailingSince = st.failingSince.UTC().Format(time.RFC3339)
		bs.Reason = fmt.Sprintf("health check failing since %s (%d consecutive): %s",
			bs.FailingSince, st.failures, st.last.Reason)
	case !st.authExpiresAt.IsZero() && !now.Before(st.authExpiresAt.Add(-policy.WarnBefore)):
		bs.Status = StatusWarning
		verb := "expires"
		if !now.Before(st.authExpiresAt) {
			verb = "expired"
		}
		bs.Reason = fmt.Sprintf("credential %s at %s", verb, bs.AuthExpiresAt)
		if st.failures > 0 {
			bs.Reason += "; last check failed: " + st.last.Reason
		}
	}
	return bs
}
