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

// Package telemetry implements opt-out usage telemetry for ToolMesh.
// It collects aggregated DADL usage statistics (call counts, error counts per
// content-hashed DADL file) and reports them to a central endpoint every 24 hours.
// A report that is due when ToolMesh starts, because none succeeded yet or
// the last one is older than 24 hours, goes out a few minutes after the start.
// Every report carries the installation's site ID: a random UUIDv7 created on
// the first start with telemetry enabled and kept in the state file, so that
// reports can be counted per installation instead of per source IP.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	endpoint     = "https://tmc.dunkel.cloud/v1/telemetry"
	sendInterval = 24 * time.Hour
	httpTimeout  = 10 * time.Second
	stateFile    = "toolmesh.json"

	// maxBatchEntries is the largest number of report entries the collector
	// accepts in one request. Larger reports go out in several requests.
	maxBatchEntries = 50

	// startDelayMin and startDelayMax bound the random delay of a report that
	// is due when ToolMesh starts. The delay lets the start settle; its random
	// part keeps installations that restart together, such as after an
	// update, from reporting at the same moment.
	startDelayMin = 1 * time.Minute
	startDelayMax = 5 * time.Minute
)

// counterPair tracks calls and errors for a single DADL backend.
type counterPair struct {
	CallCount  int `json:"call_count"`
	ErrorCount int `json:"error_count"`
}

// stateData is the JSON structure persisted in the state file.
type stateData struct {
	Telemetry *telemetryState `json:"telemetry,omitempty"`
}

type telemetryState struct {
	SiteID   string                  `json:"site_id,omitempty"`
	LastSent string                  `json:"last_sent,omitempty"`
	Counters map[string]*counterPair `json:"counters,omitempty"`
}

// report is a single entry in the telemetry payload.
type report struct {
	SiteID         string `json:"site_id,omitempty"`
	DADLHash       string `json:"dadl_hash"`
	CallCount      int    `json:"call_count"`
	ErrorCount     int    `json:"error_count"`
	Version        string `json:"version"`
	MCPServerCount int    `json:"mcp_server_count,omitempty"`
}

// Collector accumulates tool call statistics and periodically sends them.
type Collector struct {
	mu       sync.Mutex
	counters map[string]*counterPair // dadlHash → counts
	backends map[string]string       // backendName → dadlHash
	lastSent time.Time               // last successful send (from state file)
	siteID   string                  // random UUIDv7 of this installation (from state file)

	mcpServerCount int

	dataDir  string
	version  string
	interval time.Duration
	disabled bool
	logger   *slog.Logger
	client   *http.Client

	// The clock, the random delay of a report that is due at start and the
	// timer of the send loop; tests replace them to drive Run without waiting.
	now        func() time.Time
	startDelay func() time.Duration
	after      func(time.Duration) <-chan time.Time
}

// New creates a Collector. If DO_NOT_SEND_ANONYMOUS_STATISTICS=yes, sending
// is disabled but counters are still accumulated (persisted for re-enablement)
// and no site ID is created. Otherwise New makes sure the installation has a
// site ID and persists a newly created one right away.
func New(dataDir, version string, logger *slog.Logger) *Collector {
	disabled := strings.EqualFold(os.Getenv("DO_NOT_SEND_ANONYMOUS_STATISTICS"), "yes")

	interval := sendInterval
	if raw := os.Getenv("TELEMETRY_INTERVAL"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			interval = d
			logger.Info("telemetry: interval override", "interval", d)
		}
	}

	c := &Collector{
		counters: make(map[string]*counterPair),
		backends: make(map[string]string),
		dataDir:  dataDir,
		version:  version,
		interval: interval,
		disabled: disabled,
		logger:   logger,
		client:   &http.Client{Timeout: httpTimeout},

		now:        time.Now,
		startDelay: randomStartDelay,
		after:      time.After,
	}

	if disabled {
		logger.Warn("anonymous telemetry is disabled — set DO_NOT_SEND_ANONYMOUS_STATISTICS= to re-enable; see https://www.toolmesh.io/en/configuration/#telemetry for details")
	}

	c.loadState()
	if !disabled {
		c.ensureSiteID()
	}
	return c
}

// ensureSiteID creates and persists a site ID if the state file did not
// provide a valid one. Without a writable data directory the ID lives only as
// long as the process, so every start reports as a new installation.
func (c *Collector) ensureSiteID() {
	c.mu.Lock()
	if c.siteID != "" {
		c.mu.Unlock()
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		c.mu.Unlock()
		c.logger.Warn("telemetry: failed to create site ID, reports go without one", "error", err)
		return
	}
	c.siteID = id.String()
	c.mu.Unlock()

	c.persistState()
	c.logger.Info("telemetry: created site ID",
		"siteID", id.String(),
		"stateFile", filepath.Join(c.dataDir, stateFile),
	)
}

// randomStartDelay returns a random delay between startDelayMin (inclusive)
// and startDelayMax (exclusive).
func randomStartDelay() time.Duration {
	return startDelayMin + rand.N(startDelayMax-startDelayMin) //nolint:gosec // G404: spreads reports over time, nothing secret depends on it
}

// validSiteID reports whether s is a UUIDv7 in canonical form.
func validSiteID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && len(s) == 36 && id.Version() == 7 && id.Variant() == uuid.RFC4122
}

// SetMCPServerCount records the number of configured MCP server backends.
// This count is included in every telemetry report entry.
func (c *Collector) SetMCPServerCount(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mcpServerCount = n
}

// RegisterBackend maps a backend name to its DADL content hash so that
// RecordCall can accept a backend name instead of requiring the hash.
func (c *Collector) RegisterBackend(backendName, dadlHash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backends[backendName] = dadlHash
}

// RecordCall increments the call or error counter for the given backend.
// This is safe for concurrent use and works even when telemetry sending is disabled.
func (c *Collector) RecordCall(backendName string, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hash, ok := c.backends[backendName]
	if !ok {
		return // not a DADL/REST backend — skip silently
	}

	cp := c.counters[hash]
	if cp == nil {
		cp = &counterPair{}
		c.counters[hash] = cp
	}
	if success {
		cp.CallCount++
	} else {
		cp.ErrorCount++
	}
}

// Run starts the send loop. It blocks until ctx is canceled, at which
// point it persists the current counters and returns.
//
// The first report of a process is scheduled from the last successful one,
// which the state file keeps across restarts, so that installations which
// restart more often than once per interval report on schedule, and a
// restart neither postpones a report nor adds one:
//   - No successful report yet, or the last one is at least one interval
//     old: the report is due and goes out after a random delay of one to
//     five minutes (at most one interval).
//   - Otherwise: the report goes out one interval after the last one.
//
// After that, a report goes out every interval.
func (c *Collector) Run(ctx context.Context) {
	if c.disabled {
		// Telemetry is opted out, but we still want persistState() to run on
		// shutdown so counters survive for potential re-enablement.
		<-ctx.Done()
		c.persistState()
		return
	}

	c.mu.Lock()
	lastSent := c.lastSent
	c.mu.Unlock()

	firstDelay := c.firstDelay(lastSent)
	c.logger.DebugContext(ctx, "telemetry: run loop started",
		"firstReportIn", firstDelay.Round(time.Second),
		"lastSent", lastSent,
		"interval", c.interval,
	)

	fire := c.after(firstDelay)
	for {
		select {
		case <-fire:
			c.send(ctx)
			fire = c.after(c.interval)
		case <-ctx.Done():
			c.persistState()
			return
		}
	}
}

// firstDelay returns how long Run waits before the first report of this
// process, given the time of the last successful report (zero if none). A
// last report in the future means the clock went back since; that report
// counts as due, so that the next one replaces the wrong time.
func (c *Collector) firstDelay(lastSent time.Time) time.Duration {
	now := c.now()
	if !lastSent.IsZero() && !lastSent.After(now) {
		if next := lastSent.Add(c.interval); next.After(now) {
			return next.Sub(now)
		}
	}
	return min(c.startDelay(), c.interval)
}

// send posts the current counters to the telemetry endpoint, in requests of
// at most maxBatchEntries entries because the collector rejects larger ones.
// The counters of each accepted request are reset right away, so a later
// request that fails does not make the accepted ones count twice. LastSent
// advances only when every request was accepted; the counters of a rejected
// request and of the requests after it wait for the next cycle.
func (c *Collector) send(ctx context.Context) {
	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	requests := (len(payload) + maxBatchEntries - 1) / maxBatchEntries
	for i := range requests {
		batch := payload[i*maxBatchEntries : min((i+1)*maxBatchEntries, len(payload))]
		if !c.post(ctx, batch, i+1, requests) {
			if i > 0 {
				// Keep the reset counters of the accepted requests.
				c.persistState()
			}
			return
		}
		c.mu.Lock()
		c.resetCounters(batch)
		c.mu.Unlock()
	}

	c.mu.Lock()
	c.lastSent = c.now().UTC()
	c.mu.Unlock()
	c.persistState()
	c.logger.Info("telemetry: report sent", "entries", len(payload), "requests", requests)
}

// post sends one batch of report entries and reports whether the collector
// accepted it. Request n of total is named in the warnings.
func (c *Collector) post(ctx context.Context, batch []report, n, total int) bool {
	body, err := json.Marshal(batch)
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: failed to marshal payload", "error", err)
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: failed to create request", "error", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: send failed, will retry next cycle",
			"error", err, "request", n, "of", total)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		c.logger.WarnContext(ctx, "telemetry: unexpected status, will retry next cycle",
			"status", resp.StatusCode, "request", n, "of", total, "entries", len(batch))
		return false
	}
	return true
}

// buildPayload creates the report slice from the set of registered backends.
// One entry is produced per unique DADL hash — even when the counters are
// zero — so that idle installations still appear in the telemetry database as
// a heartbeat. Must be called with c.mu held.
func (c *Collector) buildPayload() []report {
	seen := make(map[string]struct{}, len(c.backends))
	reports := make([]report, 0, len(c.backends))
	for _, hash := range c.backends {
		if _, dup := seen[hash]; dup {
			continue
		}
		seen[hash] = struct{}{}

		var calls, errors int
		if cp := c.counters[hash]; cp != nil {
			calls = cp.CallCount
			errors = cp.ErrorCount
		}
		reports = append(reports, report{
			SiteID:         c.siteID,
			DADLHash:       hash,
			CallCount:      calls,
			ErrorCount:     errors,
			Version:        c.version,
			MCPServerCount: c.mcpServerCount,
		})
	}
	// A stable order keeps each DADL in the same request of a split report.
	slices.SortFunc(reports, func(a, b report) int { return strings.Compare(a.DADLHash, b.DADLHash) })
	return reports
}

// resetCounters zeroes out the counters that were included in the sent payload.
// Must be called with c.mu held.
func (c *Collector) resetCounters(sent []report) {
	for _, r := range sent {
		if cp, ok := c.counters[r.DADLHash]; ok {
			cp.CallCount -= r.CallCount
			cp.ErrorCount -= r.ErrorCount
			if cp.CallCount <= 0 && cp.ErrorCount <= 0 {
				delete(c.counters, r.DADLHash)
			}
		}
	}
}

// loadState reads persisted telemetry counters from the state file.
func (c *Collector) loadState() {
	path := filepath.Join(c.dataDir, stateFile)
	data, err := os.ReadFile(path) //nolint:gosec // path from trusted config
	if err != nil {
		return // file doesn't exist yet — start fresh
	}

	var state stateData
	if err := json.Unmarshal(data, &state); err != nil {
		c.logger.Warn("telemetry: failed to parse state file, starting fresh", "error", err)
		return
	}
	if state.Telemetry == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if state.Telemetry.LastSent != "" {
		if t, err := time.Parse(time.RFC3339, state.Telemetry.LastSent); err == nil {
			c.lastSent = t
		}
	}

	if id := state.Telemetry.SiteID; id != "" {
		if validSiteID(id) {
			c.siteID = strings.ToLower(id)
		} else {
			c.logger.Warn("telemetry: ignoring invalid site ID in state file", "siteID", id)
		}
	}

	for hash, cp := range state.Telemetry.Counters {
		c.counters[hash] = &counterPair{
			CallCount:  cp.CallCount,
			ErrorCount: cp.ErrorCount,
		}
	}

	c.logger.Debug("telemetry: state loaded",
		"siteID", c.siteID,
		"lastSent", c.lastSent,
		"counters", len(c.counters),
	)
}

// persistState writes the current counters to the state file atomically.
// LastSent reflects the last *successful* send — never the time of this
// persist call — so that shutdown persists do not corrupt the overdue check
// on the next startup.
func (c *Collector) persistState() {
	c.mu.Lock()
	state := stateData{
		Telemetry: &telemetryState{
			SiteID:   c.siteID,
			Counters: make(map[string]*counterPair, len(c.counters)),
		},
	}
	if !c.lastSent.IsZero() {
		state.Telemetry.LastSent = c.lastSent.UTC().Format(time.RFC3339)
	}
	for hash, cp := range c.counters {
		state.Telemetry.Counters[hash] = &counterPair{
			CallCount:  cp.CallCount,
			ErrorCount: cp.ErrorCount,
		}
	}
	c.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		c.logger.Warn("telemetry: failed to marshal state", "error", err)
		return
	}

	// A data directory that cannot be written leaves the state in memory: the
	// process keeps reporting on schedule, only a restart starts afresh.
	path := filepath.Join(c.dataDir, stateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // non-sensitive aggregated counters
		c.logger.Info("telemetry: cannot write state file, keeping the state in memory", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		c.logger.Info("telemetry: cannot replace state file, keeping the state in memory", "error", err)
		_ = os.Remove(tmp)
	}
}

// SetEndpoint overrides the telemetry endpoint URL (for testing).
func (c *Collector) SetEndpoint(url string) {
	// This is a test helper; not exposed beyond the package.
	// We store it in a field to avoid a global var.
	c.client = &http.Client{
		Timeout: httpTimeout,
		Transport: &rewriteTransport{
			base:    http.DefaultTransport,
			baseURL: url,
		},
	}
}

// rewriteTransport redirects all requests to a different base URL.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

// RoundTrip rewrites the request URL to the test base URL.
func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL, _ = req.URL.Parse(t.baseURL + req.URL.Path)
	if req.URL == nil {
		return nil, fmt.Errorf("failed to rewrite URL")
	}
	return t.base.RoundTrip(req)
}
