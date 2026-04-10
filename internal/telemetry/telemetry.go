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

// Package telemetry implements anonymous, opt-out usage telemetry for ToolMesh.
// It collects aggregated DADL usage statistics (call counts, error counts per
// content-hashed DADL file) and reports them to a central endpoint every 24 hours.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	endpoint     = "https://tmc.dunkel.cloud/v1/telemetry"
	sendInterval = 24 * time.Hour
	httpTimeout  = 10 * time.Second
	stateFile    = "toolmesh.json"
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
	LastSent string                  `json:"last_sent,omitempty"`
	Counters map[string]*counterPair `json:"counters,omitempty"`
}

// report is a single entry in the telemetry payload.
type report struct {
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

	mcpServerCount int

	dataDir  string
	version  string
	interval time.Duration
	disabled bool
	logger   *slog.Logger
	client   *http.Client
}

// New creates a Collector. If DO_NOT_SEND_ANONYMOUS_STATISTICS=yes, sending
// is disabled but counters are still accumulated (persisted for re-enablement).
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
	}

	if disabled {
		logger.Warn("anonymous telemetry is disabled — set DO_NOT_SEND_ANONYMOUS_STATISTICS= to re-enable; see https://toolmesh.io/telemetry for details")
	}

	c.loadState()
	return c
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
// Scheduling accounts for the persisted LastSent so that containers which
// restart more often than once per interval still send on schedule:
//   - Never sent (zero LastSent): first fire after a full interval.
//   - LastSent older than one interval: send immediately, then schedule normally.
//   - LastSent within the interval: first fire at (LastSent + interval),
//     i.e. only the remaining time, not a fresh full interval.
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

	var firstDelay time.Duration
	switch {
	case lastSent.IsZero():
		firstDelay = c.interval
		c.logger.Debug("telemetry: run loop started (no prior send)",
			"firstSendIn", firstDelay,
			"interval", c.interval,
		)
	case time.Since(lastSent) >= c.interval:
		age := time.Since(lastSent).Round(time.Second)
		c.logger.Debug("telemetry: overdue, sending now",
			"lastSent", lastSent,
			"interval", c.interval,
			"age", age,
		)
		c.send(ctx)
		firstDelay = c.interval
	default:
		firstDelay = c.interval - time.Since(lastSent)
		c.logger.Debug("telemetry: run loop started (resuming partial interval)",
			"firstSendIn", firstDelay.Round(time.Second),
			"lastSent", lastSent,
			"interval", c.interval,
		)
	}

	timer := time.NewTimer(firstDelay)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			c.send(ctx)
			timer.Reset(c.interval)
		case <-ctx.Done():
			c.persistState()
			return
		}
	}
}

// send posts the current counters to the telemetry endpoint and resets them
// on success.
func (c *Collector) send(ctx context.Context) {
	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()

	if len(payload) == 0 {
		return
	}

	body, err := json.Marshal(payload)
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: failed to marshal payload", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: failed to create request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		c.logger.WarnContext(ctx, "telemetry: send failed, will retry next cycle", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.mu.Lock()
		c.resetCounters(payload)
		c.lastSent = time.Now().UTC()
		c.mu.Unlock()
		c.persistState()
		c.logger.Info("telemetry: report sent", "entries", len(payload))
	} else {
		c.logger.WarnContext(ctx, "telemetry: unexpected status, will retry next cycle", "status", resp.StatusCode)
	}
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
			DADLHash:       hash,
			CallCount:      calls,
			ErrorCount:     errors,
			Version:        c.version,
			MCPServerCount: c.mcpServerCount,
		})
	}
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

	for hash, cp := range state.Telemetry.Counters {
		c.counters[hash] = &counterPair{
			CallCount:  cp.CallCount,
			ErrorCount: cp.ErrorCount,
		}
	}

	c.logger.Debug("telemetry: state loaded",
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

	path := filepath.Join(c.dataDir, stateFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil { //nolint:gosec // non-sensitive aggregated counters
		c.logger.Warn("telemetry: failed to write state file", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		c.logger.Warn("telemetry: failed to rename state file", "error", err)
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
