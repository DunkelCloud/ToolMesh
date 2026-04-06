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
	DADLHash   string `json:"dadl_hash"`
	CallCount  int    `json:"call_count"`
	ErrorCount int    `json:"error_count"`
	Version    string `json:"version"`
}

// Collector accumulates tool call statistics and periodically sends them.
type Collector struct {
	mu       sync.Mutex
	counters map[string]*counterPair // dadlHash → counts
	backends map[string]string       // backendName → dadlHash

	dataDir  string
	version  string
	disabled bool
	logger   *slog.Logger
	client   *http.Client
}

// New creates a Collector. If DO_NOT_SEND_ANONYMOUS_STATISTICS=yes, sending
// is disabled but counters are still accumulated (persisted for re-enablement).
func New(dataDir, version string, logger *slog.Logger) *Collector {
	disabled := strings.EqualFold(os.Getenv("DO_NOT_SEND_ANONYMOUS_STATISTICS"), "yes")

	c := &Collector{
		counters: make(map[string]*counterPair),
		backends: make(map[string]string),
		dataDir:  dataDir,
		version:  version,
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

// Run starts the 24h send loop. It blocks until ctx is cancelled, at which
// point it persists the current counters and returns.
func (c *Collector) Run(ctx context.Context) {
	ticker := time.NewTicker(sendInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !c.disabled {
				c.send(ctx)
			}
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
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		c.mu.Lock()
		c.resetCounters(payload)
		c.mu.Unlock()
		c.persistState()
		c.logger.Info("telemetry: report sent", "entries", len(payload))
	} else {
		c.logger.WarnContext(ctx, "telemetry: unexpected status, will retry next cycle", "status", resp.StatusCode)
	}
}

// buildPayload creates the report slice from current counters. Must be called
// with c.mu held.
func (c *Collector) buildPayload() []report {
	var reports []report
	for hash, cp := range c.counters {
		if cp.CallCount == 0 && cp.ErrorCount == 0 {
			continue
		}
		reports = append(reports, report{
			DADLHash:   hash,
			CallCount:  cp.CallCount,
			ErrorCount: cp.ErrorCount,
			Version:    c.version,
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
	if state.Telemetry == nil || state.Telemetry.Counters == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	for hash, cp := range state.Telemetry.Counters {
		c.counters[hash] = &counterPair{
			CallCount:  cp.CallCount,
			ErrorCount: cp.ErrorCount,
		}
	}
}

// persistState writes the current counters to the state file atomically.
func (c *Collector) persistState() {
	c.mu.Lock()
	state := stateData{
		Telemetry: &telemetryState{
			LastSent: time.Now().UTC().Format(time.RFC3339),
			Counters: make(map[string]*counterPair, len(c.counters)),
		},
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

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL, _ = req.URL.Parse(t.baseURL + req.URL.Path)
	if req.URL == nil {
		return nil, fmt.Errorf("failed to rewrite URL")
	}
	return t.base.RoundTrip(req)
}
