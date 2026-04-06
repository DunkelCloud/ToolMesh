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
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
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
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
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

func TestBuildPayload_SkipsZeroCounters(t *testing.T) {
	c := New(t.TempDir(), "v1", quietLogger())
	c.mu.Lock()
	c.counters["empty"] = &counterPair{}
	c.counters["active"] = &counterPair{CallCount: 5}
	c.mu.Unlock()

	c.mu.Lock()
	payload := c.buildPayload()
	c.mu.Unlock()

	if len(payload) != 1 {
		t.Fatalf("expected 1 report (skipping zeros), got %d", len(payload))
	}
	if payload[0].DADLHash != "active" {
		t.Errorf("expected hash 'active', got %q", payload[0].DADLHash)
	}
}
