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

package metrics_test

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

// fakeRuns stands in for the command credential store.
type fakeRuns struct {
	ok, failed atomic.Uint64
	last       atomic.Int64
}

func (f *fakeRuns) RunCounts() (uint64, uint64) { return f.ok.Load(), f.failed.Load() }

func (f *fakeRuns) LastSuccess() time.Time {
	if n := f.last.Load(); n != 0 {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

func TestWatchCredentialStore(t *testing.T) {
	r := metrics.New(metrics.Options{LabelTool: true})
	runs := &fakeRuns{}
	// A run before the registration (the first run at startup) is counted.
	runs.ok.Store(1)
	runs.last.Store(1762344000)
	if err := r.WatchCredentialStore(runs); err != nil {
		t.Fatalf("WatchCredentialStore: %v", err)
	}

	body := scrapeMetrics(t, r)
	mustContain(t, body, `toolmesh_credential_store_runs_total{result="success"} 1`)
	mustContain(t, body, `toolmesh_credential_store_runs_total{result="failure"} 0`)
	mustContain(t, body, `toolmesh_credential_store_last_success_timestamp_seconds 1.762344e+09`)

	// Values are read at scrape time.
	runs.ok.Add(2)
	runs.failed.Add(4)
	runs.last.Store(1762347600)
	body = scrapeMetrics(t, r)
	mustContain(t, body, `toolmesh_credential_store_runs_total{result="success"} 3`)
	mustContain(t, body, `toolmesh_credential_store_runs_total{result="failure"} 4`)
	mustContain(t, body, `toolmesh_credential_store_last_success_timestamp_seconds 1.7623476e+09`)

	if err := r.WatchCredentialStore(runs); err == nil {
		t.Error("a second registration must return an error, not panic")
	}
}

func TestWatchCredentialStore_NotRegisteredByDefault(t *testing.T) {
	body := scrapeMetrics(t, metrics.New(metrics.Options{}))
	if strings.Contains(body, "toolmesh_credential_store_") {
		t.Errorf("credential store metrics present without a watched store:\n%s", body)
	}
}

func TestWatchCredentialStore_NilSafe(t *testing.T) {
	var r *metrics.Registry
	if err := r.WatchCredentialStore(&fakeRuns{}); err != nil {
		t.Errorf("nil registry: %v", err)
	}
	if err := metrics.New(metrics.Options{}).WatchCredentialStore(nil); err != nil {
		t.Errorf("nil store: %v", err)
	}
}
