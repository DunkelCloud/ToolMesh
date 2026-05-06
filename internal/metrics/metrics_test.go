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
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/metrics"
)

func TestRecordLogin_IncrementsByLabel(t *testing.T) {
	r := metrics.New(metrics.Options{LabelTool: true})

	cases := []struct {
		method, result string
		times          int
	}{
		{testLoginMethodOAuthCode, testLoginResultSuccess, 3},
		{testLoginMethodOAuthCode, testLoginResultFailure, 1},
		{"oauth_refresh", testLoginResultSuccess, 2},
		{"api_key", testLoginResultSuccess, 5},
		{"oauth_bearer", testLoginResultFailure, 4},
	}
	for _, c := range cases {
		for i := 0; i < c.times; i++ {
			r.RecordLogin(c.method, c.result)
		}
	}

	body := scrapeMetrics(t, r)
	for _, c := range cases {
		want := `toolmesh_logins_total{method="` + c.method + `",result="` + c.result + `"} ` + itoa(c.times)
		mustContain(t, body, want)
	}
}

func TestRecordToolCall_LabelToolEnabled(t *testing.T) {
	r := metrics.New(metrics.Options{LabelTool: true})

	r.RecordToolCall("hetzner", "list_servers", testLoginResultSuccess, 50*time.Millisecond)
	r.RecordToolCall("hetzner", "list_servers", testLoginResultSuccess, 80*time.Millisecond)
	r.RecordToolCall("hetzner", "create_server", "error", 200*time.Millisecond)

	body := scrapeMetrics(t, r)

	mustContain(t, body, `toolmesh_tool_calls_total{backend="hetzner",result="success",tool="list_servers"} 2`)
	mustContain(t, body, `toolmesh_tool_calls_total{backend="hetzner",result="error",tool="create_server"} 1`)
	mustContain(t, body, `toolmesh_tool_call_duration_seconds_count{backend="hetzner",tool="list_servers"} 2`)
	mustContain(t, body, `toolmesh_tool_call_duration_seconds_bucket{backend="hetzner",tool="list_servers",le="0.1"} 2`)
}

func TestRecordToolCall_LabelToolDisabled_CollapsesToPlaceholder(t *testing.T) {
	r := metrics.New(metrics.Options{LabelTool: false})

	r.RecordToolCall("hetzner", "list_servers", testLoginResultSuccess, 10*time.Millisecond)
	r.RecordToolCall("hetzner", "create_server", testLoginResultSuccess, 10*time.Millisecond)

	body := scrapeMetrics(t, r)

	mustContain(t, body, `toolmesh_tool_calls_total{backend="hetzner",result="success",tool="*"} 2`)
	if strings.Contains(body, `tool="list_servers"`) || strings.Contains(body, `tool="create_server"`) {
		t.Errorf("real tool names leaked into metrics with LabelTool=false:\n%s", body)
	}
}

func TestNilRegistry_IsSafe(t *testing.T) {
	var r *metrics.Registry

	r.RecordLogin("api_key", testLoginResultSuccess)
	r.RecordToolCall("any", "thing", testLoginResultSuccess, time.Second)

	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("nil registry handler status = %d, want 404", resp.StatusCode)
	}
}

func TestEmptyScrape_LoginsPreinitialized_NoPromhttpSelfMetrics(t *testing.T) {
	// A fresh Registry with no observations must still expose every login
	// label combination at zero so dashboards have something to bind to
	// before any traffic arrives, and must not leak promhttp's own
	// instrumentation into our scrape output.
	r := metrics.New(metrics.Options{LabelTool: true})
	body := scrapeMetrics(t, r)

	for _, method := range []string{testLoginMethodOAuthCode, "oauth_refresh", "oauth_bearer", "api_key"} {
		for _, result := range []string{testLoginResultSuccess, testLoginResultFailure} {
			want := `toolmesh_logins_total{method="` + method + `",result="` + result + `"} 0`
			mustContain(t, body, want)
		}
	}

	if strings.Contains(body, "promhttp_metric_handler_") {
		t.Errorf("promhttp self-metrics leaked into scrape output:\n%s", body)
	}
}

func TestHandler_ServesPrometheusFormat(t *testing.T) {
	r := metrics.New(metrics.Options{LabelTool: true})
	// Record at least one observation per vec — Prometheus does not emit
	// HELP/TYPE lines for vecs that have never had a label combination set.
	r.RecordLogin("api_key", testLoginResultSuccess)
	r.RecordToolCall("hetzner", "list_servers", testLoginResultSuccess, 25*time.Millisecond)

	body := scrapeMetrics(t, r)

	for _, want := range []string{
		"# HELP toolmesh_logins_total",
		"# TYPE toolmesh_logins_total counter",
		`toolmesh_logins_total{method="api_key",result="success"} 1`,
		"# HELP toolmesh_tool_calls_total",
		"# TYPE toolmesh_tool_call_duration_seconds histogram",
	} {
		mustContain(t, body, want)
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain:\n  %s\ngot:\n%s", needle, haystack)
	}
}

func scrapeMetrics(t *testing.T, r *metrics.Registry) string {
	t.Helper()
	srv := httptest.NewServer(r.Handler())
	t.Cleanup(srv.Close)
	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("scrape: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("scrape status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
