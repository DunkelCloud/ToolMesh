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

// Package metrics exposes ToolMesh runtime counters and latency histograms in
// Prometheus text format. The package owns its own [prometheus.Registry] so
// metric registration cannot collide with other libraries that touch the
// global default registry.
//
// All Registry methods are safe to call on a nil receiver, so callers may
// keep an optional *Registry field without nil-checking at every call site.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// AnyTool is the placeholder used in the "tool" label when per-tool labeling
// is disabled via Options.LabelTool=false. Choosing a sentinel value (rather
// than dropping the label) keeps PromQL queries that group by tool valid in
// either configuration.
const AnyTool = "*"

// restLatencyBuckets are histogram buckets tuned to typical REST backend
// latencies — finer-grained at the low end where most ToolMesh calls land,
// with a 30 s ceiling that matches the default executor timeout.
var restLatencyBuckets = []float64{0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0}

// Options configures a Registry at construction time.
type Options struct {
	// LabelTool controls whether the "tool" label on tool-call metrics carries
	// the actual tool name (true) or the [AnyTool] placeholder (false). Disable
	// for deployments with many tools where per-tool cardinality is too high.
	LabelTool bool
}

// Registry owns a Prometheus registry and the metric vectors ToolMesh exposes.
type Registry struct {
	reg              *prometheus.Registry
	logins           *prometheus.CounterVec
	toolCalls        *prometheus.CounterVec
	toolCallDuration *prometheus.HistogramVec
	labelTool        bool
}

// New constructs a Registry with all ToolMesh metrics pre-registered.
func New(opts Options) *Registry {
	reg := prometheus.NewRegistry()

	logins := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "toolmesh",
		Name:      "logins_total",
		Help:      "Authentication events. method=oauth_code|oauth_refresh|oauth_bearer|api_key, result=success|failure.",
	}, []string{"method", "result"})

	toolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "toolmesh",
		Name:      "tool_calls_total",
		Help:      "Tool invocations after authentication. result=success|error.",
	}, []string{"backend", "tool", "result"})

	toolCallDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "toolmesh",
		Name:      "tool_call_duration_seconds",
		Help:      "End-to-end tool-call latency, from handler entry to result return.",
		Buckets:   restLatencyBuckets,
	}, []string{"backend", "tool"})

	reg.MustRegister(logins, toolCalls, toolCallDuration)

	// Pre-initialize all login label combinations to zero so a fresh scrape
	// returns informative output (HELP/TYPE plus zero counters) before the
	// first authentication event. The set of (method, result) values is
	// closed and small enough that this does not bloat cardinality.
	for _, method := range []string{"oauth_code", "oauth_refresh", "oauth_bearer", "api_key"} {
		for _, result := range []string{"success", "failure"} {
			logins.WithLabelValues(method, result)
		}
	}

	return &Registry{
		reg:              reg,
		logins:           logins,
		toolCalls:        toolCalls,
		toolCallDuration: toolCallDuration,
		labelTool:        opts.LabelTool,
	}
}

// RecordLogin increments the logins counter for the given method and result.
// Callers should pass one of: "oauth_code", "oauth_refresh", "oauth_bearer",
// "api_key" for method, and "success" or "failure" for result.
//
// Safe to call on a nil receiver.
func (r *Registry) RecordLogin(method, result string) {
	if r == nil {
		return
	}
	r.logins.WithLabelValues(method, result).Inc()
}

// RecordToolCall records a single tool invocation: it increments the call
// counter and observes the duration on the latency histogram. The tool label
// is replaced with [AnyTool] if per-tool labeling is disabled.
//
// Safe to call on a nil receiver.
func (r *Registry) RecordToolCall(backendName, toolName, result string, duration time.Duration) {
	if r == nil {
		return
	}
	tool := toolName
	if !r.labelTool {
		tool = AnyTool
	}
	r.toolCalls.WithLabelValues(backendName, tool, result).Inc()
	r.toolCallDuration.WithLabelValues(backendName, tool).Observe(duration.Seconds())
}

// Handler returns an http.Handler that serves the metrics in Prometheus text
// format on whatever path it is mounted at (usually "/metrics").
//
// Returns a 404 handler if r is nil.
//
// HandlerOpts.Registry is intentionally left unset so promhttp's own
// instrumentation (promhttp_metric_handler_requests_total etc.) is registered
// against the global default registry rather than ours, keeping our scrape
// output focused on toolmesh_* series.
func (r *Registry) Handler() http.Handler {
	if r == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "metrics disabled", http.StatusNotFound)
		})
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

// PrometheusRegistry exposes the underlying [prometheus.Registry], primarily
// for tests that need to gather metrics directly with [testutil.ToFloat64].
func (r *Registry) PrometheusRegistry() *prometheus.Registry {
	if r == nil {
		return nil
	}
	return r.reg
}
