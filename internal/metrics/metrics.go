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

// Values of the "outcome" label on toolmesh_codemode_scripts_total: how an
// execute_code script ended.
const (
	// ScriptOutcomeOK means the script ran to completion without throwing.
	ScriptOutcomeOK = "ok"
	// ScriptOutcomeError means the script did not run to completion: the
	// static analysis rejected it, it threw an uncaught exception, it
	// exceeded the tool-call budget, or the request was canceled.
	ScriptOutcomeError = "error"
	// ScriptOutcomeTimeout means the script ran out of its wall-clock budget.
	ScriptOutcomeTimeout = "timeout"
)

// Values of the "reason" label on toolmesh_codemode_swallowed_errors_total:
// how a tool call inside an execute_code script failed.
const (
	// SwallowedDispatch means the call produced no result at all, such as a
	// backend request that failed on the network or timed out; the script
	// got an {error, tool} object.
	SwallowedDispatch = "dispatch"
	// SwallowedCoercion means the arguments could not be converted to the
	// tool's declared types; the call did not run and returned undefined.
	// Only tools with a TypeScript definition in the tools directory are
	// coerced, so DADL and MCP backend tools never report it.
	SwallowedCoercion = "coercion"
	// SwallowedToolError means the call returned an error result: the backend
	// reported an error, or authorization or a gate policy refused the call.
	SwallowedToolError = "tool_error"
)

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
	codeScripts      *prometheus.CounterVec
	swallowedErrors  *prometheus.CounterVec
	healthUp         *prometheus.GaugeVec
	healthDegraded   *prometheus.GaugeVec
	authExpiry       *prometheus.GaugeVec
	labelTool        bool
}

// metricsNamespace is the Prometheus namespace prefix for all ToolMesh metrics.
const metricsNamespace = "toolmesh"

// labelBackend is the name of the label that carries the backend name.
const labelBackend = "backend"

// New constructs a Registry with all ToolMesh metrics pre-registered.
func New(opts Options) *Registry {
	reg := prometheus.NewRegistry()

	logins := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "logins_total",
		Help:      "Authentication events. method=password|oauth_code|oauth_refresh|oauth_bearer|api_key|anonymous, result=success|failure.",
	}, []string{"method", "result"})

	toolCalls := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "tool_calls_total",
		Help:      "Tool invocations after authentication. result=success|error|denied (denied = blocked by OpenFGA or output gate).",
	}, []string{labelBackend, "tool", "result"})

	toolCallDuration := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metricsNamespace,
		Name:      "tool_call_duration_seconds",
		Help:      "End-to-end tool-call latency, from handler entry to result return.",
		Buckets:   restLatencyBuckets,
	}, []string{labelBackend, "tool"})

	codeScripts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "codemode_scripts_total",
		Help:      "execute_code scripts by how they ended. outcome=ok|error|timeout (error = rejected by the static analysis, uncaught exception, tool-call budget exceeded or request canceled).",
	}, []string{"outcome"})

	swallowedErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: metricsNamespace,
		Name:      "codemode_swallowed_errors_total",
		Help:      "execute_code scripts that ended without throwing although a tool call in them failed, counted once per script, backend and reason. reason=dispatch|coercion|tool_error.",
	}, []string{labelBackend, "reason"})

	healthUp := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "backend_health_up",
		Help:      "1 when the latest health check of a backend (DADL spec 4.6) passed, 0 when it failed. Only backends whose DADL declares a check.",
	}, []string{labelBackend})

	healthDegraded := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "backend_health_degraded",
		Help:      "1 while a backend counts as degraded: its health check failed at least degrade_after times in a row.",
	}, []string{labelBackend})

	authExpiry := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "backend_auth_expiry_timestamp_seconds",
		Help:      "Unix time at which a backend credential expires, from the health check response or backends.yaml auth_expires_at. Absent when unknown.",
	}, []string{labelBackend})

	reg.MustRegister(logins, toolCalls, toolCallDuration, codeScripts, swallowedErrors, healthUp, healthDegraded, authExpiry)

	// Pre-initialize all login label combinations to zero so a fresh scrape
	// returns informative output (HELP/TYPE plus zero counters) before the
	// first authentication event. The set of (method, result) values is
	// closed and small enough that this does not bloat cardinality.
	for _, method := range []string{"password", "oauth_code", "oauth_refresh", "oauth_bearer", "api_key", "anonymous"} {
		for _, result := range []string{"success", "failure"} {
			logins.WithLabelValues(method, result)
		}
	}
	for _, outcome := range []string{ScriptOutcomeOK, ScriptOutcomeError, ScriptOutcomeTimeout} {
		codeScripts.WithLabelValues(outcome)
	}

	return &Registry{
		reg:              reg,
		logins:           logins,
		toolCalls:        toolCalls,
		toolCallDuration: toolCallDuration,
		codeScripts:      codeScripts,
		swallowedErrors:  swallowedErrors,
		healthUp:         healthUp,
		healthDegraded:   healthDegraded,
		authExpiry:       authExpiry,
		labelTool:        opts.LabelTool,
	}
}

// RecordLogin increments the logins counter for the given method and result.
// Callers should pass one of: "password", "oauth_code", "oauth_refresh",
// "oauth_bearer", "api_key", "anonymous" for method, and "success" or
// "failure" for result.
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

// RecordCodeScript counts one execute_code script by how it ended: one of
// [ScriptOutcomeOK], [ScriptOutcomeError] or [ScriptOutcomeTimeout].
//
// Safe to call on a nil receiver.
func (r *Registry) RecordCodeScript(outcome string) {
	if r == nil {
		return
	}
	r.codeScripts.WithLabelValues(outcome).Inc()
}

// RecordSwallowedError counts an execute_code script that ran to completion
// although a tool call of the given backend failed for the given reason
// ([SwallowedDispatch], [SwallowedCoercion] or [SwallowedToolError]). Callers
// record each (backend, reason) pair at most once per script.
//
// Safe to call on a nil receiver.
func (r *Registry) RecordSwallowedError(backendName, reason string) {
	if r == nil {
		return
	}
	r.swallowedErrors.WithLabelValues(backendName, reason).Inc()
}

// InitSwallowedErrors creates the swallowed-error series of every given
// backend at zero, so the counter shows up before the first failure and
// increase() over a range sees that first failure. Creating a series twice
// is a no-op, so callers may pass the backend list again after a reload.
//
// Safe to call on a nil receiver.
func (r *Registry) InitSwallowedErrors(backendNames []string) {
	if r == nil {
		return
	}
	for _, name := range backendNames {
		for _, reason := range []string{SwallowedDispatch, SwallowedCoercion, SwallowedToolError} {
			r.swallowedErrors.WithLabelValues(name, reason)
		}
	}
}

// SetBackendHealth records the latest health check of a backend: whether it
// passed, and whether the backend counts as degraded.
//
// Safe to call on a nil receiver.
func (r *Registry) SetBackendHealth(backendName string, up, degraded bool) {
	if r == nil {
		return
	}
	r.healthUp.WithLabelValues(backendName).Set(boolGauge(up))
	r.healthDegraded.WithLabelValues(backendName).Set(boolGauge(degraded))
}

// SetBackendAuthExpiry records when a backend credential expires. A zero
// time removes the series: the expiry is unknown.
//
// Safe to call on a nil receiver.
func (r *Registry) SetBackendAuthExpiry(backendName string, expires time.Time) {
	if r == nil {
		return
	}
	if expires.IsZero() {
		r.authExpiry.DeleteLabelValues(backendName)
		return
	}
	r.authExpiry.WithLabelValues(backendName).Set(float64(expires.Unix()))
}

// DeleteBackendHealth removes the health series of a backend that is no
// longer monitored, so a removed backend does not linger as failing.
//
// Safe to call on a nil receiver.
func (r *Registry) DeleteBackendHealth(backendName string) {
	if r == nil {
		return
	}
	r.healthUp.DeleteLabelValues(backendName)
	r.healthDegraded.DeleteLabelValues(backendName)
	r.authExpiry.DeleteLabelValues(backendName)
}

// boolGauge maps a bool to a gauge value.
func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
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
