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

package mcp

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogging_SetsTraceID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	handler := RequestLogging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify trace ID is in context
		traceID := TraceIDFromContext(r.Context())
		if traceID == "" {
			t.Error("expected trace ID in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify X-Trace-Id response header
	traceHeader := rec.Header().Get("X-Trace-Id")
	if traceHeader == "" {
		t.Error("expected X-Trace-Id response header")
	}
	if len(traceHeader) != 32 {
		t.Errorf("expected 32-char trace ID, got %d chars: %s", len(traceHeader), traceHeader)
	}

	// Verify log output contains trace_id
	logOutput := buf.String()
	if !strings.Contains(logOutput, "trace_id=") {
		t.Errorf("expected trace_id in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "http request start") {
		t.Errorf("expected 'http request start' in log output, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, "http request done") {
		t.Errorf("expected 'http request done' in log output, got:\n%s", logOutput)
	}
}

func TestRequestLogging_CapturesStatusCode(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewContextHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))

	handler := RequestLogging(logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "status=404") {
		t.Errorf("expected status=404 in log output, got:\n%s", logOutput)
	}
}

func TestContextHandler_AddsTraceID(t *testing.T) {
	var buf bytes.Buffer
	handler := NewContextHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger := slog.New(handler)

	ctx := WithTraceID(t.Context(), "abc123")
	logger.InfoContext(ctx, "test message")

	logOutput := buf.String()
	if !strings.Contains(logOutput, "trace_id=abc123") {
		t.Errorf("expected trace_id=abc123 in log output, got:\n%s", logOutput)
	}
}

func TestContextHandler_NoTraceID(t *testing.T) {
	var buf bytes.Buffer
	handler := NewContextHandler(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger := slog.New(handler)

	// Log without trace ID in context
	logger.Info("test message")

	logOutput := buf.String()
	if strings.Contains(logOutput, "trace_id") {
		t.Errorf("expected no trace_id in log output, got:\n%s", logOutput)
	}
}

func TestGenerateTraceID_UniqueAndCorrectLength(t *testing.T) {
	id1 := generateTraceID()
	id2 := generateTraceID()

	if len(id1) != 32 {
		t.Errorf("expected 32-char trace ID, got %d: %s", len(id1), id1)
	}
	if id1 == id2 {
		t.Error("expected unique trace IDs")
	}
}
