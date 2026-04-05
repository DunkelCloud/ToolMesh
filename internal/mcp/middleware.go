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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// SecurityHeaders sets standard security response headers on all responses (M-4).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// PanicRecovery returns HTTP middleware that catches panics in handlers,
// logs them, and returns a 500 Internal Server Error instead of crashing (H-10).
func PanicRecovery(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.ErrorContext(r.Context(), "panic recovered in HTTP handler",
						"panic", fmt.Sprintf("%v", rec),
						"method", r.Method,
						"path", r.URL.Path,
					)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestLogging returns HTTP middleware that logs every request with
// method, path, status, duration, and a generated trace ID.
// The trace ID is stored in the request context so downstream handlers
// and slog *Context methods can access it automatically.
func RequestLogging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			traceID := generateTraceID()
			start := time.Now()

			// Store trace ID in context for downstream use.
			ctx := WithTraceID(r.Context(), traceID)
			r = r.WithContext(ctx)

			// Set trace ID response header for client-side correlation.
			w.Header().Set("X-Trace-Id", traceID)

			// Wrap ResponseWriter to capture status code.
			rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}

			logger.InfoContext(ctx, "http request start",
				"method", r.Method,
				"path", r.URL.Path,
				"remote", clientIP(r),
			)

			next.ServeHTTP(rw, r)

			logger.InfoContext(ctx, "http request done",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rw.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"remote", clientIP(r),
			)
		})
	}
}

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader captures the status code before delegating.
func (w *statusWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.status = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// Write ensures a default 200 status is recorded if WriteHeader was not called.
func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.wroteHeader = true
		// status stays at default 200
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap allows http.ResponseController and middleware to access the
// underlying ResponseWriter (e.g. for http.Flusher support).
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// generateTraceID produces a 16-byte hex trace ID (32 chars).
func generateTraceID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; degrade gracefully.
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}
