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
	"context"
	"log/slog"
)

type traceIDKey struct{}

// WithTraceID stores a trace ID in the context.
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, traceIDKey{}, traceID)
}

// TraceIDFromContext extracts the trace ID from a context, or returns "".
func TraceIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(traceIDKey{}).(string)
	return id
}

// ContextHandler wraps a slog.Handler and automatically adds the trace_id
// attribute from context to every log record emitted via *Context methods.
type ContextHandler struct {
	inner slog.Handler
}

// NewContextHandler creates a ContextHandler wrapping the given handler.
func NewContextHandler(inner slog.Handler) *ContextHandler {
	return &ContextHandler{inner: inner}
}

// Enabled delegates to the inner handler.
func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle extracts trace_id from the context and prepends it to the record.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if traceID := TraceIDFromContext(ctx); traceID != "" {
		r.AddAttrs(slog.String("trace_id", traceID))
	}
	return h.inner.Handle(ctx, r)
}

// WithAttrs delegates to the inner handler.
func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup delegates to the inner handler.
func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{inner: h.inner.WithGroup(name)}
}
