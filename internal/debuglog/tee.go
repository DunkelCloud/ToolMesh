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

// Package debuglog provides a tee slog.Handler that writes to both the
// primary handler (stdout) and a secondary handler (debug file).
package debuglog

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// TeeHandler fans out slog records to two handlers.
// The primary handler uses the caller's level (unchanged behavior).
// The secondary handler always accepts debug-level records.
type TeeHandler struct {
	primary   slog.Handler
	secondary slog.Handler
}

// NewTeeHandler creates a handler that writes to both the primary handler
// and a JSON debug handler writing to w at debug level.
func NewTeeHandler(primary slog.Handler, w io.Writer) *TeeHandler {
	secondary := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	})
	return &TeeHandler{primary: primary, secondary: secondary}
}

// Enabled reports whether either handler accepts records at the given level.
func (h *TeeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.primary.Enabled(ctx, level) || h.secondary.Enabled(ctx, level)
}

// Handle writes the record to both handlers (if they accept the level).
func (h *TeeHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.primary.Enabled(ctx, r.Level) {
		if err := h.primary.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}
	if h.secondary.Enabled(ctx, r.Level) {
		return h.secondary.Handle(ctx, r.Clone())
	}
	return nil
}

// WithAttrs returns a new TeeHandler with the given attributes added to both handlers.
func (h *TeeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TeeHandler{
		primary:   h.primary.WithAttrs(attrs),
		secondary: h.secondary.WithAttrs(attrs),
	}
}

// WithGroup returns a new TeeHandler with the given group name applied to both handlers.
func (h *TeeHandler) WithGroup(name string) slog.Handler {
	return &TeeHandler{
		primary:   h.primary.WithGroup(name),
		secondary: h.secondary.WithGroup(name),
	}
}

// OpenDebugFile opens the debug log file for writing (append mode, create if needed).
// The caller is responsible for closing the returned file.
func OpenDebugFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}
