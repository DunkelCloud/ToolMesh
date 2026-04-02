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

package audit

import (
	"context"
	"log/slog"
)

func init() {
	Register("log", func(_ map[string]string) (AuditStore, error) {
		return NewLogStore(), nil
	})
}

// LogStore implements AuditStore by writing structured log entries via slog.
// It is the default store — zero dependencies, write-only.
type LogStore struct{}

// NewLogStore creates a new LogStore.
func NewLogStore() *LogStore {
	return &LogStore{}
}

// Record writes an audit entry as a structured slog.Info message.
func (s *LogStore) Record(_ context.Context, entry AuditEntry) error {
	attrs := []any{
		"trace_id", entry.TraceID,
		"timestamp", entry.Timestamp,
		"user_id", entry.UserID,
		"company_id", entry.CompanyID,
		"caller_id", entry.CallerID,
		"caller_name", entry.CallerName,
		"caller_class", entry.CallerClass,
		"tool", entry.Tool,
		"duration_ms", entry.DurationMs,
		"status", entry.Status,
		"backend", entry.Backend,
	}

	if entry.Error != "" {
		attrs = append(attrs, "error", entry.Error)
	}
	if entry.IsComposite {
		attrs = append(attrs, "is_composite", true, "child_count", len(entry.ChildEvents))
	}

	slog.Info("audit", attrs...)

	// Log child events for composite tools.
	for _, child := range entry.ChildEvents {
		childAttrs := []any{
			"parent_trace_id", entry.TraceID,
			"tool", child.Tool,
			"duration_ms", child.DurationMs,
			"status", child.Status,
		}
		if child.Error != "" {
			childAttrs = append(childAttrs, "error", child.Error)
		}
		slog.Info("audit.child", childAttrs...)
	}

	return nil
}

// Query is not supported by the log store — it is write-only.
func (s *LogStore) Query(_ context.Context, _ AuditFilter) ([]AuditEntry, error) {
	return nil, ErrQueryNotSupported
}

// Healthy always returns nil for LogStore since slog is always available.
func (s *LogStore) Healthy(_ context.Context) error {
	return nil
}
