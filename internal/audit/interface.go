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

// Package audit provides a pluggable audit trail for tool executions.
package audit

import (
	"context"
	"errors"
	"time"
)

// AuditEntry represents a single tool execution record.
type AuditEntry struct {
	TraceID     string            `json:"trace_id"`
	Timestamp   time.Time         `json:"timestamp"`
	UserID      string            `json:"user_id"`
	CompanyID   string            `json:"company_id"`
	CallerID    string            `json:"caller_id"`
	CallerClass string            `json:"caller_class"`
	Tool        string            `json:"tool"`
	Params      map[string]any    `json:"params,omitempty"`
	DurationMs  int64             `json:"duration_ms"`
	Status      string            `json:"status"` // "success" | "error" | "denied"
	Error       string            `json:"error,omitempty"`
	Backend     string            `json:"backend"`
	IsComposite bool              `json:"is_composite,omitempty"`
	ChildEvents []AuditEntry      `json:"child_events,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// AuditFilter defines query parameters for audit searches.
type AuditFilter struct {
	UserID      string
	CompanyID   string
	CallerID    string
	CallerClass string
	Tool        string
	Since       time.Time
	Until       time.Time
	Status      string
	Limit       int
}

// AuditStore persists audit entries for tool executions.
type AuditStore interface {
	// Record persists a single audit entry.
	Record(ctx context.Context, entry AuditEntry) error

	// Query returns audit entries matching the given filter.
	// Filter syntax is store-specific (SQL WHERE for sqlite, noop for log).
	Query(ctx context.Context, filter AuditFilter) ([]AuditEntry, error)

	// Healthy returns nil if the store is operational.
	Healthy(ctx context.Context) error
}

// ErrQueryNotSupported is returned by stores that do not support queries (e.g. log store).
var ErrQueryNotSupported = errors.New("audit: query not supported by this store")
