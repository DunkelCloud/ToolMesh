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
	"errors"
	"testing"
	"time"
)

func sampleEntry() AuditEntry {
	return AuditEntry{
		TraceID:     "trace-001",
		Timestamp:   time.Now().UTC().Truncate(time.Second),
		UserID:      "user-1",
		CompanyID:   "acme",
		CallerID:    "claude-code",
		CallerClass: "trusted",
		Tool:        "github_list_issues",
		Params:      map[string]any{"owner": "DunkelCloud", "repo": "ToolMesh"},
		DurationMs:  42,
		Status:      "success",
		Backend:     "github",
	}
}

func TestLogStore_Record(t *testing.T) {
	store := NewLogStore()
	ctx := context.Background()

	if err := store.Record(ctx, sampleEntry()); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
}

func TestLogStore_QueryNotSupported(t *testing.T) {
	store := NewLogStore()
	ctx := context.Background()

	_, err := store.Query(ctx, AuditFilter{})
	if !errors.Is(err, ErrQueryNotSupported) {
		t.Fatalf("Query() error = %v, want ErrQueryNotSupported", err)
	}
}

func TestLogStore_Healthy(t *testing.T) {
	store := NewLogStore()
	if err := store.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
}

func TestSQLiteStore_RecordAndQuery(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	entry := sampleEntry()

	if err := store.Record(ctx, entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	tests := []struct {
		name    string
		filter  AuditFilter
		wantLen int
	}{
		{
			name:    "no filter",
			filter:  AuditFilter{},
			wantLen: 1,
		},
		{
			name:    "by user_id",
			filter:  AuditFilter{UserID: "user-1"},
			wantLen: 1,
		},
		{
			name:    "by company_id",
			filter:  AuditFilter{CompanyID: "acme"},
			wantLen: 1,
		},
		{
			name:    "by tool",
			filter:  AuditFilter{Tool: "github_list_issues"},
			wantLen: 1,
		},
		{
			name:    "by status",
			filter:  AuditFilter{Status: "success"},
			wantLen: 1,
		},
		{
			name:    "by caller_id",
			filter:  AuditFilter{CallerID: "claude-code"},
			wantLen: 1,
		},
		{
			name:    "by caller_class",
			filter:  AuditFilter{CallerClass: "trusted"},
			wantLen: 1,
		},
		{
			name:    "non-matching user",
			filter:  AuditFilter{UserID: "nobody"},
			wantLen: 0,
		},
		{
			name:    "time range includes entry",
			filter:  AuditFilter{Since: time.Now().Add(-time.Hour)},
			wantLen: 1,
		},
		{
			name:    "time range excludes entry",
			filter:  AuditFilter{Since: time.Now().Add(time.Hour)},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := store.Query(ctx, tt.filter)
			if err != nil {
				t.Fatalf("Query() error = %v", err)
			}
			if len(results) != tt.wantLen {
				t.Errorf("Query() returned %d entries, want %d", len(results), tt.wantLen)
			}
		})
	}
}

func TestSQLiteStore_CompositeEntry(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	entry := sampleEntry()
	entry.IsComposite = true
	entry.ChildEvents = []AuditEntry{
		{
			Tool:       "github_get_issue",
			DurationMs: 10,
			Status:     "success",
		},
		{
			Tool:       "github_add_comment",
			DurationMs: 15,
			Status:     "error",
			Error:      "permission denied",
		},
	}

	if err := store.Record(ctx, entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results, err := store.Query(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}
	if !results[0].IsComposite {
		t.Error("expected IsComposite = true")
	}
	if len(results[0].ChildEvents) != 2 {
		t.Errorf("expected 2 child events, got %d", len(results[0].ChildEvents))
	}
}

func TestSQLiteStore_Healthy(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Healthy(context.Background()); err != nil {
		t.Fatalf("Healthy() error = %v", err)
	}
}

func TestSQLiteStore_ErrorEntry(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	entry := sampleEntry()
	entry.Status = "error"
	entry.Error = "backend timeout"

	if err := store.Record(ctx, entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results, err := store.Query(ctx, AuditFilter{Status: "error"})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}
	if results[0].Error != "backend timeout" {
		t.Errorf("expected error = %q, got %q", "backend timeout", results[0].Error)
	}
}

func TestSQLiteStore_QueryLimit(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	for i := 0; i < 10; i++ {
		e := sampleEntry()
		e.TraceID = "trace-" + time.Now().Format("150405.000000000")
		if err := store.Record(ctx, e); err != nil {
			t.Fatalf("Record() error = %v", err)
		}
	}

	results, err := store.Query(ctx, AuditFilter{Limit: 3})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 3 {
		t.Errorf("expected 3 entries with limit, got %d", len(results))
	}
}

func TestRegistry(t *testing.T) {
	// "log" is registered via init()
	names := Names()
	found := false
	for _, n := range names {
		if n == "log" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected 'log' store to be registered")
	}

	store, err := New("log", nil)
	if err != nil {
		t.Fatalf("New('log') error = %v", err)
	}
	if store == nil {
		t.Fatal("New('log') returned nil")
	}

	_, err = New("nonexistent", nil)
	if err == nil {
		t.Fatal("New('nonexistent') should return error")
	}
}
