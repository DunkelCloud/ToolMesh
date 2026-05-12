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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
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
		Status:      testStatusSuccess,
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
			filter:  AuditFilter{Status: testStatusSuccess},
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
			Status:     testStatusSuccess,
		},
		{
			Tool:       "github_add_comment",
			DurationMs: 15,
			Status:     testStatusError,
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
	entry.Status = testStatusError
	entry.Error = "backend timeout"

	if err := store.Record(ctx, entry); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results, err := store.Query(ctx, AuditFilter{Status: testStatusError})
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

func TestSQLiteStore_ModificationsRoundtrip(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	entry := sampleEntry()
	entry.Modifications = []PolicyModification{
		{
			Policy: "pii_protection.js",
			Phase:  "post",
			Target: ModificationTargetResponseContent,
			Before: json.RawMessage(`[{"type":"text","text":"alice@example.com"}]`),
			After:  json.RawMessage(`[{"type":"text","text":"[EMAIL]"}]`),
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
	got := results[0]
	if len(got.Modifications) != 1 {
		t.Fatalf("expected 1 modification, got %d", len(got.Modifications))
	}
	mod := got.Modifications[0]
	if mod.Policy != "pii_protection.js" {
		t.Errorf("policy = %q, want pii_protection.js", mod.Policy)
	}
	if mod.Target != ModificationTargetResponseContent {
		t.Errorf("target = %q, want %q", mod.Target, ModificationTargetResponseContent)
	}
	if !strings.Contains(string(mod.Before), "alice@example.com") {
		t.Errorf("before missing original email: %s", string(mod.Before))
	}
	if !strings.Contains(string(mod.After), "[EMAIL]") {
		t.Errorf("after missing redaction marker: %s", string(mod.After))
	}
}

func TestSQLiteStore_NoModifications_StoresNull(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	if err := store.Record(ctx, sampleEntry()); err != nil {
		t.Fatalf("Record() error = %v", err)
	}

	results, err := store.Query(ctx, AuditFilter{})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(results))
	}
	if results[0].Modifications != nil {
		t.Errorf("expected nil modifications when none were recorded, got %+v",
			results[0].Modifications)
	}
}

func TestLogStore_EmitsPolicyModificationLineOnlyWhenModified(t *testing.T) {
	// Capture slog output so we can verify which lines were emitted.
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	store := NewLogStore()
	ctx := context.Background()

	// Case 1: unchanged entry — no policy_modification line.
	if err := store.Record(ctx, sampleEntry()); err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if strings.Contains(buf.String(), "audit.policy_modification") {
		t.Errorf("unchanged entry must not produce audit.policy_modification, got: %s", buf.String())
	}
	buf.Reset()

	// Case 2: modified entry — exactly one policy_modification line per mod.
	mod := PolicyModification{
		Policy: "role_field_filter.js",
		Phase:  "post",
		Target: ModificationTargetResponseContent,
		Before: json.RawMessage(`{"secret":"shhh"}`),
		After:  json.RawMessage(`{"secret":"[REDACTED]"}`),
	}
	modified := sampleEntry()
	modified.TraceID = "trace-002"
	modified.Modifications = []PolicyModification{mod}
	if err := store.Record(ctx, modified); err != nil {
		t.Fatalf("Record() modified error = %v", err)
	}

	out := buf.String()
	count := strings.Count(out, `"msg":"audit.policy_modification"`)
	if count != 1 {
		t.Errorf("expected exactly 1 audit.policy_modification line, got %d. Output:\n%s",
			count, out)
	}
	if !strings.Contains(out, "role_field_filter.js") {
		t.Errorf("modification line should reference policy name, got: %s", out)
	}
	if !strings.Contains(out, `"trace_id":"trace-002"`) {
		t.Errorf("modification line should carry trace_id, got: %s", out)
	}
	// The before/after must round-trip through the log unaltered.
	if !strings.Contains(out, `"before":"{\"secret\":\"shhh\"}"`) {
		t.Errorf("expected before JSON in log, got: %s", out)
	}
	if !strings.Contains(out, `"after":"{\"secret\":\"[REDACTED]\"}"`) {
		t.Errorf("expected after JSON in log, got: %s", out)
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
