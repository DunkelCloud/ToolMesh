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
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// TestSQLiteStore_ToolAccessRoundTrip verifies that the access classification
// is persisted and read back through the SQLite audit store.
func TestSQLiteStore_ToolAccessRoundTrip(t *testing.T) {
	store, err := NewSQLiteStore(t.TempDir(), 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	entry := sampleEntry()
	entry.ToolAccess = "write"

	if err := store.Record(ctx, entry); err != nil {
		t.Fatalf("Record: %v", err)
	}

	got, err := store.Query(ctx, AuditFilter{Tool: entry.Tool, Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("Query returned %d entries, want 1", len(got))
	}
	if got[0].ToolAccess != "write" {
		t.Errorf("ToolAccess = %q, want %q", got[0].ToolAccess, "write")
	}
}

// TestSQLiteStore_ToolAccessMigration creates a legacy schema (without the
// tool_access column), opens the store, and verifies the migration runs and
// new inserts can populate the new column.
func TestSQLiteStore_ToolAccessMigration(t *testing.T) {
	dataDir := t.TempDir()
	dbPath := filepath.Join(dataDir, "audit.db")
	setupCtx := context.Background()

	// Create a legacy schema, deliberately omitting tool_access.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := db.ExecContext(setupCtx, `
		CREATE TABLE audit_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			trace_id      TEXT NOT NULL,
			timestamp     DATETIME NOT NULL,
			user_id       TEXT NOT NULL DEFAULT '',
			company_id    TEXT NOT NULL DEFAULT '',
			caller_id     TEXT NOT NULL DEFAULT '',
			caller_name   TEXT NOT NULL DEFAULT '',
			caller_class  TEXT NOT NULL DEFAULT '',
			tool          TEXT NOT NULL,
			params        TEXT,
			duration_ms   INTEGER NOT NULL DEFAULT 0,
			status        TEXT NOT NULL,
			error         TEXT,
			backend       TEXT NOT NULL DEFAULT '',
			is_composite  INTEGER NOT NULL DEFAULT 0,
			child_events  TEXT,
			metadata      TEXT
		);
	`); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	// Insert a legacy row that has no access classification.
	if _, err := db.ExecContext(setupCtx, `
		INSERT INTO audit_events (trace_id, timestamp, tool, status)
		VALUES ('legacy-1', ?, 'github_list_repos', 'success')
	`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close legacy db: %v", err)
	}

	// Open through the store — this triggers the migration.
	store, err := NewSQLiteStore(dataDir, 90)
	if err != nil {
		t.Fatalf("NewSQLiteStore (post-migration): %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Insert a new record with an access tag — should now succeed.
	entry := sampleEntry()
	entry.TraceID = "post-migration-1"
	entry.ToolAccess = "read"
	if err := store.Record(context.Background(), entry); err != nil {
		t.Fatalf("Record post-migration: %v", err)
	}

	// Query should return both rows; the legacy one must default to "".
	got, err := store.Query(context.Background(), AuditFilter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) < 2 {
		t.Fatalf("Query returned %d entries, want >= 2", len(got))
	}

	var sawLegacy, sawNew bool
	for _, e := range got {
		switch e.TraceID {
		case "legacy-1":
			sawLegacy = true
			if e.ToolAccess != "" {
				t.Errorf("legacy row ToolAccess = %q, want empty", e.ToolAccess)
			}
		case "post-migration-1":
			sawNew = true
			if e.ToolAccess != "read" {
				t.Errorf("post-migration row ToolAccess = %q, want %q", e.ToolAccess, "read")
			}
		}
	}
	if !sawLegacy {
		t.Error("legacy-1 row not returned by Query")
	}
	if !sawNew {
		t.Error("post-migration-1 row not returned by Query")
	}
}
