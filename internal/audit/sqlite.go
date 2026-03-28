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
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

const (
	defaultRetentionDays = 90
	cleanupInterval      = 24 * time.Hour
)

func init() {
	Register("sqlite", func(config map[string]string) (AuditStore, error) {
		dataDir := config["data_dir"]
		if dataDir == "" {
			dataDir = "/app/data"
		}
		retentionDays := defaultRetentionDays
		if v, ok := config["retention_days"]; ok {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				retentionDays = n
			}
		}
		return NewSQLiteStore(dataDir, retentionDays)
	})
}

// SQLiteStore implements AuditStore using an append-only SQLite database.
type SQLiteStore struct {
	db            *sql.DB
	retentionDays int
	done          chan struct{}
}

// NewSQLiteStore creates a new SQLiteStore, initializes the schema, and starts
// background cleanup of expired entries.
func NewSQLiteStore(dataDir string, retentionDays int) (*SQLiteStore, error) {
	dbPath := filepath.Join(dataDir, "audit.db")
	db, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("audit sqlite: open %s: %w", dbPath, err)
	}

	if err := createSchema(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit sqlite: create schema: %w", err)
	}

	s := &SQLiteStore{
		db:            db,
		retentionDays: retentionDays,
		done:          make(chan struct{}),
	}

	// Run initial cleanup and start background goroutine.
	if err := s.cleanup(context.Background()); err != nil {
		slog.Warn("audit sqlite: initial cleanup failed", "error", err)
	}
	go s.cleanupLoop()

	return s, nil
}

func createSchema(db *sql.DB) error {
	_, err := db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS audit_events (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			trace_id      TEXT NOT NULL,
			timestamp     DATETIME NOT NULL,
			user_id       TEXT NOT NULL DEFAULT '',
			company_id    TEXT NOT NULL DEFAULT '',
			caller_id     TEXT NOT NULL DEFAULT '',
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

		CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_events(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_company_id ON audit_events(company_id);
		CREATE INDEX IF NOT EXISTS idx_audit_caller_id ON audit_events(caller_id);
		CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_events(tool);
		CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_events(status);
	`)
	return err
}

// Record persists a single audit entry to SQLite.
func (s *SQLiteStore) Record(ctx context.Context, entry AuditEntry) error {
	var paramsJSON, childJSON, metaJSON []byte
	var err error

	if len(entry.Params) > 0 {
		paramsJSON, err = json.Marshal(entry.Params)
		if err != nil {
			return fmt.Errorf("audit sqlite: marshal params: %w", err)
		}
	}
	if len(entry.ChildEvents) > 0 {
		childJSON, err = json.Marshal(entry.ChildEvents)
		if err != nil {
			return fmt.Errorf("audit sqlite: marshal child_events: %w", err)
		}
	}
	if len(entry.Metadata) > 0 {
		metaJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("audit sqlite: marshal metadata: %w", err)
		}
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_events (
			trace_id, timestamp, user_id, company_id, caller_id, caller_class,
			tool, params, duration_ms, status, error, backend,
			is_composite, child_events, metadata
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.TraceID, entry.Timestamp.UTC().Format(time.RFC3339Nano), entry.UserID, entry.CompanyID,
		entry.CallerID, entry.CallerClass, entry.Tool,
		nullableBytes(paramsJSON), entry.DurationMs, entry.Status,
		nullableString(entry.Error), entry.Backend,
		boolToInt(entry.IsComposite), nullableBytes(childJSON), nullableBytes(metaJSON),
	)
	if err != nil {
		return fmt.Errorf("audit sqlite: insert: %w", err)
	}
	return nil
}

// Query returns audit entries matching the given filter.
func (s *SQLiteStore) Query(ctx context.Context, filter AuditFilter) ([]AuditEntry, error) {
	var conditions []string
	var args []any

	if filter.UserID != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if filter.CompanyID != "" {
		conditions = append(conditions, "company_id = ?")
		args = append(args, filter.CompanyID)
	}
	if filter.CallerID != "" {
		conditions = append(conditions, "caller_id = ?")
		args = append(args, filter.CallerID)
	}
	if filter.CallerClass != "" {
		conditions = append(conditions, "caller_class = ?")
		args = append(args, filter.CallerClass)
	}
	if filter.Tool != "" {
		conditions = append(conditions, "tool = ?")
		args = append(args, filter.Tool)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.Until.UTC().Format(time.RFC3339Nano))
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}

	query := "SELECT trace_id, timestamp, user_id, company_id, caller_id, caller_class, tool, params, duration_ms, status, error, backend, is_composite, child_events, metadata FROM audit_events"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY timestamp DESC"

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit) //nolint:gosec // G202: limit is a validated integer, not user input

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("audit sqlite: query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var paramsJSON, childJSON, metaJSON sql.NullString
		var errStr sql.NullString
		var isComposite int
		var ts string

		if err := rows.Scan(
			&e.TraceID, &ts, &e.UserID, &e.CompanyID,
			&e.CallerID, &e.CallerClass, &e.Tool,
			&paramsJSON, &e.DurationMs, &e.Status,
			&errStr, &e.Backend, &isComposite,
			&childJSON, &metaJSON,
		); err != nil {
			return nil, fmt.Errorf("audit sqlite: scan: %w", err)
		}

		e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		e.IsComposite = isComposite != 0
		if errStr.Valid {
			e.Error = errStr.String
		}
		if paramsJSON.Valid && paramsJSON.String != "" {
			_ = json.Unmarshal([]byte(paramsJSON.String), &e.Params)
		}
		if childJSON.Valid && childJSON.String != "" {
			_ = json.Unmarshal([]byte(childJSON.String), &e.ChildEvents)
		}
		if metaJSON.Valid && metaJSON.String != "" {
			_ = json.Unmarshal([]byte(metaJSON.String), &e.Metadata)
		}

		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Healthy checks whether the SQLite database is accessible.
func (s *SQLiteStore) Healthy(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *SQLiteStore) cleanup(ctx context.Context) error {
	cutoff := time.Now().AddDate(0, 0, -s.retentionDays).UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, "DELETE FROM audit_events WHERE timestamp < ?", cutoff)
	if err != nil {
		return fmt.Errorf("audit sqlite: cleanup: %w", err)
	}
	return nil
}

// Close stops the background cleanup goroutine and closes the database.
func (s *SQLiteStore) Close() error {
	close(s.done)
	return s.db.Close()
}

func (s *SQLiteStore) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.cleanup(context.Background()); err != nil {
				slog.Warn("audit sqlite: periodic cleanup failed", "error", err)
			}
		}
	}
}

func nullableString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullableBytes(b []byte) sql.NullString {
	if len(b) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{String: string(b), Valid: true}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
