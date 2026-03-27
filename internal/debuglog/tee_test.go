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

package debuglog

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestTeeHandler_BothReceiveRecord(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	tee := NewTeeHandler(ph, &secondary)
	logger := slog.New(tee)

	logger.Info("hello", "key", "value")

	if !strings.Contains(primary.String(), "hello") {
		t.Error("primary handler did not receive record")
	}
	if !strings.Contains(secondary.String(), "hello") {
		t.Error("secondary handler did not receive record")
	}
}

func TestTeeHandler_DebugOnlyInSecondary(t *testing.T) {
	var primary, secondary bytes.Buffer

	// Primary at Info level, secondary at Debug level (via NewTeeHandler).
	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelInfo})
	tee := NewTeeHandler(ph, &secondary)
	logger := slog.New(tee)

	logger.Debug("debug-only-msg")

	if strings.Contains(primary.String(), "debug-only-msg") {
		t.Error("primary handler should not receive debug record at info level")
	}
	if !strings.Contains(secondary.String(), "debug-only-msg") {
		t.Error("secondary handler should receive debug record")
	}
}

func TestTeeHandler_WithAttrs(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	tee := NewTeeHandler(ph, &secondary)
	logger := slog.New(tee).With("backend", "github")

	logger.Info("test")

	if !strings.Contains(primary.String(), "github") {
		t.Error("primary handler missing WithAttrs attribute")
	}
	if !strings.Contains(secondary.String(), "github") {
		t.Error("secondary handler missing WithAttrs attribute")
	}
}

func TestTeeHandler_WithGroup(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	tee := NewTeeHandler(ph, &secondary)
	logger := slog.New(tee).WithGroup("mygroup")

	logger.Info("grouped", "k", "v")

	if !strings.Contains(primary.String(), "mygroup") {
		t.Error("primary handler missing group")
	}
	if !strings.Contains(secondary.String(), "mygroup") {
		t.Error("secondary handler missing group")
	}
}

func TestTeeHandler_Enabled(t *testing.T) {
	var buf bytes.Buffer

	// Primary only accepts Error, secondary accepts Debug.
	ph := slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})
	tee := NewTeeHandler(ph, &buf)

	ctx := context.Background()

	if !tee.Enabled(ctx, slog.LevelDebug) {
		t.Error("should be enabled at debug (secondary accepts it)")
	}
	if !tee.Enabled(ctx, slog.LevelError) {
		t.Error("should be enabled at error (both accept it)")
	}
}

func TestFilteredTeeHandler_MatchingBackend(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	allowed := map[string]bool{"github": true}
	filtered := NewFilteredTeeHandler(ph, &secondary, allowed)
	logger := slog.New(filtered)

	logger.Info("matched", "backend", "github", "tool", "create_pull")

	if !strings.Contains(primary.String(), "matched") {
		t.Error("primary should always receive record")
	}
	if !strings.Contains(secondary.String(), "matched") {
		t.Error("secondary should receive record for matching backend")
	}
}

func TestFilteredTeeHandler_NonMatchingBackend(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	allowed := map[string]bool{"github": true}
	filtered := NewFilteredTeeHandler(ph, &secondary, allowed)
	logger := slog.New(filtered)

	logger.Info("filtered-out", "backend", "fetch_url", "count", 3)

	if !strings.Contains(primary.String(), "filtered-out") {
		t.Error("primary should always receive record")
	}
	if strings.Contains(secondary.String(), "filtered-out") {
		t.Error("secondary should NOT receive record for non-matching backend")
	}
}

func TestFilteredTeeHandler_NoBackendAttr(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	allowed := map[string]bool{"github": true}
	filtered := NewFilteredTeeHandler(ph, &secondary, allowed)
	logger := slog.New(filtered)

	logger.Info("no-backend", "key", "value")

	if !strings.Contains(primary.String(), "no-backend") {
		t.Error("primary should always receive record")
	}
	if strings.Contains(secondary.String(), "no-backend") {
		t.Error("secondary should NOT receive record without backend attr")
	}
}

func TestFilteredTeeHandler_WithAttrsMatch(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	allowed := map[string]bool{"github": true}
	filtered := NewFilteredTeeHandler(ph, &secondary, allowed)

	// Simulate a child logger with a pre-set matching backend attr.
	logger := slog.New(filtered).With("backend", "github")
	logger.Info("via-with")

	if !strings.Contains(secondary.String(), "via-with") {
		t.Error("secondary should receive record when WithAttrs matched backend")
	}
}

func TestFilteredTeeHandler_WithAttrsNoMatch(t *testing.T) {
	var primary, secondary bytes.Buffer

	ph := slog.NewTextHandler(&primary, &slog.HandlerOptions{Level: slog.LevelDebug})
	allowed := map[string]bool{"github": true}
	filtered := NewFilteredTeeHandler(ph, &secondary, allowed)

	logger := slog.New(filtered).With("backend", "fetch_url")
	logger.Info("via-with-nomatch")

	if strings.Contains(secondary.String(), "via-with-nomatch") {
		t.Error("secondary should NOT receive record when WithAttrs did not match")
	}
}
