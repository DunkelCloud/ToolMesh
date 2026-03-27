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
