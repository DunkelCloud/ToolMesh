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

package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// recordingHandler collects slog.Records so we can assert on what was logged.
type recordingHandler struct {
	records []slog.Record
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(_ string) slog.Handler      { return h }

func TestSanitizeParams(t *testing.T) {
	const redacted = "[REDACTED]"
	got := sanitizeParams(map[string]any{
		"name":          "alice",
		"password":      "hunter2",
		"API_KEY":       "abcd",
		"access_token":  "xyz",
		"refresh_token": "rrr",
	})
	if got["name"] != "alice" {
		t.Errorf("name = %v", got["name"])
	}
	if got["password"] != redacted {
		t.Errorf("password = %v", got["password"])
	}
	if got["API_KEY"] != redacted {
		t.Errorf("API_KEY = %v", got["API_KEY"])
	}
	if got["access_token"] != redacted {
		t.Errorf("access_token = %v", got["access_token"])
	}
	if got["refresh_token"] != redacted {
		t.Errorf("refresh_token = %v", got["refresh_token"])
	}

	// Empty params returns input unchanged.
	if got := sanitizeParams(nil); got != nil {
		t.Errorf("nil params = %v, want nil", got)
	}
}

// TestExecute_DebugLoggingRedactsSecrets verifies that sensitive parameter
// values are redacted in debug log output, not only in audit records.
func TestExecute_DebugLoggingRedactsSecrets(t *testing.T) {
	h := &recordingHandler{}
	logger := slog.New(h)

	mb := &mockBackend{}
	exec := New(nil, nil, mb, nil, nil, 5*time.Second, logger)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "u",
		CompanyID:     "c",
		Authenticated: true,
	})
	_, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
		ToolName: "test:tool",
		Params: map[string]any{
			"username": "alice",
			"password": "plaintext-secret-value",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Scan all records for "plaintext-secret-value" — must not appear.
	for _, r := range h.records {
		r.Attrs(func(a slog.Attr) bool {
			if containsRecursive(a.Value.Any(), "plaintext-secret-value") {
				t.Errorf("secret leaked in log record %q: %v", r.Message, a)
				return false
			}
			return true
		})
	}
}

func containsRecursive(v any, needle string) bool {
	switch x := v.(type) {
	case string:
		return x == needle
	case map[string]any:
		for _, val := range x {
			if containsRecursive(val, needle) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if containsRecursive(val, needle) {
				return true
			}
		}
	}
	return false
}

func TestSplitToolPrefix(t *testing.T) {
	cases := []struct {
		in   string
		want [2]string
	}{
		{"github_create_issue", [2]string{"github", "create_issue"}},
		{"noprefix", [2]string{"", "noprefix"}},
		{"_leading", [2]string{"", "_leading"}},
	}
	for _, c := range cases {
		got := splitToolPrefix(c.in)
		if got != c.want {
			t.Errorf("splitToolPrefix(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// Assert backend.ToolResult isn't accidentally imported as unused.
var _ = backend.ToolResult{}
