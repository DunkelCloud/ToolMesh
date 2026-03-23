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

package gate

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

func TestGate_Evaluate_Authenticated(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "auth.js", `
		if (!ctx.user.authenticated) {
			throw new Error("Unauthenticated request");
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	tests := []struct {
		name    string
		user    userctx.UserContext
		wantErr bool
	}{
		{
			name:    "authenticated user passes",
			user:    userctx.UserContext{UserID: "u1", Authenticated: true},
			wantErr: false,
		},
		{
			name:    "unauthenticated user rejected",
			user:    userctx.UserContext{UserID: "u2", Authenticated: false},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := g.Evaluate(GateContext{
				User:     tt.user,
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed == tt.wantErr {
				t.Errorf("Evaluate() allowed = %v, wantRejected %v", result.Allowed, tt.wantErr)
			}
		})
	}
}

func TestGate_Evaluate_NoPolicies(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1"},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Errorf("expected allowed with no policies, got rejected: %s", result.Reason)
	}
}

func TestGate_Evaluate_MissingDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	g, err := New("/nonexistent/path", logger)
	if err != nil {
		t.Fatalf("expected no error for missing dir, got: %v", err)
	}
	if len(g.policies) != 0 {
		t.Errorf("expected 0 policies, got %d", len(g.policies))
	}
}

func TestRateLimiter_Check(t *testing.T) {
	rl := NewRateLimiter()

	// Should not exceed with limit of 5
	for i := 0; i < 5; i++ {
		if rl.Check("user1", 5) {
			t.Fatalf("should not exceed limit at request %d", i+1)
		}
	}

	// The 6th request should exceed
	if !rl.Check("user1", 5) {
		t.Fatal("should exceed limit at request 6")
	}

	// Different user should not be affected
	if rl.Check("user2", 5) {
		t.Fatal("different user should not be rate limited")
	}
}

func TestGate_PIIProtection(t *testing.T) {
	dir := t.TempDir()
	// Copy the actual PII policy
	piiPolicy, _ := os.ReadFile("policies/pii_protection.js")
	writePolicy(t, dir, "pii.js", string(piiPolicy))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "masks email",
			input:    "Contact us at admin@example.com for help",
			contains: "[EMAIL]",
		},
		{
			name:     "masks credit card",
			input:    "Card: 4111-1111-1111-1111",
			contains: "[CREDIT_CARD]",
		},
		{
			name:     "masks SSN",
			input:    "SSN: 123-45-6789",
			contains: "[SSN]",
		},
		{
			name:     "masks AWS key",
			input:    "Key: AKIAIOSFODNN7EXAMPLE",
			contains: "[AWS_KEY]",
		},
		{
			name:     "preserves clean text",
			input:    "Hello world, everything is fine",
			contains: "Hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := &backend.ToolResult{
				Content: []any{map[string]any{
					"type": "text",
					"text": tt.input,
				}},
			}

			evalResult, err := g.Evaluate(GateContext{
				User:     userctx.UserContext{UserID: "u1", Authenticated: true},
				Tool:     "test_tool",
				Response: result,
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !evalResult.Allowed {
				t.Fatalf("expected allowed, got rejected: %s", evalResult.Reason)
			}

			text := result.Content[0].(map[string]any)["text"].(string)
			if !contains(text, tt.contains) {
				t.Errorf("output %q should contain %q", text, tt.contains)
			}
		})
	}
}

func TestGate_PIIProtection_NoOriginalLeakage(t *testing.T) {
	dir := t.TempDir()
	piiPolicy, _ := os.ReadFile("policies/pii_protection.js")
	writePolicy(t, dir, "pii.js", string(piiPolicy))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, _ := New(dir, logger)

	result := &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": "Email: secret@company.com, Card: 4111 1111 1111 1111",
		}},
	}

	g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test",
		Response: result,
	})

	text := result.Content[0].(map[string]any)["text"].(string)
	if contains(text, "secret@company.com") {
		t.Error("email should have been masked")
	}
	if contains(text, "4111") {
		t.Error("credit card should have been masked")
	}
}

func TestGate_RoleFieldFilter(t *testing.T) {
	dir := t.TempDir()
	rolePolicy, _ := os.ReadFile("policies/role_field_filter.js")
	writePolicy(t, dir, "roles.js", string(rolePolicy))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	jsonContent := `{"name":"John","ssn":"123-45-6789","email":"john@test.com"}`

	// Non-compliance user calling a user tool — ssn should be redacted
	result := &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": jsonContent,
		}},
	}

	evalResult, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Roles: []string{"viewer"}, Authenticated: true},
		Tool:     "user:get_profile",
		Response: result,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !evalResult.Allowed {
		t.Fatalf("expected allowed, got rejected: %s", evalResult.Reason)
	}

	text := result.Content[0].(map[string]any)["text"].(string)
	if contains(text, "123-45-6789") {
		t.Error("SSN should have been redacted for non-compliance user")
	}
	if !contains(text, "[REDACTED]") {
		t.Error("expected [REDACTED] marker in output")
	}
	if !contains(text, "John") {
		t.Error("non-restricted fields should be preserved")
	}
}

func TestGate_RoleFieldFilter_AdminBypass(t *testing.T) {
	dir := t.TempDir()
	rolePolicy, _ := os.ReadFile("policies/role_field_filter.js")
	writePolicy(t, dir, "roles.js", string(rolePolicy))

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, _ := New(dir, logger)

	jsonContent := `{"name":"John","ssn":"123-45-6789"}`

	result := &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": jsonContent,
		}},
	}

	// Admin should see everything
	g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "admin1", Roles: []string{"admin"}, Authenticated: true},
		Tool:     "user:get_profile",
		Response: result,
	})

	text := result.Content[0].(map[string]any)["text"].(string)
	if contains(text, "[REDACTED]") {
		t.Error("admin should not have fields redacted")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && stringContains(s, substr)))
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}
