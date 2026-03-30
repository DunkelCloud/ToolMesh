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

const gojaEvaluatorName = "goja"

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
		{ //nolint:gosec // G101: intentional test data for PII masking
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

func TestGate_Evaluate_PrePhase_BlocksWriteOperation(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "block_writes.js", `
		if (ctx.phase === "pre") {
			if (/^shelly_cloud_set_switch$/.test(ctx.tool)) {
				if (ctx.params && ctx.params.on === false) {
					throw "Turning off devices is not allowed";
				}
			}
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	tests := []struct {
		name    string
		tool    string
		params  map[string]any
		phase   Phase
		wantErr bool
	}{
		{
			name:    "pre phase blocks turn-off",
			tool:    "shelly_cloud_set_switch",
			params:  map[string]any{"on": false, "id": "abc123"},
			phase:   PhasePre,
			wantErr: true,
		},
		{
			name:    "pre phase allows turn-on",
			tool:    "shelly_cloud_set_switch",
			params:  map[string]any{"on": true, "id": "abc123"},
			phase:   PhasePre,
			wantErr: false,
		},
		{
			name:    "post phase ignores params",
			tool:    "shelly_cloud_set_switch",
			params:  map[string]any{"on": false},
			phase:   PhasePost,
			wantErr: false,
		},
		{
			name:    "pre phase allows unrelated tool",
			tool:    "shelly_cloud_get_devices_status",
			params:  map[string]any{},
			phase:   PhasePre,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := g.Evaluate(GateContext{
				User:     userctx.UserContext{UserID: "u1", Authenticated: true},
				Tool:     tt.tool,
				Params:   tt.params,
				Phase:    tt.phase,
				Response: &backend.ToolResult{},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed == tt.wantErr {
				t.Errorf("Evaluate() allowed = %v, wantRejected = %v", result.Allowed, tt.wantErr)
			}
		})
	}
}

func TestGate_Evaluate_PhaseDefaultsToPost(t *testing.T) {
	dir := t.TempDir()
	// Policy that only blocks in pre phase
	writePolicy(t, dir, "pre_only.js", `
		if (ctx.phase === "pre") {
			throw "blocked in pre";
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	// Without phase set, should default to "post" and pass
	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed when phase defaults to post")
	}
}

func TestGate_Evaluate_ParamsAvailableInContext(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "check_params.js", `
		if (ctx.phase === "pre" && ctx.params && ctx.params.channel === 2) {
			throw "channel 2 is restricted";
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	// Channel 2 should be blocked
	result, _ := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "shelly_cloud_set_switch",
		Params:   map[string]any{"channel": 2, "on": true},
		Phase:    PhasePre,
		Response: &backend.ToolResult{},
	})
	if result.Allowed {
		t.Error("expected channel 2 to be blocked")
	}

	// Channel 1 should pass
	result, _ = g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "shelly_cloud_set_switch",
		Params:   map[string]any{"channel": 1, "on": true},
		Phase:    PhasePre,
		Response: &backend.ToolResult{},
	})
	if !result.Allowed {
		t.Error("expected channel 1 to pass")
	}
}

func TestPipeline_EvaluatePre(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "block_pre.js", `
		if (ctx.phase === "pre" && ctx.tool === "dangerous_tool") {
			throw "dangerous tool blocked";
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	p := NewPipeline([]Evaluator{g})

	err = p.EvaluatePre(GateContext{
		User:   userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:   "dangerous_tool",
		Params: map[string]any{},
	})
	if err == nil {
		t.Error("expected EvaluatePre to reject dangerous_tool")
	}

	err = p.EvaluatePost(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "dangerous_tool",
		Params:   map[string]any{},
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Errorf("expected EvaluatePost to pass dangerous_tool, got: %v", err)
	}
}

func TestGate_CallerIDAndCallerClassAvailable(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "caller_class.js", `
		// Verify callerId and callerClass are accessible
		if (ctx.phase === "pre") {
			if (ctx.user.callerClass === "untrusted" && ctx.tool.match(/_(delete|drop|remove)/i)) {
				throw new Error("destructive op blocked for " + ctx.user.callerId + " (class: " + ctx.user.callerClass + ")");
			}
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	tests := []struct {
		name        string
		callerID    string
		callerClass string
		tool        string
		phase       Phase
		wantAllowed bool
	}{
		{
			name:        "untrusted caller blocked on destructive tool",
			callerID:    "anonymous",
			callerClass: "untrusted",
			tool:        "db_delete_user",
			phase:       PhasePre,
			wantAllowed: false,
		},
		{
			name:        "trusted caller allowed on destructive tool",
			callerID:    "claude-code",
			callerClass: "trusted",
			tool:        "db_delete_user",
			phase:       PhasePre,
			wantAllowed: true,
		},
		{
			name:        "untrusted caller allowed on read tool",
			callerID:    "anonymous",
			callerClass: "untrusted",
			tool:        "db_get_user",
			phase:       PhasePre,
			wantAllowed: true,
		},
		{
			name:        "post phase not affected",
			callerID:    "anonymous",
			callerClass: "untrusted",
			tool:        "db_delete_user",
			phase:       PhasePost,
			wantAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := g.Evaluate(GateContext{
				User: userctx.UserContext{
					UserID:        "u1",
					Authenticated: true,
					CallerID:      tt.callerID,
					CallerClass:   tt.callerClass,
				},
				Tool:     tt.tool,
				Params:   map[string]any{},
				Phase:    tt.phase,
				Response: &backend.ToolResult{},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Allowed != tt.wantAllowed {
				t.Errorf("Evaluate() allowed = %v, want %v (reason: %s)", result.Allowed, tt.wantAllowed, result.Reason)
			}
		})
	}
}

func TestGate_evalPolicy_EmptyPolicy(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "empty.js", "")

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("empty policy should allow all requests")
	}
}

func TestGate_evalPolicy_SyntaxError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "bad_syntax.js", `
		function( { broken syntax here !!!
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Syntax errors in goja become JS exceptions, policy should reject
	if result.Allowed {
		t.Error("policy with syntax error should reject request")
	}
}

func TestGate_evalPolicy_PolicyThrowsString(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "throw_string.js", `throw "blocked by string throw";`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("policy throwing string should reject")
	}
	if !contains(result.Reason, "blocked by string throw") {
		t.Errorf("reason should contain thrown string, got: %s", result.Reason)
	}
}

func TestGate_evalPolicy_PolicyThrowsError(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "throw_error.js", `throw new Error("blocked by Error object");`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("policy throwing Error should reject")
	}
	if !contains(result.Reason, "blocked by Error object") {
		t.Errorf("reason should contain Error message, got: %s", result.Reason)
	}
}

func TestGate_evalPolicy_PolicyReturnsWithoutThrowing(t *testing.T) {
	dir := t.TempDir()
	// Policy that does something but does not throw — should allow
	writePolicy(t, dir, "no_throw.js", `
		var x = ctx.tool;
		var y = x.toUpperCase();
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "my_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("policy that does not throw should allow")
	}
}

func TestGate_evalPolicy_PolicyModifiesResponseContent(t *testing.T) {
	dir := t.TempDir()
	// Policy that modifies the response content
	writePolicy(t, dir, "modify.js", `
		if (ctx.response && ctx.response.content) {
			for (var i = 0; i < ctx.response.content.length; i++) {
				if (ctx.response.content[i].type === "text") {
					ctx.response.content[i].text = "REDACTED";
				}
			}
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result := &backend.ToolResult{
		Content: []any{map[string]any{
			"type": "text",
			"text": "sensitive data",
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
		t.Error("policy that modifies content should still allow")
	}

	text := result.Content[0].(map[string]any)["text"].(string)
	if text != "REDACTED" {
		t.Errorf("expected modified content 'REDACTED', got %q", text)
	}
}

func TestGate_evalPolicy_NilResponse(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "check_nil.js", `
		// Policy that accesses ctx but does not require response
		if (ctx.tool === "") {
			throw "empty tool name";
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Allowed {
		t.Error("expected allowed with nil response and non-empty tool")
	}
}

func TestGate_evalPolicy_RateLimitFunction(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "rate_limit.js", `
		if (ctx.rateLimitExceeded(2)) {
			throw "rate limit exceeded";
		}
	`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	ctx := GateContext{
		User:     userctx.UserContext{UserID: "rate-test-user", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	}

	// First two calls should pass (limit is 2)
	for i := 0; i < 2; i++ {
		result, err := g.Evaluate(ctx)
		if err != nil {
			t.Fatalf("unexpected error on call %d: %v", i+1, err)
		}
		if !result.Allowed {
			t.Errorf("call %d should be allowed", i+1)
		}
	}

	// Third call should be rate limited
	result, err := g.Evaluate(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("third call should be rate limited")
	}
}

func TestGate_evalPolicy_MultiplePoliciesShortCircuit(t *testing.T) {
	dir := t.TempDir()
	// First policy allows, second policy blocks
	writePolicy(t, dir, "01_allow.js", `// allows all`)
	writePolicy(t, dir, "02_block.js", `throw "blocked by second policy";`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}

	result, err := g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1", Authenticated: true},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Allowed {
		t.Error("should be blocked by second policy")
	}
}

func TestGate_Name(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}
	if g.Name() != gojaEvaluatorName {
		t.Errorf("expected name 'goja', got %q", g.Name())
	}
}

func TestGate_New_SkipsDirectoriesAndNonJSFiles(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory
	subDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subDir, 0750); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}
	// Create a non-JS file
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("not a policy"), 0600); err != nil {
		t.Fatalf("failed to write txt file: %v", err)
	}
	// Create a JS file
	writePolicy(t, dir, "valid.js", `// valid policy`)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	g, err := New(dir, logger)
	if err != nil {
		t.Fatalf("failed to create gate: %v", err)
	}
	if len(g.policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(g.policies))
	}
}

func TestGate_Init_RegistersGojaEvaluator(t *testing.T) {
	// The init() function in gate.go registers "goja" — verify it exists
	names := EvaluatorNames()
	found := false
	for _, n := range names {
		if n == gojaEvaluatorName {
			found = true
			break
		}
	}
	if !found {
		t.Error("init() should register 'goja' evaluator")
	}
}

func TestGate_Init_GojaFactory_DefaultDir(t *testing.T) {
	// NewEvaluator with "goja" and no policies_dir config should use default
	// The default dir "/app/policies" likely does not exist in test, but the
	// factory should still succeed (missing dir is not an error)
	eval, err := NewEvaluator(gojaEvaluatorName, map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error creating goja evaluator with default dir: %v", err)
	}
	if eval == nil {
		t.Fatal("expected non-nil evaluator")
	}
	if eval.Name() != gojaEvaluatorName {
		t.Errorf("expected name 'goja', got %q", eval.Name())
	}
}

func TestGate_Init_GojaFactory_CustomDir(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "simple.js", `// passes all`)

	eval, err := NewEvaluator(gojaEvaluatorName, map[string]string{"policies_dir": dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval == nil {
		t.Fatal("expected non-nil evaluator")
	}
}

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil { //nolint:gosec // G703: test helper with controlled path
		t.Fatalf("write policy: %v", err)
	}
}
