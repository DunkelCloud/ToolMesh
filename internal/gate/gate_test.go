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
			err := g.Evaluate(GateContext{
				User:     tt.user,
				Tool:     "test_tool",
				Response: &backend.ToolResult{},
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("Evaluate() error = %v, wantErr %v", err, tt.wantErr)
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

	err = g.Evaluate(GateContext{
		User:     userctx.UserContext{UserID: "u1"},
		Tool:     "test_tool",
		Response: &backend.ToolResult{},
	})
	if err != nil {
		t.Errorf("expected no error with no policies, got: %v", err)
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

func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
}
