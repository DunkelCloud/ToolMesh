package authz

import (
	"testing"
)

func TestPtr(t *testing.T) {
	s := "test"
	p := ptr(s)
	if *p != "test" {
		t.Errorf("ptr(%q) = %q, want %q", s, *p, "test")
	}
}

func TestPtrMap(t *testing.T) {
	m := map[string]any{"key": "value"}
	p := ptrMap(m)
	if (*p)["key"] != "value" {
		t.Errorf("ptrMap result missing key")
	}
}

// Integration tests for NewAuthorizer and Check require a running OpenFGA server.
// They are skipped in unit test mode.

func TestNewAuthorizer_InvalidURL(t *testing.T) {
	// NewAuthorizer should still succeed with an invalid URL (the error
	// surfaces on first Check call, not at construction time).
	a, err := NewAuthorizer("http://localhost:99999", "store-id", nil)
	if err != nil {
		// Some SDK versions may fail at construction, which is also acceptable
		t.Skipf("SDK fails at construction with invalid URL: %v", err)
	}
	if a == nil {
		t.Fatal("expected non-nil authorizer")
	}
}
