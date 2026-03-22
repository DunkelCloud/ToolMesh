package credentials

import (
	"context"
	"errors"
	"testing"
)

func TestEmbeddedStore_Get(t *testing.T) {
	store := NewEmbeddedStore()
	ctx := context.Background()
	tenant := TenantInfo{CompanyID: "acme", UserID: "user1", Environment: "production"}

	tests := []struct {
		name       string
		envKey     string
		envValue   string
		logical    string
		wantValue  string
		wantErr    bool
		wantNotFound bool
	}{
		{
			name:      "existing credential",
			envKey:    "CREDENTIAL_MY_API_KEY",
			envValue:  "secret-123",
			logical:   "MY_API_KEY",
			wantValue: "secret-123",
		},
		{
			name:      "lowercase logical name gets uppercased",
			envKey:    "CREDENTIAL_BRAVE_API_KEY",
			envValue:  "BSA-test",
			logical:   "brave_api_key",
			wantValue: "BSA-test",
		},
		{
			name:         "missing credential",
			logical:      "NONEXISTENT_KEY",
			wantErr:      true,
			wantNotFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envKey != "" {
				t.Setenv(tt.envKey, tt.envValue)
			}

			val, err := store.Get(ctx, tt.logical, tenant)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.wantNotFound && !errors.Is(err, ErrCredentialNotFound) {
					t.Errorf("expected ErrCredentialNotFound, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if val != tt.wantValue {
				t.Errorf("got %q, want %q", val, tt.wantValue)
			}
		})
	}
}

func TestEmbeddedStore_Healthy(t *testing.T) {
	store := NewEmbeddedStore()
	if err := store.Healthy(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
