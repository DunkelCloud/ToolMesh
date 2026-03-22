// Package credentials provides abstractions for secure credential retrieval.
package credentials

import "context"

// TenantInfo identifies the tenant context for credential lookups.
type TenantInfo struct {
	CompanyID   string
	UserID      string
	Environment string // "production" | "staging"
}

// CredentialStore is the interface for retrieving credentials by logical name.
type CredentialStore interface {
	// Get retrieves a credential value by its logical name for the given tenant.
	Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error)

	// Healthy checks if the credential store is reachable.
	Healthy(ctx context.Context) error
}
