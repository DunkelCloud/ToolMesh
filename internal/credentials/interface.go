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

// Package credentials provides abstractions for secure credential retrieval.
package credentials

import "context"

// TenantInfo identifies the tenant context for credential lookups.
type TenantInfo struct {
	CompanyID   string
	UserID      string
	Environment string // "production" | "staging"
	CallerID    string
	CallerClass string
}

// CredentialStore is the interface for retrieving credentials by logical name.
type CredentialStore interface {
	// Get retrieves a credential value by its logical name for the given tenant.
	Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error)

	// Healthy checks if the credential store is reachable.
	Healthy(ctx context.Context) error
}

// PrefixLister is an optional interface for credential stores that support
// listing all credentials matching a prefix. Used by the executor to inject
// all credentials for a backend (e.g. CREDENTIAL_GITHUB_API_KEY, CREDENTIAL_GITHUB_TOKEN).
type PrefixLister interface {
	// ListByPrefix returns all credential name→value pairs whose logical name
	// starts with the given prefix. The returned map keys are the full logical
	// names (without the CREDENTIAL_ env prefix).
	ListByPrefix(ctx context.Context, prefix string, tenant TenantInfo) (map[string]string, error)
}
