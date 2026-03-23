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
}

// CredentialStore is the interface for retrieving credentials by logical name.
type CredentialStore interface {
	// Get retrieves a credential value by its logical name for the given tenant.
	Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error)

	// Healthy checks if the credential store is reachable.
	Healthy(ctx context.Context) error
}
