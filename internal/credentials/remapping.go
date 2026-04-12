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

package credentials

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// RemappingStore wraps a CredentialStore and remaps credential lookups via an
// env map. This allows the same DADL file to be used with different credential
// sources (e.g. prod vs staging) by remapping the DADL's credential variable
// names to different environment variables in backends.yaml.
//
// The envMap maps full environment variable names:
//
//	"CREDENTIAL_ANTHROPIC_TOKEN" → "ANTHR_PROD_TOKEN"
//
// When Get() is called for logical name "ANTHROPIC_TOKEN", the store checks
// whether "CREDENTIAL_ANTHROPIC_TOKEN" has a remapping. If so, it reads the
// mapped env var directly. Otherwise it delegates to the underlying store.
type RemappingStore struct {
	delegate CredentialStore
	envMap   map[string]string // CREDENTIAL_X → actual env var name
}

// NewRemappingStore creates a credential store that remaps lookups.
// The envMap keys are the CREDENTIAL_* environment variable names as written
// in backends.yaml; the values are the actual environment variable names to
// read from.
func NewRemappingStore(delegate CredentialStore, envMap map[string]string) *RemappingStore {
	return &RemappingStore{delegate: delegate, envMap: envMap}
}

// Get retrieves a credential, checking the env remapping first.
func (r *RemappingStore) Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error) {
	envKey := "CREDENTIAL_" + strings.ToUpper(logicalName)
	if mapped, ok := r.envMap[envKey]; ok {
		val := os.Getenv(mapped)
		if val == "" {
			return "", fmt.Errorf("remapped credential %q (env %q) is empty: %w", logicalName, mapped, ErrCredentialNotFound)
		}
		return val, nil
	}
	return r.delegate.Get(ctx, logicalName, tenant)
}

// ListByPrefix delegates to the underlying store, then applies remapping
// for any matching entries.
func (r *RemappingStore) ListByPrefix(ctx context.Context, prefix string, tenant TenantInfo) (map[string]string, error) {
	// Get baseline from delegate
	var result map[string]string
	if lister, ok := r.delegate.(PrefixLister); ok {
		var err error
		result, err = lister.ListByPrefix(ctx, prefix, tenant)
		if err != nil {
			return nil, err
		}
	}
	if result == nil {
		result = make(map[string]string)
	}

	// Apply remapped entries that match the prefix
	envPrefix := "CREDENTIAL_" + strings.ToUpper(prefix)
	for credEnvKey, actualEnvVar := range r.envMap {
		if !strings.HasPrefix(credEnvKey, envPrefix) {
			continue
		}
		val := os.Getenv(actualEnvVar)
		if val == "" {
			continue
		}
		logicalName := strings.TrimPrefix(credEnvKey, "CREDENTIAL_")
		result[logicalName] = val
	}

	return result, nil
}

// Healthy delegates to the underlying store.
func (r *RemappingStore) Healthy(ctx context.Context) error {
	return r.delegate.Healthy(ctx)
}
