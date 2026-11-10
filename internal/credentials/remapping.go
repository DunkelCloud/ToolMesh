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
// mapped key through [LookupKey]: from the underlying store when that holds its
// values outside the process environment (the command store), from the
// environment otherwise. Without a remapping it delegates to the underlying
// store.
type RemappingStore struct {
	delegate CredentialStore
	envMap   map[string]string // CanonicalEnvKey(CREDENTIAL_X) → actual env var name
}

// EnvKeyPrefix starts every env: key that remaps a credential.
const EnvKeyPrefix = "CREDENTIAL_"

// CanonicalEnvKey returns the form of an env: key that every reader of the
// env: map compares: trimmed and upper-cased, as the environment variable
// of a credential is named. The remapping and the credential binding of a
// backend both use it, so a key that widens what a backend may read is the
// key that remaps the read.
func CanonicalEnvKey(key string) string {
	return strings.ToUpper(strings.TrimSpace(key))
}

// NewRemappingStore creates a credential store that remaps lookups.
// The envMap keys are the CREDENTIAL_* environment variable names as written
// in backends.yaml, in any case; the values are the actual environment
// variable names to read from. Two keys with the same canonical form remap
// to nothing: a lookup of that credential fails.
func NewRemappingStore(delegate CredentialStore, envMap map[string]string) *RemappingStore {
	m := make(map[string]string, len(envMap))
	clash := map[string]bool{}
	for k, v := range envMap {
		ck := CanonicalEnvKey(k)
		if _, dup := m[ck]; dup {
			clash[ck] = true
		}
		m[ck] = v
	}
	for ck := range clash {
		m[ck] = ""
	}
	return &RemappingStore{delegate: delegate, envMap: m}
}

// Get retrieves a credential, checking the env remapping first.
func (r *RemappingStore) Get(ctx context.Context, logicalName string, tenant TenantInfo) (string, error) {
	envKey := CanonicalEnvKey(EnvKeyPrefix + logicalName)
	if mapped, ok := r.envMap[envKey]; ok {
		val, _ := LookupKey(r.delegate, mapped)
		if val == "" {
			return "", fmt.Errorf("remapped credential %q (key %q) is empty: %w", logicalName, mapped, ErrCredentialNotFound)
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
		val, _ := LookupKey(r.delegate, actualEnvVar)
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
