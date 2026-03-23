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

func init() {
	Register("embedded", func(_ map[string]string) (CredentialStore, error) {
		return NewEmbeddedStore(), nil
	})
}

// EmbeddedStore implements CredentialStore by reading CREDENTIAL_<name>
// environment variables.
type EmbeddedStore struct{}

// NewEmbeddedStore creates a new EmbeddedStore.
func NewEmbeddedStore() *EmbeddedStore {
	return &EmbeddedStore{}
}

// Get retrieves a credential from environment variables.
// The logical name is uppercased and looked up as CREDENTIAL_<NAME>.
func (s *EmbeddedStore) Get(_ context.Context, logicalName string, _ TenantInfo) (string, error) {
	envKey := "CREDENTIAL_" + strings.ToUpper(logicalName)
	val := os.Getenv(envKey)
	if val == "" {
		return "", fmt.Errorf("credential %q not found (env %s is empty): %w", logicalName, envKey, ErrCredentialNotFound)
	}
	return val, nil
}

// Healthy always returns nil for EmbeddedStore since env vars are always available.
func (s *EmbeddedStore) Healthy(_ context.Context) error {
	return nil
}

// ErrCredentialNotFound is returned when a credential cannot be found.
var ErrCredentialNotFound = fmt.Errorf("credential not found")
