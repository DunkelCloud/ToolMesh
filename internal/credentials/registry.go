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
	"fmt"
	"sync"
)

// Factory creates a CredentialStore instance from configuration.
type Factory func(config map[string]string) (CredentialStore, error)

var (
	mu       sync.RWMutex
	registry = make(map[string]Factory)
)

// Register registers a CredentialStore factory under a name.
// Typically called from init().
func Register(name string, factory Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("credentials: store %q already registered", name))
	}
	registry[name] = factory
}

// New creates a CredentialStore instance by its registered name.
func New(name string, config map[string]string) (CredentialStore, error) {
	mu.RLock()
	factory, exists := registry[name]
	mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("credentials: unknown store type %q (registered: %v)", name, Names())
	}
	return factory(config)
}

// Names returns all registered store names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
