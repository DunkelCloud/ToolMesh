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

package backend

import (
	"fmt"
	"sync"
)

// BackendFactory creates a ToolBackend instance from configuration.
type BackendFactory func(config map[string]any) (ToolBackend, error)

var (
	backendMu       sync.RWMutex
	backendRegistry = make(map[string]BackendFactory)
)

// Register registers a ToolBackend factory under a name.
// Typically called from init().
func Register(name string, factory BackendFactory) {
	backendMu.Lock()
	defer backendMu.Unlock()
	if _, exists := backendRegistry[name]; exists {
		panic(fmt.Sprintf("backend: %q already registered", name))
	}
	backendRegistry[name] = factory
}

// NewBackend creates a ToolBackend instance by its registered name.
func NewBackend(name string, config map[string]any) (ToolBackend, error) {
	backendMu.RLock()
	factory, exists := backendRegistry[name]
	backendMu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("backend: unknown type %q (registered: %v)", name, BackendNames())
	}
	return factory(config)
}

// BackendNames returns all registered backend names.
func BackendNames() []string {
	backendMu.RLock()
	defer backendMu.RUnlock()
	names := make([]string, 0, len(backendRegistry))
	for name := range backendRegistry {
		names = append(names, name)
	}
	return names
}
