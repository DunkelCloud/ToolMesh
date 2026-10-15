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

package authz

import (
	"sync/atomic"
	"time"

	"github.com/openfga/openfga/pkg/storage"
	"github.com/openfga/openfga/pkg/storage/cache/keys"
)

// epochCache scopes every key of the OpenFGA check cache to an epoch, so
// that bumping the epoch invalidates all entries at once. OpenFGA's own cache
// controller invalidates eventually and asynchronously; Apply needs a revoked
// grant to stop working before it returns. Entries of earlier epochs are
// never read again and age out of the underlying LRU.
type epochCache struct {
	inner storage.InMemoryCache[any]
	epoch atomic.Uint64
}

var _ storage.InMemoryCache[any] = (*epochCache)(nil)

func (c *epochCache) scoped(k keys.Key) keys.Key {
	var kb keys.Builder
	kb.EncodeUint64(c.epoch.Load())
	_, _ = kb.Write(k.Bytes())
	return kb.Key()
}

// Get returns the entry for key in the current epoch, or nil.
func (c *epochCache) Get(key keys.Key) any { return c.inner.Get(c.scoped(key)) }

// Set stores an entry for key in the current epoch.
func (c *epochCache) Set(key keys.Key, value any, ttl time.Duration) {
	c.inner.Set(c.scoped(key), value, ttl)
}

// Delete removes the entry for key in the current epoch.
func (c *epochCache) Delete(key keys.Key) { c.inner.Delete(c.scoped(key)) }

// Stop releases the underlying cache.
func (c *epochCache) Stop() { c.inner.Stop() }

// invalidate makes every entry written so far unreachable.
func (c *epochCache) invalidate() { c.epoch.Add(1) }
