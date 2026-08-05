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

package dadl

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// generateUUIDv4 is the only idempotency-key generator defined in spec v0.2.
const generateUUIDv4 = "uuid_v4"

// NewIdempotencyKey generates a fresh idempotency key for one logical tool
// call (spec §6.6). The caller must generate it before the first attempt
// and reuse it for every retry of that call; two distinct calls get
// distinct keys.
func NewIdempotencyKey(cfg *IdempotencyConfig) (string, error) {
	switch cfg.Generate {
	case "", generateUUIDv4:
		return uuid.NewString(), nil
	default:
		// Unreachable for validated specs — validation rejects unknown
		// generators fail-closed (behavior-determining enum, spec §15.3).
		return "", fmt.Errorf("unknown idempotency generator %q", cfg.Generate)
	}
}

// MethodSafeToRetry reports whether the HTTP method is idempotent by HTTP
// semantics (spec §8 retry safety): GET, HEAD, PUT, DELETE.
func MethodSafeToRetry(method string) bool {
	switch strings.ToUpper(method) {
	case httpMethodGET, httpMethodHEAD, httpMethodPUT, httpMethodDELETE:
		return true
	default:
		return false
	}
}

// CanAutoRetry reports whether automatic retries are permitted for the tool
// (spec §8 retry safety): the method is idempotent by HTTP semantics, the
// tool declares idempotency (the reused key makes re-execution safe), or it
// opts in with retry_unsafe. A POST or PATCH with none of these fails on
// the first retryable error instead of being retried.
func CanAutoRetry(tool *ToolDef) bool {
	return MethodSafeToRetry(tool.Method) || tool.Idempotency != nil || tool.RetryUnsafe
}
