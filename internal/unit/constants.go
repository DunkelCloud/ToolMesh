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

package unit

// DefaultMaxCallDepth is the in-process limit for nested api.* calls within
// a single top-level unit invocation. The depth counter increments on every
// cross-backend call that has not yet returned and decrements on completion,
// so it bounds the stack of pending sub-backend invocations rather than the
// total number. Setting it to 16 leaves comfortable headroom for legitimate
// compositions (a unit calls a unit that calls another unit...) while
// guaranteeing termination for accidental cycles. Until unit-in-unit
// dependencies are wired through, this counter only ever reaches 1 in
// practice; it is in place for the eventual nested case.
const DefaultMaxCallDepth = 16

// DefaultMaxAPICalls bounds the cumulative number of api.* calls a single
// top-level unit invocation may perform. This is the runaway-loop safety
// net that fires today, before unit-in-unit nesting exercises the depth
// counter. The dice unit's worst case is roll(10000), which fits.
const DefaultMaxAPICalls = 20000

// AuditFull, AuditCompact, AuditNone are the accepted values for
// ExposeConfig.Audit.
const (
	AuditFull    = "full"
	AuditCompact = "compact"
	AuditNone    = "none"
)

// Default file and directory names used by the loader.
const (
	configFileName = "unit.yaml"
)

// JSON Schema / MCP content shape literals that recur often enough to
// warrant centralization. Kept in one place so the goconst linter stays
// silent and the strings can be grep'd from one location.
const (
	schemaKeyType    = "type"
	schemaTypeObject = "object"
	contentTypeText  = "text"
)
