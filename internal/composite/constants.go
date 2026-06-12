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

package composite

// maxJSCallStackDepth bounds the goja runtime call stack so unbounded JS
// recursion throws a catchable RangeError rather than growing the runtime
// stack toward an out-of-memory condition. The value is well above any
// legitimate composite call depth.
const maxJSCallStackDepth = 2000

// JavaScript identifier names referenced by the sandbox lockdown and the
// AST scanner. Centralized so the goconst linter does not flag each
// occurrence and so the two lists stay in sync.
const (
	jsIdentFetch      = "fetch"
	jsIdentRequire    = "require"
	jsIdentProcess    = "process"
	jsIdentGlobalThis = "globalThis"
	jsIdentSetTimeout = "setTimeout"
	jsIdentWindow     = "window"
	jsIdentSelf       = "self"
)
