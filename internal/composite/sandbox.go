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

import (
	"fmt"

	"github.com/dop251/goja"
)

// blockedGlobals lists all global identifiers that must be removed or overridden
// in the goja sandbox before executing composite code.
var blockedGlobals = []string{
	jsIdentFetch,
	"XMLHttpRequest",
	jsIdentRequire,
	"import",
	jsIdentProcess,
	"fs",
	"os",
	"child_process",
	jsIdentGlobalThis,
	jsIdentSetTimeout,
	"setInterval",
	"setImmediate",
	"clearTimeout",
	"clearInterval",
	"clearImmediate",
	jsIdentWindow,
	jsIdentSelf,
	"global",
}

// prototypeFreezeScripts clears the `constructor` reference on the intrinsic
// prototypes so the prototype chain cannot be used to reach the Function
// constructor, e.g. `(function(){}).constructor('code')()` or
// `[].constructor.constructor('code')()`. Each statement runs in its own
// RunString: a parse error in one (e.g. an unsupported literal) must not
// prevent the others from applying, and a surrounding try/catch does not
// catch SyntaxErrors.
var prototypeFreezeScripts = []string{
	`Object.defineProperty(Function.prototype, 'constructor', {value: undefined, writable: false, configurable: false});`,
	`Object.defineProperty(Object.prototype, 'constructor', {value: undefined, writable: false, configurable: false});`,
	// AsyncFunction and GeneratorFunction constructors are reached via their own
	// prototype's `constructor` slot, independent of Function.prototype (H-11).
	`Object.defineProperty((async function(){}).constructor.prototype, 'constructor', {value: undefined, writable: false, configurable: false});`,
	`Object.defineProperty((function*(){}).constructor.prototype, 'constructor', {value: undefined, writable: false, configurable: false});`,
}

// LockdownRuntime removes the dangerous globals from the goja runtime and
// disables dynamic code generation.
//
// Ordering is significant. The prototype-chain neutralization must run while
// the real ECMAScript Function constructor is still the global binding. If the
// global Function were replaced with the Go stub first, `Function.prototype`
// would resolve to the stub's prototype and the defineProperty calls below
// would no longer touch the real intrinsics — leaving `(function(){}).constructor`
// callable. The previous revision set the stubs before the freeze, so the
// constructor reference was never actually cleared; this version closes that
// gap by freezing first and stubbing afterwards.
func LockdownRuntime(rt *goja.Runtime) {
	// Remove all blocked globals.
	for _, name := range blockedGlobals {
		_ = rt.GlobalObject().Delete(name)
	}

	// Clear the constructor reference on the intrinsic prototypes while the real
	// Function constructor is still reachable as the global binding.
	for _, script := range prototypeFreezeScripts {
		_, _ = rt.RunString(script)
	}

	// Only now replace eval and the Function constructor with stubs that report
	// a clear error if composite code calls them directly.
	_ = rt.Set("eval", func(call goja.FunctionCall) goja.Value {
		panic(rt.NewGoError(fmt.Errorf("eval is not allowed in composite sandbox")))
	})
	_ = rt.Set("Function", func(call goja.FunctionCall) goja.Value {
		panic(rt.NewGoError(fmt.Errorf("function constructor is not allowed in composite sandbox")))
	})
}
