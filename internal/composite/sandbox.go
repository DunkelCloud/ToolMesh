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
	"fetch",
	"XMLHttpRequest",
	"require",
	"import",
	"process",
	"fs",
	"os",
	"child_process",
	"globalThis",
	"setTimeout",
	"setInterval",
	"setImmediate",
	"clearTimeout",
	"clearInterval",
	"clearImmediate",
	"window",
	"self",
	"global",
}

// LockdownRuntime removes all dangerous globals from the goja runtime and
// overrides eval/Function with error-returning stubs.
func LockdownRuntime(rt *goja.Runtime) {
	// Delete all blocked globals
	for _, name := range blockedGlobals {
		_ = rt.GlobalObject().Delete(name)
	}

	// Override eval with an error-returning function
	_ = rt.Set("eval", func(call goja.FunctionCall) goja.Value {
		panic(rt.NewGoError(fmt.Errorf("eval is not allowed in composite sandbox")))
	})

	// Override Function constructor with an error-returning function
	_ = rt.Set("Function", func(call goja.FunctionCall) goja.Value {
		panic(rt.NewGoError(fmt.Errorf("function constructor is not allowed in composite sandbox")))
	})

	// Freeze Function.prototype.constructor to prevent prototype-chain bypass:
	//   const F = (function(){}).constructor; F('code')()
	_, _ = rt.RunString(`
		Object.defineProperty(Function.prototype, 'constructor', {
			value: undefined, writable: false, configurable: false
		});
		Object.defineProperty(Object.prototype, 'constructor', {
			value: undefined, writable: false, configurable: false
		});
	`)
}
