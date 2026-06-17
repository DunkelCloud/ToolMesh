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

import "context"

// ChildGuard authorizes a nested tool call made from inside a composite before
// it is dispatched. A composite's api.* calls run directly against the owning
// adapter's Execute and therefore do not pass back through the top-level
// executor pipeline; without a guard they would skip the per-tool authorization
// and pre-execution gate that a direct call to the same tool goes through.
//
// CheckChild runs only those two checks (authorization + pre-gate), fail-closed,
// for the canonical "<backend>_<tool>" name. It deliberately does NOT re-run
// credential injection, the post-execution gate, audit recording, or metrics —
// those happen once for the composite as a whole. A non-nil error aborts the
// child call (and thus the composite).
//
// The interface lives in this package so adapters can depend on it without
// importing the executor; the executor implements it.
type ChildGuard interface {
	CheckChild(ctx context.Context, toolName string, params map[string]any) error
}

// childGuardSetter is implemented by backends that can have a ChildGuard
// installed after construction. CompositeBackend.SetChildGuard uses it to
// propagate a guard to every child backend that supports one.
type childGuardSetter interface {
	SetChildGuard(g ChildGuard)
}
