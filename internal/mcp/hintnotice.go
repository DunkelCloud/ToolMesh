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

package mcp

import (
	"context"
	"strings"
	"sync"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// maxTrackedHintPrincipals bounds the first-use ledger so a long-lived server
// cannot grow it without limit. See [hintNotifier.markFirstUse] for what
// happens on overflow.
const maxTrackedHintPrincipals = 10000

// hintNoticePrefix labels the notice as gateway metadata rather than part of
// the backend's own response.
const hintNoticePrefix = "[ToolMesh note: "

// hintNotifier delivers a backend's configured hint (backends.yaml `hint:`)
// on the first tool call a principal makes into that backend.
//
// The hint text is also folded into the execute_code tool description, but
// that channel does not scale: with a few dozen backends the combined string
// is long enough that clients truncate it, and every hint past the cut is
// never seen. Attaching the hint to the call itself delivers it in full, at
// the moment it is relevant, to whoever is actually using the backend.
//
// Delivery is best-effort by design. A missed or repeated notice costs a few
// tokens and nothing else, which is why the ledger below may be keyed
// coarsely and dropped wholesale — no correctness rests on it.
type hintNotifier struct {
	resolver   backend.BackendNameResolver
	summarizer backend.BackendSummarizer

	mu   sync.Mutex
	seen map[string]struct{}
}

// newHintNotifier returns a notifier when the backend can both resolve a
// tool's owning backend and report per-backend hints. It returns nil
// otherwise; a nil *hintNotifier is usable and never emits a notice.
func newHintNotifier(back backend.ToolBackend) *hintNotifier {
	resolver, hasResolver := back.(backend.BackendNameResolver)
	summarizer, hasSummaries := back.(backend.BackendSummarizer)
	if !hasResolver || !hasSummaries {
		return nil
	}
	return &hintNotifier{
		resolver:   resolver,
		summarizer: summarizer,
		seen:       make(map[string]struct{}),
	}
}

// noticeFor returns the notice to attach to a call of toolName, or an empty
// string when the owning backend has no hint configured or this principal has
// already been told. Safe to call on a nil receiver.
func (n *hintNotifier) noticeFor(ctx context.Context, toolName string) string {
	if n == nil {
		return ""
	}
	backendName, ok := n.resolver.ResolveBackendName(toolName)
	if !ok {
		return ""
	}
	hint := n.hintFor(backendName)
	if hint == "" {
		return ""
	}
	if !n.markFirstUse(principalKey(ctx) + "\x00" + backendName) {
		return ""
	}
	return hintNoticePrefix + backendName + "] " + hint
}

// hintFor returns the configured hint for a backend, or an empty string. The
// summaries are read live on every call rather than cached at construction so
// a hot-reloaded backend set takes effect immediately.
func (n *hintNotifier) hintFor(backendName string) string {
	for _, info := range n.summarizer.BackendSummaries() {
		if info.Name == backendName {
			return strings.TrimSpace(info.Hint)
		}
	}
	return ""
}

// markFirstUse records key in the ledger and reports whether this call was the
// first for it. On overflow the whole ledger is dropped rather than evicted
// entry by entry: the only consequence is that some principals see a notice a
// second time, which is cheaper than the bookkeeping an LRU would cost.
func (n *hintNotifier) markFirstUse(key string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if _, seen := n.seen[key]; seen {
		return false
	}
	if len(n.seen) >= maxTrackedHintPrincipals {
		n.seen = make(map[string]struct{})
	}
	n.seen[key] = struct{}{}
	return true
}

// principalKey identifies who the ledger is kept per. MCP has no protocol
// session to bind to — the 2026-07-28 revision removed sessions outright — so
// the authenticated user, falling back to the verified caller, is the finest
// grain available. Unauthenticated calls share one bucket.
func principalKey(ctx context.Context) string {
	uc := userctx.FromContext(ctx)
	if uc == nil {
		return ""
	}
	if uc.UserID != "" {
		return uc.UserID
	}
	return uc.CallerID
}
