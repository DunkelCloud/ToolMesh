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

// Package gate implements the Gate — a goja-based JavaScript policy engine
// that evaluates tool calls in two phases: pre-execution (input validation)
// and post-execution (output filtering/masking).
package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/composite"
	"github.com/dop251/goja"
)

func init() {
	RegisterEvaluator("goja", func(config map[string]string) (Evaluator, error) {
		dir := config["policies_dir"]
		if dir == "" {
			dir = "/app/policies"
		}
		logger := slog.Default()
		g, err := New(dir, logger)
		if err != nil {
			return nil, err
		}
		return g, nil
	})
}

// Gate evaluates JavaScript policies against tool results.
type Gate struct {
	policies    []policy
	rateLimiter *RateLimiter
	logger      *slog.Logger
}

type policy struct {
	name   string
	source string
}

// New creates a Gate by loading all .js files from the given directory.
func New(policiesDir string, logger *slog.Logger) (*Gate, error) {
	g := &Gate{
		rateLimiter: NewRateLimiter(),
		logger:      logger,
	}

	entries, err := os.ReadDir(policiesDir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("policies directory not found, running without policies", "dir", policiesDir)
			return g, nil
		}
		return nil, fmt.Errorf("read policies dir %s: %w", policiesDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".js" {
			continue
		}

		path := filepath.Join(policiesDir, entry.Name())
		data, err := os.ReadFile(path) //nolint:gosec // path from trusted policies dir
		if err != nil {
			return nil, fmt.Errorf("read policy %s: %w", path, err)
		}

		g.policies = append(g.policies, policy{
			name:   entry.Name(),
			source: string(data),
		})
		logger.Info("loaded policy", "name", entry.Name())
	}

	return g, nil
}

// Name returns the evaluator name.
func (g *Gate) Name() string {
	return "goja"
}

// Evaluate runs all policies against the given context.
// Policies can modify the response or throw an error to reject the request.
// Returned EvalResult.Modifications captures every before/after mutation
// produced by a policy — one entry per (policy, target) where the JSON
// representation changed. Policies that leave the data untouched produce
// no entries, so an empty list is a positive proof of "no mutation".
func (g *Gate) Evaluate(gctx GateContext) (*EvalResult, error) {
	// Record the request once for rate limiting, separate from the Check call
	// exposed to policies (which is read-only to prevent counter pollution).
	g.rateLimiter.Record(gctx.User.UserID)

	var mods []audit.PolicyModification
	for _, p := range g.policies {
		policyMods, err := g.evalPolicy(p, gctx)
		if err != nil {
			g.logger.Warn("policy rejected request",
				"policy", p.name,
				"tool", gctx.Tool,
				"user", gctx.User.UserID,
				"error", err,
			)
			return &EvalResult{Allowed: false, Reason: fmt.Sprintf("policy %s: %s", p.name, err)}, nil
		}
		if len(policyMods) > 0 {
			mods = append(mods, policyMods...)
		}
	}
	return &EvalResult{Allowed: true, Modifications: mods}, nil
}

// gatePolicyTimeout is the maximum time a gate policy may run before being interrupted.
const gatePolicyTimeout = 5 * time.Second

func (g *Gate) evalPolicy(p policy, gctx GateContext) ([]audit.PolicyModification, error) {
	vm := goja.New()

	// Defense-in-depth: lock down the runtime even though policies are from trusted files
	composite.LockdownRuntime(vm)

	// Set up timeout to prevent infinite loops in policies
	ctx, cancel := context.WithTimeout(context.Background(), gatePolicyTimeout)
	defer cancel()
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			vm.Interrupt(fmt.Errorf("gate policy %s: execution timeout exceeded", p.name))
		}
	}()

	// Marshal the context to a JS-friendly object
	ctxJSON, err := json.Marshal(gctx)
	if err != nil {
		return nil, fmt.Errorf("marshal gate context: %w", err)
	}

	var ctxObj map[string]any
	if err := json.Unmarshal(ctxJSON, &ctxObj); err != nil {
		return nil, fmt.Errorf("unmarshal gate context: %w", err)
	}

	// Snapshot before policy run. We capture the exact JSON the policy will
	// see for params (pre-phase) and response.content (post-phase) so we
	// can diff against the post-run state and emit an audit modification
	// only if the policy actually changed something.
	beforeParams, err := marshalForDiff(ctxObj["params"])
	if err != nil {
		return nil, fmt.Errorf("snapshot params before %s: %w", p.name, err)
	}
	beforeResponseContent, err := snapshotResponseContent(ctxObj)
	if err != nil {
		return nil, fmt.Errorf("snapshot response.content before %s: %w", p.name, err)
	}

	// Add rate limit check function
	userID := gctx.User.UserID
	ctxObj["rateLimitExceeded"] = func(call goja.FunctionCall) goja.Value {
		limit := 100
		if len(call.Arguments) > 0 {
			if v, ok := call.Arguments[0].Export().(int64); ok {
				limit = int(v)
			}
		}
		return vm.ToValue(g.rateLimiter.Check(userID, limit))
	}

	if err := vm.Set("ctx", ctxObj); err != nil {
		return nil, fmt.Errorf("set ctx: %w", err)
	}

	_, err = vm.RunString(p.source)
	if err != nil {
		var jsErr *goja.Exception
		if errors.As(err, &jsErr) {
			return nil, fmt.Errorf("%s", jsErr.Value().String())
		}
		return nil, err
	}

	// Read back the post-run state. Policies can mutate ctx.response.content
	// (mask PII, filter fields) or, by extension, ctx.params. Both targets
	// are checked for changes against the pre-run snapshots.
	exported := exportCtx(vm)
	afterParams, err := marshalForDiff(exported["params"])
	if err != nil {
		return nil, fmt.Errorf("snapshot params after %s: %w", p.name, err)
	}
	afterResponseContent, err := snapshotResponseContent(exported)
	if err != nil {
		return nil, fmt.Errorf("snapshot response.content after %s: %w", p.name, err)
	}

	// Propagate response-content mutations back to the live GateContext so
	// downstream evaluators and the executor observe the masked/filtered
	// content. Done unconditionally for post-phase so a policy that
	// rewrites content blocks (even if the JSON happens to be byte-equal)
	// is still reflected in the live struct.
	if resp, ok := exported["response"].(map[string]any); ok && gctx.Response != nil {
		if content, ok := resp["content"].([]any); ok {
			gctx.Response.Content = content
		}
	}

	var mods []audit.PolicyModification
	if !bytes.Equal(beforeParams, afterParams) {
		mods = append(mods, audit.PolicyModification{
			Policy: p.name,
			Phase:  string(gctx.Phase),
			Target: audit.ModificationTargetParams,
			Before: append(json.RawMessage(nil), beforeParams...),
			After:  append(json.RawMessage(nil), afterParams...),
		})
	}
	if !bytes.Equal(beforeResponseContent, afterResponseContent) {
		mods = append(mods, audit.PolicyModification{
			Policy: p.name,
			Phase:  string(gctx.Phase),
			Target: audit.ModificationTargetResponseContent,
			Before: append(json.RawMessage(nil), beforeResponseContent...),
			After:  append(json.RawMessage(nil), afterResponseContent...),
		})
	}

	return mods, nil
}

// exportCtx returns the post-run ctx object as a map, or an empty map when
// the policy somehow removed or replaced ctx with a non-object value (which
// our lockdown should prevent, but we still degrade gracefully).
func exportCtx(vm *goja.Runtime) map[string]any {
	val := vm.Get("ctx")
	if val == nil {
		return map[string]any{}
	}
	exported, ok := val.Export().(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return exported
}

// snapshotResponseContent returns the JSON encoding of ctx.response.content
// for diffing. A missing or non-array content slot collapses to JSON null,
// so policies that leave it untouched produce byte-equal snapshots.
func snapshotResponseContent(ctxObj map[string]any) ([]byte, error) {
	resp, ok := ctxObj["response"].(map[string]any)
	if !ok {
		return marshalForDiff(nil)
	}
	return marshalForDiff(resp["content"])
}

// marshalForDiff JSON-encodes v for byte-equality diffing. nil collapses to
// the JSON literal null so an absent and a present-but-nil value compare
// equal — matching how the policy sees them.
func marshalForDiff(v any) ([]byte, error) {
	if v == nil {
		return []byte("null"), nil
	}
	return json.Marshal(v)
}
