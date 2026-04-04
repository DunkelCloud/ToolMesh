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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

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
func (g *Gate) Evaluate(gctx GateContext) (*EvalResult, error) {
	// Record the request once for rate limiting, separate from the Check call
	// exposed to policies (which is read-only to prevent counter pollution).
	g.rateLimiter.Record(gctx.User.UserID)

	for _, p := range g.policies {
		if err := g.evalPolicy(p, gctx); err != nil {
			g.logger.Warn("policy rejected request",
				"policy", p.name,
				"tool", gctx.Tool,
				"user", gctx.User.UserID,
				"error", err,
			)
			return &EvalResult{Allowed: false, Reason: fmt.Sprintf("policy %s: %s", p.name, err)}, nil
		}
	}
	return &EvalResult{Allowed: true}, nil
}

// gatePolicyTimeout is the maximum time a gate policy may run before being interrupted.
const gatePolicyTimeout = 5 * time.Second

func (g *Gate) evalPolicy(p policy, gctx GateContext) error {
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
		return fmt.Errorf("marshal gate context: %w", err)
	}

	var ctxObj map[string]any
	if err := json.Unmarshal(ctxJSON, &ctxObj); err != nil {
		return fmt.Errorf("unmarshal gate context: %w", err)
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
		return fmt.Errorf("set ctx: %w", err)
	}

	_, err = vm.RunString(p.source)
	if err != nil {
		var jsErr *goja.Exception
		if errors.As(err, &jsErr) {
			return fmt.Errorf("%s", jsErr.Value().String())
		}
		return err
	}

	// Read back potentially modified response content from the JS context.
	// Policies can mutate ctx.response.content (e.g., mask PII, filter fields).
	val := vm.Get("ctx")
	if val != nil {
		if exported, ok := val.Export().(map[string]any); ok {
			if resp, ok := exported["response"].(map[string]any); ok {
				if content, ok := resp["content"].([]any); ok {
					gctx.Response.Content = content
				}
			}
		}
	}

	return nil
}
