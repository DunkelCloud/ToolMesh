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

package executor

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	paramGateIn    = "body"
	paramGateSpec  = "https://dadl.ai/spec/dadl-spec-v0.2.md"
	paramGateType  = "rest"
	paramGatePost  = "POST"
	paramGateLimit = "limit"
)

// TestExecuteTool_TypeCheckBeforeGate pins that a declared boolean cannot be
// passed as the string "false" to slip past a policy that blocks false: the
// argument check runs before the pre-execution gate and the API is never
// called.
func TestExecuteTool_TypeCheckBeforeGate(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: paramGateSpec,
		Backend: dadl.BackendDef{
			Name:    "shelly-cloud",
			Type:    paramGateType,
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"set_switch": {Method: paramGatePost, Path: "/switch", Params: map[string]dadl.ParamDef{
					"id": {Type: "string", In: paramGateIn, Required: true},
					"on": {Type: "boolean", In: paramGateIn, Required: true},
				}},
			},
		},
	}
	adapter, err := backend.NewRESTAdapter(spec, nil, slog.Default(), backend.RESTAdapterOptions{AllowPrivateURL: true, Unbound: true})
	if err != nil {
		t.Fatal(err)
	}
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{"shelly-cloud": adapter})

	dir := t.TempDir()
	// The second rule shows whether the gate ever sees the string form.
	policy := `if (ctx.phase === "pre" && ctx.tool === "shelly-cloud_set_switch" && ctx.params) {
		if (ctx.params.on === false) { throw "Turning off devices is not allowed by policy"; }
		if (ctx.params.on === "false") { throw "gate saw the string form"; }
	}`
	if err := os.WriteFile(filepath.Join(dir, "shelly.js"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	exec := New(nil, nil, comp, gate.NewPipeline([]gate.Evaluator{g}), &recordingAudit{}, 30*time.Second, newTestLogger(), nil, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testUserID, Authenticated: true})

	call := func(on any) *backend.ToolResult {
		t.Helper()
		res, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
			ToolName: "shelly-cloud_set_switch",
			Params:   map[string]any{"id": "dev1", "on": on},
		})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}

	if res := call(false); !res.IsError || !strings.Contains(resultText(res), "not allowed by policy") {
		t.Fatalf("boolean false: want the policy refusal, got %v", res.Content)
	}
	if res := call("false"); !res.IsError || !strings.Contains(resultText(res), `must be boolean`) {
		t.Fatalf(`string "false": want a type error, got %v`, res.Content)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("API was called %d times, want 0", n)
	}
	if res := call(true); res.IsError {
		t.Fatalf("boolean true should pass: %v", res.Content)
	}
}

// TestExecuteTool_GateSeesEffectiveParams pins that the gate sees the
// arguments the API receives: a declared default the caller left out, and a
// numeric string as the number it is sent as.
func TestExecuteTool_GateSeesEffectiveParams(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: paramGateSpec,
		Backend: dadl.BackendDef{
			Name: "dev", Type: paramGateType, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"set_switch": {Method: paramGatePost, Path: "/switch", Params: map[string]dadl.ParamDef{
					"id": {Type: "string", In: paramGateIn, Required: true},
					"on": {Type: "boolean", In: paramGateIn, Default: false},
				}},
				"set_limit": {Method: "GET", Path: "/limit", Params: map[string]dadl.ParamDef{
					paramGateLimit: {Type: "integer", In: "query", Required: true},
				}},
			},
		},
	}
	adapter, err := backend.NewRESTAdapter(spec, nil, slog.Default(), backend.RESTAdapterOptions{AllowPrivateURL: true, Unbound: true})
	if err != nil {
		t.Fatal(err)
	}
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{"dev": adapter})
	dir := t.TempDir()
	policy := `if (ctx.phase === "pre" && ctx.params) {
		if (ctx.tool === "dev_set_switch" && ctx.params.on === false) { throw "off is not allowed by policy"; }
		if (ctx.tool === "dev_set_limit" && ctx.params.limit === 0) { throw "limit 0 is not allowed by policy"; }
	}`
	if err := os.WriteFile(filepath.Join(dir, "p.js"), []byte(policy), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatal(err)
	}
	exec := New(nil, nil, comp, gate.NewPipeline([]gate.Evaluator{g}), &recordingAudit{}, 30*time.Second, newTestLogger(), nil, nil)
	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testUserID, Authenticated: true})

	for _, c := range []struct {
		tool   string
		params map[string]any
	}{
		{"dev_set_switch", map[string]any{"id": "d1"}},
		{"dev_set_limit", map[string]any{paramGateLimit: "0"}},
		{"dev_set_limit", map[string]any{paramGateLimit: "+0"}},
	} {
		res, err := exec.ExecuteTool(ctx, ExecuteToolRequest{ToolName: c.tool, Params: c.params})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(resultText(res), "not allowed by policy") {
			t.Errorf("%s %v: want the policy refusal, got %v", c.tool, c.params, res.Content)
		}
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("API was called %d times, want 0", n)
	}
}
