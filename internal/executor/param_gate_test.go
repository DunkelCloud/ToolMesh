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
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	paramGateString  = "string"
	paramGateBackend = "dev"
	paramGateProject = "project_id"
	paramGateMode    = "mode"
	paramGateTag     = "tag"
	paramGateNote    = "note"
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
					"id": {Type: paramGateString, In: paramGateIn, Required: true},
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
			Name: paramGateBackend, Type: paramGateType, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"set_switch": {Method: paramGatePost, Path: "/switch", Params: map[string]dadl.ParamDef{
					"id": {Type: paramGateString, In: paramGateIn, Required: true},
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
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{paramGateBackend: adapter})
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

// TestExecuteTool_GateSeesStringParamsAsText pins that a number or boolean
// given for a declared string parameter reaches the gate as the text the API
// receives. Left as a number, {"project_id": 42} passed a policy that
// forbids project "42" and still sent DELETE /projects/42.
func TestExecuteTool_GateSeesStringParamsAsText(t *testing.T) {
	type sentRequest struct {
		method, path, mode, tag string
		body                    map[string]any
	}
	var (
		mu   sync.Mutex
		sent []sentRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := sentRequest{method: r.Method, path: r.URL.Path, mode: r.URL.Query().Get(paramGateMode), tag: r.Header.Get(paramGateTag)}
		if r.Method == http.MethodPut {
			if err := json.NewDecoder(r.Body).Decode(&req.body); err != nil {
				t.Errorf("decode request body: %v", err)
			}
		}
		mu.Lock()
		sent = append(sent, req)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	projectID := dadl.ParamDef{Type: paramGateString, In: "path", Required: true}
	spec := &dadl.Spec{
		Spec: paramGateSpec,
		Backend: dadl.BackendDef{
			Name: paramGateBackend, Type: paramGateType, BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				"delete_project": {Method: http.MethodDelete, Path: "/projects/{project_id}", Params: map[string]dadl.ParamDef{
					paramGateProject: projectID,
				}},
				"update_project": {Method: http.MethodPut, Path: "/projects/{project_id}", Params: map[string]dadl.ParamDef{
					paramGateProject: projectID,
					paramGateMode:    {Type: paramGateString, In: "query"},
					paramGateTag:     {Type: paramGateString, In: "header"},
					paramGateNote:    {Type: paramGateString, In: paramGateIn},
				}},
			},
		},
	}
	adapter, err := backend.NewRESTAdapter(spec, nil, slog.Default(), backend.RESTAdapterOptions{AllowPrivateURL: true, Unbound: true})
	if err != nil {
		t.Fatal(err)
	}
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{paramGateBackend: adapter})
	dir := t.TempDir()
	policy := `if (ctx.phase === "pre" && ctx.params) {
		if (ctx.tool === "dev_delete_project") {
			var p = ctx.params.project_id;
			if (p === "42" || p === "4.5" || p === "true" || p === "false") { throw "project " + p + " is protected by policy"; }
		}
		if (ctx.tool === "dev_update_project") {
			var names = ["project_id", "mode", "tag", "note"];
			for (var i = 0; i < names.length; i++) {
				if (typeof ctx.params[names[i]] !== "string") { throw "gate saw " + names[i] + " as " + typeof ctx.params[names[i]]; }
			}
		}
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

	cases := []struct {
		val  any
		want string
	}{
		{float64(42), "42"},
		{4.5, "4.5"},
		{true, "true"},
		{false, "false"},
	}
	for _, c := range cases {
		res, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
			ToolName: "dev_delete_project",
			Params:   map[string]any{paramGateProject: c.val},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError || !strings.Contains(resultText(res), "project "+c.want+" is protected by policy") {
			t.Errorf("project_id %v: want the policy refusal for %q, got %v", c.val, c.want, res.Content)
		}
	}
	mu.Lock()
	deletes := len(sent)
	mu.Unlock()
	if deletes != 0 {
		t.Fatalf("a protected project reached the API: %+v", sent)
	}

	for _, c := range cases {
		res, err := exec.ExecuteTool(ctx, ExecuteToolRequest{
			ToolName: "dev_update_project",
			Params:   map[string]any{paramGateProject: c.val, paramGateMode: c.val, paramGateTag: c.val, paramGateNote: c.val},
		})
		if err != nil {
			t.Fatal(err)
		}
		if res.IsError {
			t.Errorf("update with %v: %v", c.val, res.Content)
			continue
		}
		mu.Lock()
		got := sent[len(sent)-1]
		mu.Unlock()
		if got.method != http.MethodPut || got.path != "/projects/"+c.want || got.mode != c.want || got.tag != c.want {
			t.Errorf("update with %v: request %s %s mode=%q tag=%q, want the text %q in path, query and header",
				c.val, got.method, got.path, got.mode, got.tag, c.want)
		}
		if note, ok := got.body[paramGateNote].(string); !ok || note != c.want {
			t.Errorf("update with %v: body note = %#v, want the string %q", c.val, got.body[paramGateNote], c.want)
		}
	}
}
