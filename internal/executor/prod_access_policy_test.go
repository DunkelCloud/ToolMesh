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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	prodAccessPolicyFile = "prod-access-by-caller-class.js"
	prodAccessPolicyDir  = "../../config/policies/examples"

	prodClassTrusted    = "trusted"
	prodClassStandard   = "standard"
	prodClassRestricted = "restricted"

	prodBackendAPI    = "api"
	prodToolUnknown   = "github_unknown"
	prodToolList      = "list_items"
	prodToolPurge     = "purge_items"
	prodCompositeName = "purge_all"
	prodAccessDanger  = "dangerous"
)

// prodAccessCredStore satisfies the REST adapter; the fixture backend has no
// auth section, so nothing is ever looked up.
type prodAccessCredStore struct{}

func (prodAccessCredStore) Get(_ context.Context, _ string, _ credentials.TenantInfo) (string, error) {
	return "", nil
}
func (prodAccessCredStore) Healthy(_ context.Context) error { return nil }

// newProdAccessGate loads the shipped prod-access-by-caller-class.js example
// policy into a gate pipeline, exactly the file an operator copies to
// production.
func newProdAccessGate(t *testing.T) *gate.Pipeline {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(prodAccessPolicyDir, prodAccessPolicyFile)) //nolint:gosec // G304: fixed path inside the repository
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prodAccessPolicyFile), src, 0o600); err != nil { //nolint:gosec // G703: test helper with controlled path
		t.Fatalf("write policy: %v", err)
	}
	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return gate.NewPipeline([]gate.Evaluator{g})
}

func prodAccessCtx(class string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        testUserID,
		Authenticated: true,
		CallerID:      "caller-" + class,
		CallerClass:   class,
	})
}

func prodAccessText(t *testing.T, res *backend.ToolResult) string {
	t.Helper()
	if res == nil || len(res.Content) == 0 {
		t.Fatal("empty tool result")
	}
	item, ok := res.Content[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected content block %T", res.Content[0])
	}
	text, _ := item[contentKeyText].(string)
	return text
}

// TestProdAccessPolicy_UnclassifiedToolDenied runs a tool the backend knows
// nothing about (so lookupToolAccess yields "") through the executor with the
// production policy: every caller class is denied before the backend is
// called, and the denial names the reason, while a classified read tool
// passes for the same callers.
func TestProdAccessPolicy_UnclassifiedToolDenied(t *testing.T) {
	calls := 0
	be := &accessAwareBackend{
		mockBackend: mockBackend{executeFunc: func(_ context.Context, _ string, _ map[string]any) (*backend.ToolResult, error) {
			calls++
			return &backend.ToolResult{Content: []any{map[string]any{contentKeyType: contentKeyText, contentKeyText: "ok"}}}, nil
		}},
		access: map[string]string{testGitHubListRepos: testAccessRead},
	}
	exec := New(nil, nil, be, newProdAccessGate(t), nil, 30*time.Second, newTestLogger(), nil, nil)

	for _, class := range []string{prodClassTrusted, prodClassStandard, prodClassRestricted, testCallerUntrusted} {
		res, err := exec.ExecuteTool(prodAccessCtx(class), ExecuteToolRequest{ToolName: prodToolUnknown})
		if err != nil {
			t.Fatalf("%s: ExecuteTool: %v", class, err)
		}
		if !res.IsError {
			t.Fatalf("%s: unclassified tool must be denied", class)
		}
		text := prodAccessText(t, res)
		for _, part := range []string{"Gate rejected (pre-execution)", prodToolUnknown, `caller class "` + class + `"`, "no access classification"} {
			if !strings.Contains(text, part) {
				t.Errorf("%s: denial %q does not contain %q", class, text, part)
			}
		}
	}
	if calls != 0 {
		t.Fatalf("backend was called %d times for a denied tool", calls)
	}

	res, err := exec.ExecuteTool(prodAccessCtx(testCallerUntrusted), ExecuteToolRequest{ToolName: testGitHubListRepos})
	if err != nil {
		t.Fatalf("read tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("read tool denied for untrusted caller: %s", prodAccessText(t, res))
	}
	if calls != 1 {
		t.Fatalf("backend calls = %d, want 1", calls)
	}
}

// TestProdAccessPolicy_CompositeChildrenSeeSameAccess wires a DADL backend
// behind the composite backend with the executor as child guard — the
// production wiring — and runs a composite classified read whose code calls
// a dangerous primitive. The policy sees the composite's own access on the
// top-level call and the primitive's access on the api.* child call, the
// same value a direct call to that primitive gets, so a caller who may not
// call the primitive directly cannot reach it through the composite either.
func TestProdAccessPolicy_CompositeChildrenSeeSameAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok": true}`))
	}))
	defer srv.Close()

	spec := &dadl.Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.2.md",
		Backend: dadl.BackendDef{
			Name:    prodBackendAPI,
			Type:    "rest",
			BaseURL: srv.URL,
			Tools: map[string]dadl.ToolDef{
				prodToolList:  {Method: "GET", Path: "/items", Access: testAccessRead},
				prodToolPurge: {Method: "POST", Path: "/purge", Access: prodAccessDanger},
			},
			Composites: map[string]dadl.CompositeDef{
				prodCompositeName: {
					Description: "List, then purge",
					Access:      testAccessRead,
					Code:        "await api.list_items(); await api.purge_items(); return \"purged\";",
					Timeout:     "5s",
				},
			},
		},
	}
	adapter, err := backend.NewRESTAdapter(spec, prodAccessCredStore{}, newTestLogger(), backend.RESTAdapterOptions{AllowPrivateURL: true})
	if err != nil {
		t.Fatalf("NewRESTAdapter: %v", err)
	}
	comp := backend.NewCompositeBackend(map[string]backend.ToolBackend{prodBackendAPI: adapter})
	exec := New(nil, nil, comp, newProdAccessGate(t), nil, 30*time.Second, newTestLogger(), nil, nil)
	comp.SetChildGuard(exec)

	canonical := func(tool string) string { return prodBackendAPI + "_" + tool }

	// The access the gate is handed is the same whether the tool is called
	// directly or reached as a composite child: both resolve through
	// CompositeBackend.LookupTool, and discovery now lists the same value.
	tools, err := comp.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	listed := map[string]string{}
	for _, d := range tools {
		listed[d.Name] = d.Access
	}
	for tool, want := range map[string]string{
		canonical(prodToolList):      testAccessRead,
		canonical(prodToolPurge):     prodAccessDanger,
		canonical(prodCompositeName): testAccessRead,
	} {
		if got := exec.lookupToolAccess(tool); got != want {
			t.Errorf("gate access for %s = %q, want %q", tool, got, want)
		}
		if got := listed[tool]; got != want {
			t.Errorf("discovery access for %s = %q, want %q", tool, got, want)
		}
	}

	// A standard caller may run the read composite, but its dangerous child
	// is denied by the same rule that denies the direct call; the composite
	// fails closed and surfaces the reason.
	res, err := exec.ExecuteTool(prodAccessCtx(prodClassStandard), ExecuteToolRequest{ToolName: canonical(prodCompositeName)})
	if err != nil {
		t.Fatalf("composite: %v", err)
	}
	if !res.IsError {
		t.Fatal("composite with a dangerous child must fail closed for a standard caller")
	}
	viaComposite := prodAccessText(t, res)

	res, err = exec.ExecuteTool(prodAccessCtx(prodClassStandard), ExecuteToolRequest{ToolName: canonical(prodToolPurge)})
	if err != nil {
		t.Fatalf("direct: %v", err)
	}
	if !res.IsError {
		t.Fatal("direct call to the dangerous tool must be denied for a standard caller")
	}
	direct := prodAccessText(t, res)

	reason := `tool ` + canonical(prodToolPurge) + ` denied for caller class "` + prodClassStandard + `": access class "dangerous" is not allowed`
	for name, text := range map[string]string{"composite child": viaComposite, "direct call": direct} {
		if !strings.Contains(text, reason) {
			t.Errorf("%s: %q does not contain %q", name, text, reason)
		}
	}

	// A trusted caller passes the top-level gate and every child gate.
	res, err = exec.ExecuteTool(prodAccessCtx(prodClassTrusted), ExecuteToolRequest{ToolName: canonical(prodCompositeName)})
	if err != nil {
		t.Fatalf("trusted composite: %v", err)
	}
	if res.IsError {
		t.Fatalf("trusted caller denied: %s", prodAccessText(t, res))
	}
}
