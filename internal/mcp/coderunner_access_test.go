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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

const (
	prodAccessPolicyFile = "prod-access-by-caller-class.js"
	prodAccessPolicyDir  = "../../config/policies/examples"
	prodClassStandard    = "standard"
)

// accessCodeRunnerBackend adds a ToolMetadataLookup to the code-runner test
// backend so the executor can classify each toolmesh.* call.
type accessCodeRunnerBackend struct {
	codeRunnerTestBackend
	access map[string]string
}

func (b *accessCodeRunnerBackend) LookupTool(toolName string) (backend.ToolDescriptor, bool) {
	access, ok := b.access[toolName]
	if !ok {
		return backend.ToolDescriptor{}, false
	}
	return backend.ToolDescriptor{Name: toolName, Access: access}, true
}

// newProdAccessCodeRunner builds a code runner whose executor runs the
// shipped prod-access-by-caller-class.js policy on every toolmesh.* call.
func newProdAccessCodeRunner(t *testing.T, mb *accessCodeRunnerBackend) *CodeRunner {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(prodAccessPolicyDir, prodAccessPolicyFile)) //nolint:gosec // G304: fixed path inside the repository
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prodAccessPolicyFile), src, 0o600); err != nil { //nolint:gosec // G703: test helper with controlled path
		t.Fatalf("write policy: %v", err)
	}
	logger := handlerTestLogger()
	g, err := gate.New(dir, logger)
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	exec := executor.New(nil, nil, mb, gate.NewPipeline([]gate.Evaluator{g}), nil, 120*time.Second, logger, nil, nil)
	nameMap := map[string]string{
		"test_foo": testToolFoo,
		"test_bar": testToolBar,
	}
	tools, err := mb.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	return NewCodeRunner(nameMap, tools, exec, nil, logger)
}

// TestCodeRunner_ProdAccessPolicy_DenialReachesScript runs execute_code for
// a standard caller against a dangerous tool and a read tool. The denied
// call never reaches the backend; the script receives the gate's error text
// as the call's value (naming tool, caller class and reason) and keeps
// running, the allowed call goes through, and the wire result keeps the
// denied call as an error entry.
func TestCodeRunner_ProdAccessPolicy_DenialReachesScript(t *testing.T) {
	mb := &accessCodeRunnerBackend{access: map[string]string{
		testToolFoo: "dangerous",
		testToolBar: testAccessRead,
	}}
	runner := newProdAccessCodeRunner(t, mb)

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "test-user",
		Authenticated: true,
		CallerID:      "partner-acme",
		CallerClass:   prodClassStandard,
	})
	code := `
		const denied = await toolmesh.test_foo({ zone: "example.com" });
		const ok = await toolmesh.test_bar({});
		return { denied: String(denied), ok: String(ok) };
	`
	result, err := runner.Execute(ctx, code)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.IsError {
		t.Fatalf("execute_code itself must succeed; the denial is data for the script: %v", result.Content)
	}

	if len(mb.calls) != 1 || mb.calls[0].ToolName != testToolBar {
		t.Fatalf("backend calls = %+v, want exactly one call to %s", mb.calls, testToolBar)
	}

	text := extractText(t, result)
	var results []map[string]any
	if err := json.Unmarshal([]byte(text), &results); err != nil {
		t.Fatalf("unmarshal results: %v\n%s", err, text)
	}
	ret, ok := results[len(results)-1]["return"].(map[string]any)
	if !ok {
		t.Fatalf("missing return value in %s", text)
	}
	denied, _ := ret["denied"].(string)
	for _, part := range []string{"Gate rejected (pre-execution)", testToolFoo, `caller class "` + prodClassStandard + `"`, `access class "dangerous" is not allowed`} {
		if !strings.Contains(denied, part) {
			t.Errorf("script saw %q, which does not contain %q", denied, part)
		}
	}
	if got, _ := ret["ok"].(string); got != "ok" {
		t.Errorf("allowed call returned %q, want \"ok\"", got)
	}

	// The compact wire format keeps the denied call in full, flagged as error.
	entry, ok := results[0]["result"].(map[string]any)
	if !ok {
		t.Fatalf("first entry is not a kept tool result: %v", results[0])
	}
	if isErr, _ := entry["isError"].(bool); !isErr {
		t.Errorf("denied call must be kept as an error entry, got %v", entry)
	}
}
