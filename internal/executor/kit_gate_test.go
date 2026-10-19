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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names of the tests of kits replacing the pre-execution gate.
const (
	testUserDave          = "dave"
	testKitGraylogWrite   = "graylog-write"
	testScopeGraylogWrite = "graylog:write"
	testBackendGraylog    = "graylog"
	testBackendUnifi      = "unifi"
	testScopeUnifiRead    = "unifi:read"
	testKitAgent          = "kit-agent"
	metaHeldKits          = "held_kits"
	paramForce            = "force"
	reasonForce           = "force is not allowed"
	maskedMark            = " [masked]"
	// Policies loaded next to the shipped prod-access-by-caller-class.js.
	policyKeep    = "keep.js"    // enforce-with-kit: refuses params.force
	policyContext = "context.js" // enforce-with-kit: checks ctx.kits and ctx.kitCovered
	policyMask    = "mask.js"    // post-execution: marks the response
)

var kitTestPolicies = map[string]string{
	policyKeep: "// toolmesh: enforce-with-kit\n" +
		`if (ctx.phase === "pre" && ctx.params && ctx.params.force === true) { throw "` + reasonForce + `"; }`,
	policyContext: "// toolmesh: enforce-with-kit\n" +
		`if (!Array.isArray(ctx.kits)) { throw "ctx.kits is not an array"; }` + "\n" +
		`if (typeof ctx.kitCovered !== "boolean") { throw "ctx.kitCovered is not a boolean"; }` + "\n" +
		`if (ctx.kitCovered && ctx.kits.length === 0) { throw "kitCovered without kits"; }`,
	policyMask: `if (ctx.phase === "post" && ctx.response && ctx.response.content) {
    for (var i = 0; i < ctx.response.content.length; i++) {
        if (ctx.response.content[i].type === "text") { ctx.response.content[i].text = ctx.response.content[i].text + "` + maskedMark + `"; }
    }
}`,
}

// newKitGate loads the shipped prod-access-by-caller-class.js and the given
// policies (file name → source) into a gate pipeline.
func newKitGate(t *testing.T, policies map[string]string) *gate.Pipeline {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(prodAccessPolicyDir, prodAccessPolicyFile)) //nolint:gosec // G304: fixed path inside the repository
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	dir := t.TempDir()
	write := func(name, source string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil { //nolint:gosec // G703: test helper with controlled path
			t.Fatalf("write policy %s: %v", name, err)
		}
	}
	write(prodAccessPolicyFile, string(src))
	for name, source := range policies {
		write(name, source)
	}
	g, err := gate.New(dir, newTestLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return gate.NewPipeline([]gate.Evaluator{g})
}

// newKitGateExecutor builds an executor on the embedded engine with the
// owner granted everything, dave granted graylog, carol denied
// graylog_search, the kit net-diag-read for the read tools of graylog and
// unifi, the kit graylog-write for the write tools of graylog, and a gate
// with the shipped prod-access policy plus the given policies.
func newKitGateExecutor(t *testing.T, policies map[string]string) (*Executor, *recordingAudit) {
	t.Helper()
	engine, err := authz.OpenEmbedded(context.Background(), authz.EmbeddedOptions{Path: filepath.Join(t.TempDir(), authz.DBFileName)})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.ApplyPolicy(context.Background(), authz.Policy{
		Grants: []authz.Grant{{User: testUserOwner, AllTools: true}, {User: testUserDave, Backends: []string{testBackendGraylog}}},
		Denies: []authz.Grant{{User: testUserCarol, Tools: []string{testGraylogSearch}}},
		Kits: []authz.Kit{
			{Name: testKitNetDiag, Description: "Network diagnosis (read-only)", Grants: []string{testScopeGraylogRead, testScopeUnifiRead}},
			{Name: testKitGraylogWrite, Description: "Change Graylog", Grants: []string{testScopeGraylogWrite}},
		},
	}); err != nil {
		t.Fatalf("ApplyPolicy: %v", err)
	}
	composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		testBackendGraylog: &classifiedBackend{access: map[string]string{"search": testAccessRead, "delete_stream": testAccessWrite}},
		testBackendUnifi:   &classifiedBackend{access: map[string]string{"list_clients": testAccessRead}},
	})
	rec := &recordingAudit{}
	return New(engine, nil, composite, newKitGate(t, policies), rec, time.Second, newTestLogger(), nil, nil), rec
}

// kitCaller is an authenticated caller of the class, connected as the kit
// test agent.
func kitCaller(user, class string) *userctx.UserContext {
	return &userctx.UserContext{UserID: user, CallerID: testKitAgent, CallerClass: class, Authenticated: true}
}

// holding makes the user, as the kit test agent, hold the kits.
func holding(user string, kits ...string) fixedKits {
	return fixedKits{user: user, caller: testKitAgent, kits: kits}
}

// skippedPolicies returns the policies the audit entry names as skipped.
func skippedPolicies(rec *recordingAudit) []string {
	if rec.last.Metadata[metaGateSkipped] == "" {
		return nil
	}
	return strings.Split(rec.last.Metadata[metaGateSkipped], ",")
}

// TestExecuteTool_KitReplacesPreGate: the prod-access policy refuses a
// restricted caller's write; a kit that covers the tool lifts that, the
// audit entry says so, and a policy with the directive still runs.
func TestExecuteTool_KitReplacesPreGate(t *testing.T) {
	exec, rec := newKitGateExecutor(t, kitTestPolicies)
	dave := kitCaller(testUserDave, prodClassRestricted)

	// Dave may call graylog, but his class may not write.
	res, err := exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "Gate rejected (pre-execution)") {
		t.Fatalf("without the kit = %q, %v; want the gate to refuse", resultText(res), err)
	}
	if rec.last.Status != statusDenied || rec.last.Metadata[metaKitApplied] != "" {
		t.Errorf("audit without the kit = %s %v, want denied without a kit", rec.last.Status, rec.last.Metadata)
	}

	exec.SetKitHolder(holding(testUserDave, testKitGraylogWrite))
	res, err = exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || res.IsError {
		t.Fatalf("with the kit = %q, %v; want the call to pass although the caller class may not write", resultText(res), err)
	}
	md := rec.last.Metadata
	if rec.last.Status != statusSuccess || md[metaKitApplied] != testKitGraylogWrite || md[metaHeldKits] != testKitGraylogWrite {
		t.Errorf("audit with the kit = %s %v, want success with the kit applied", rec.last.Status, md)
	}
	skipped := skippedPolicies(rec)
	if !slices.Contains(skipped, prodAccessPolicyFile) || slices.Contains(skipped, policyKeep) || slices.Contains(skipped, policyContext) {
		t.Errorf("gate_skipped = %v, want the prod-access policy skipped and the enforced ones not", skipped)
	}

	// A policy with the directive still runs: it refuses the parameter.
	res, err = exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogDelete, Params: map[string]any{paramForce: true}})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), reasonForce) {
		t.Fatalf("with the kit and force = %q, %v; want the enforced policy to refuse", resultText(res), err)
	}
	if rec.last.Status != statusDenied || rec.last.Metadata[metaKitApplied] != testKitGraylogWrite {
		t.Errorf("audit of the refusal = %s %v, want denied with the kit applied", rec.last.Status, rec.last.Metadata)
	}

	// Without kits every policy runs, and ctx.kits is an empty array.
	res, err = exec.ExecuteTool(callerCtx(kitCaller(testUserOwner, prodClassTrusted)), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || res.IsError {
		t.Fatalf("owner without kits = %q, %v", resultText(res), err)
	}
	if md := rec.last.Metadata; md[metaGateSkipped] != "" || md[metaKitApplied] != "" {
		t.Errorf("audit of the owner's call = %v, want no kit and nothing skipped", md)
	}
}

// TestExecuteTool_KitPartAppliesToGrantedEntriesOnly: a kit held in part
// covers the tools of its granted entries and no other.
func TestExecuteTool_KitPartAppliesToGrantedEntriesOnly(t *testing.T) {
	exec, rec := newKitGateExecutor(t, kitTestPolicies)
	exec.SetKitHolder(fixedKits{user: testUserBob, caller: testKitAgent, parts: []authz.KitPart{{Kit: testKitNetDiag, Grants: []string{testScopeGraylogRead}}}})
	bob := kitCaller(testUserBob, prodClassRestricted)

	res, err := exec.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil || res.IsError {
		t.Fatalf("the granted entry = %q, %v; want the call to pass", resultText(res), err)
	}
	if md := rec.last.Metadata; md[metaKitApplied] != testKitNetDiag || !slices.Contains(skippedPolicies(rec), prodAccessPolicyFile) {
		t.Errorf("audit = %v, want the kit applied and the prod-access policy skipped", md)
	}
	res, err = exec.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testUnifiClients})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "not authorized") {
		t.Fatalf("the left-out entry = %q, %v; want authorization to refuse", resultText(res), err)
	}
	if md := rec.last.Metadata; rec.last.Status != statusDenied || md[metaKitApplied] != "" || md[metaGateSkipped] != "" {
		t.Errorf("audit of the left-out entry = %s %v, want denied without a kit", rec.last.Status, md)
	}

	// Without a gate the kit is still recorded.
	plain, plainRec := newKitExecutor(t)
	plain.SetKitHolder(holding(testUserBob, testKitNetDiag))
	if res, err := plain.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testGraylogSearch}); err != nil || res.IsError {
		t.Fatalf("without a gate = %q, %v", resultText(res), err)
	}
	if md := plainRec.last.Metadata; md[metaKitApplied] != testKitNetDiag || md[metaGateSkipped] != "" {
		t.Errorf("audit without a gate = %v, want the kit applied and nothing skipped", md)
	}
}

// TestCheckChild_KitReplacesPreGate: a child call from inside a composite
// gets the same treatment as a direct call.
func TestCheckChild_KitReplacesPreGate(t *testing.T) {
	exec, _ := newKitGateExecutor(t, kitTestPolicies)
	dave := kitCaller(testUserDave, prodClassRestricted)
	if err := exec.CheckChild(callerCtx(dave), testGraylogDelete, nil); err == nil || !strings.Contains(err.Error(), "gate rejected") {
		t.Errorf("child call without the kit = %v, want the gate to refuse", err)
	}
	exec.SetKitHolder(holding(testUserDave, testKitGraylogWrite))
	if err := exec.CheckChild(callerCtx(dave), testGraylogDelete, nil); err != nil {
		t.Errorf("child call with the kit: %v", err)
	}
	if err := exec.CheckChild(callerCtx(dave), testGraylogDelete, map[string]any{paramForce: true}); err == nil || !strings.Contains(err.Error(), reasonForce) {
		t.Errorf("child call with the kit and force = %v, want the enforced policy to refuse", err)
	}
	// Authorization still decides first.
	if err := exec.CheckChild(callerCtx(kitCaller(testUserBob, prodClassRestricted)), testGraylogDelete, nil); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("child call of a caller without rights = %v, want authorization to refuse", err)
	}
}

// TestExecuteTool_DenyWinsOverKit: a deny blocks the tool for the caller
// even though a kit it holds covers it; the kit still applies to the rest.
func TestExecuteTool_DenyWinsOverKit(t *testing.T) {
	exec, rec := newKitGateExecutor(t, kitTestPolicies)
	exec.SetKitHolder(holding(testUserCarol, testKitNetDiag))
	carol := kitCaller(testUserCarol, prodClassRestricted)

	res, err := exec.ExecuteTool(callerCtx(carol), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), "not authorized") {
		t.Fatalf("the denied tool = %q, %v; want the deny to win", resultText(res), err)
	}
	if md := rec.last.Metadata; rec.last.Status != statusDenied || md[metaHeldKits] != testKitNetDiag || md[metaKitApplied] != "" || md[metaGateSkipped] != "" {
		t.Errorf("audit of the denied tool = %s %v, want denied with the kit held but not applied", rec.last.Status, md)
	}
	res, err = exec.ExecuteTool(callerCtx(carol), ExecuteToolRequest{ToolName: testUnifiClients})
	if err != nil || res.IsError || rec.last.Metadata[metaKitApplied] != testKitNetDiag {
		t.Errorf("another tool of the kit = %q, %v, %v; want it to pass with the kit applied", resultText(res), err, rec.last.Metadata)
	}
}

// TestExecuteTool_PostGateRunsWithKit: the post-execution phase runs every
// policy for a call a kit covers.
func TestExecuteTool_PostGateRunsWithKit(t *testing.T) {
	exec, rec := newKitGateExecutor(t, kitTestPolicies)
	exec.SetKitHolder(holding(testUserDave, testKitGraylogWrite))
	res, err := exec.ExecuteTool(callerCtx(kitCaller(testUserDave, prodClassRestricted)), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || res.IsError || !strings.HasSuffix(resultText(res), maskedMark) {
		t.Fatalf("with the kit = %q, %v; want the post policy's mark", resultText(res), err)
	}
	if !slices.Contains(skippedPolicies(rec), policyMask) {
		t.Errorf("gate_skipped = %v, want the post policy listed for the pre-execution phase", skippedPolicies(rec))
	}
	var post []string
	for _, m := range rec.last.Modifications {
		if m.Phase == string(gate.PhasePost) {
			post = append(post, m.Policy)
		}
	}
	if !slices.Equal(post, []string{policyMask}) {
		t.Errorf("post-execution modifications = %v, want the post policy's", post)
	}
}

// TestAssessTools_EscalatableHoldsWithProdPolicy: what tell_me_my_rights
// promises as escalatable is what the caller gets with the kit, the
// prod-access policy notwithstanding.
func TestAssessTools_EscalatableHoldsWithProdPolicy(t *testing.T) {
	exec, _ := newKitGateExecutor(t, kitTestPolicies)
	bob := kitCaller(testUserBob, prodClassRestricted)
	rights := exec.AssessTools(context.Background(), bob, descriptors(testGraylogDelete), true)
	if rights[0].Verdict != VerdictEscalatable || !slices.Equal(rights[0].Kits, []string{testKitGraylogWrite}) {
		t.Fatalf("rights = %+v, want the write tool escalatable through %s", rights, testKitGraylogWrite)
	}
	exec.SetKitHolder(holding(testUserBob, testKitGraylogWrite))
	if rights := exec.AssessTools(context.Background(), bob, descriptors(testGraylogDelete), true); rights[0].Verdict != VerdictAllowed {
		t.Errorf("rights with the kit = %+v, want allowed", rights)
	}
	res, err := exec.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || res.IsError {
		t.Errorf("the escalated call = %q, %v; want it to pass", resultText(res), err)
	}
}
