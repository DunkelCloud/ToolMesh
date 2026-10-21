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
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Policies of the preflight tests, loaded next to the shipped
// prod-access-by-caller-class.js and the policies of the kit gate tests.
const (
	policyFrozen = "frozen.js" // enforce-with-kit: refuses graylog_delete_stream for everyone
	policyReason = "reason.js" // enforce-with-kit: requires params.reason, except in a preflight
	reasonFrozen = "frozen"
	reasonNeeded = "reason required"
	paramReason  = "reason"
	noKitLifts   = " No kit lifts this policy."
)

var (
	policyFrozenSource = "// toolmesh: enforce-with-kit\n" +
		`if (ctx.phase === "pre" && ctx.tool === "` + testGraylogDelete + `") { throw "` + reasonFrozen + `"; }`
	policyReasonSource = "// toolmesh: enforce-with-kit\n" +
		`if (ctx.phase === "pre" && ctx.preflight && (ctx.params === null || typeof ctx.params !== "object")) { throw "preflight without a params object"; }` + "\n" +
		`if (ctx.phase === "pre" && !ctx.preflight && !(ctx.params && ctx.params.` + paramReason + `)) { throw "` + reasonNeeded + `"; }`
)

// withPolicies returns the policies of the kit gate tests plus the given ones.
func withPolicies(extra map[string]string) map[string]string {
	out := maps.Clone(kitTestPolicies)
	maps.Copy(out, extra)
	return out
}

// TestAssessTools_PolicyRefusalEscalatable: a caller the authorizer allows
// but the prod-access policy refuses sees the tool as escalatable through
// the kit that covers it, since a held kit replaces the policy. Discovery
// (without verify) does not ask the policies, the call without the kit is
// refused with the kit named, and with the kit the tool is allowed.
func TestAssessTools_PolicyRefusalEscalatable(t *testing.T) {
	exec, rec := newKitGateExecutor(t, kitTestPolicies)
	dave := kitCaller(testUserDave, prodClassRestricted)
	tools := descriptors(testGraylogSearch, testGraylogDelete)

	rights := exec.AssessTools(context.Background(), dave, tools, true)
	if r := rights[0]; r.Verdict != VerdictAllowed || r.PolicyRefusal != "" {
		t.Errorf("%s = %+v, want allowed", testGraylogSearch, r)
	}
	if r := rights[1]; r.Verdict != VerdictEscalatable || !slices.Equal(r.Kits, []string{testKitGraylogWrite}) ||
		!strings.HasPrefix(r.PolicyRefusal, "policy "+prodAccessPolicyFile+": ") || !strings.Contains(r.PolicyRefusal, prodClassRestricted) {
		t.Errorf("%s = %+v, want escalatable through %s with the policy's refusal", testGraylogDelete, r, testKitGraylogWrite)
	}

	if cheap := exec.AssessTools(context.Background(), dave, tools, false); cheap[1].Verdict != VerdictAllowed || cheap[1].PolicyRefusal != "" {
		t.Errorf("without verify %s = %+v, want allowed: discovery does not ask the policies", testGraylogDelete, cheap[1])
	}

	res, err := exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || !res.IsError {
		t.Fatalf("call without the kit = %q, %v; want the gate's refusal", resultText(res), err)
	}
	if text := resultText(res); !strings.Contains(text, prodAccessPolicyFile) || !strings.Contains(text, `The kit "`+testKitGraylogWrite+`"`) || !strings.Contains(text, RightsToolName) {
		t.Errorf("refusal = %q, want it to name the policy, the kit %s and %s", text, testKitGraylogWrite, RightsToolName)
	}
	if rec.last.Status != statusDenied || rec.last.Metadata[metaRemedyKits] != testKitGraylogWrite {
		t.Errorf("audit = %+v, want status denied with %s=%s", rec.last, metaRemedyKits, testKitGraylogWrite)
	}

	exec.SetKitHolder(holding(testUserDave, testKitGraylogWrite))
	if rights := exec.AssessTools(context.Background(), dave, tools, true); rights[1].Verdict != VerdictAllowed || rights[1].PolicyRefusal != "" {
		t.Errorf("with the kit %s = %+v, want allowed", testGraylogDelete, rights[1])
	}
}

// TestAssessTools_EnforcedPolicyRefusalDenied: a policy that declares
// enforce-with-kit runs for kit holders too, so a tool it refuses is denied
// whether the authorizer allows the caller or a kit would. The refusal of
// the call says that no kit lifts it, and an authorization denial names no
// kit that the policy would refuse anyway.
func TestAssessTools_EnforcedPolicyRefusalDenied(t *testing.T) {
	exec, rec := newKitGateExecutor(t, withPolicies(map[string]string{policyFrozen: policyFrozenSource}))
	dave := kitCaller(testUserDave, prodClassRestricted)
	bob := kitCaller(testUserBob, prodClassRestricted)
	want := "policy " + policyFrozen + ": " + reasonFrozen
	for _, uc := range []*userctx.UserContext{dave, bob} {
		r := exec.AssessTools(context.Background(), uc, descriptors(testGraylogDelete), true)[0]
		if r.Verdict != VerdictDenied || len(r.Kits) != 0 || r.Blocked || r.PolicyRefusal != want {
			t.Errorf("%s for %s = %+v, want denied by %q", testGraylogDelete, uc.UserID, r, want)
		}
	}

	res, err := exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || !res.IsError || !strings.HasSuffix(resultText(res), reasonFrozen+"."+noKitLifts) {
		t.Errorf("call = %q, %v; want the refusal to end in %q", resultText(res), err, noKitLifts)
	}
	if rec.last.Status != statusDenied || rec.last.Metadata[metaRemedyKits] != "" {
		t.Errorf("audit = %+v, want status denied without %s", rec.last, metaRemedyKits)
	}

	res, err = exec.ExecuteTool(callerCtx(bob), ExecuteToolRequest{ToolName: testGraylogDelete})
	if err != nil || !res.IsError || strings.Contains(resultText(res), "The kit") || rec.last.Metadata[metaRemedyKits] != "" {
		t.Errorf("authorization denial = %q, %v (audit %+v); want no kit named, as the policy refuses kit holders too", resultText(res), err, rec.last.Metadata)
	}
}

// TestAssessTools_PreflightSeesFlag: a policy that requires a parameter lets
// the preflight pass, where there are no parameters and ctx.preflight says
// so, and refuses the call without the parameter.
func TestAssessTools_PreflightSeesFlag(t *testing.T) {
	exec, _ := newKitGateExecutor(t, withPolicies(map[string]string{policyReason: policyReasonSource}))
	dave := kitCaller(testUserDave, prodClassRestricted)
	if r := exec.AssessTools(context.Background(), dave, descriptors(testGraylogSearch), true)[0]; r.Verdict != VerdictAllowed || r.PolicyRefusal != "" {
		t.Errorf("preflight = %+v, want allowed", r)
	}
	res, err := exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogSearch})
	if err != nil || !res.IsError || !strings.Contains(resultText(res), reasonNeeded) {
		t.Errorf("call without a reason = %q, %v; want %q", resultText(res), err, reasonNeeded)
	}
	res, err = exec.ExecuteTool(callerCtx(dave), ExecuteToolRequest{ToolName: testGraylogSearch, Params: map[string]any{paramReason: "audit"}})
	if err != nil || res.IsError {
		t.Errorf("call with a reason = %q, %v; want it to pass", resultText(res), err)
	}
}

// TestKitCoverage_PolicyRefusalCountsAsNew: an approver sees a tool the
// policy refuses the caller now as new for the kit that lifts the refusal,
// and nothing new for a caller the policy lets through.
func TestKitCoverage_PolicyRefusalCountsAsNew(t *testing.T) {
	exec, _ := newKitGateExecutor(t, kitTestPolicies)
	kits := exec.Kits()
	k := slices.IndexFunc(kits, func(k authz.Kit) bool { return k.Name == testKitGraylogWrite })
	if k < 0 {
		t.Fatalf("kit %s not in %+v", testKitGraylogWrite, kits)
	}
	all, err := exec.backend.ListTools(context.Background())
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	cov := exec.KitCoverage(context.Background(), kitCaller(testUserDave, prodClassRestricted), kits[k], all)
	if len(cov) != 1 || cov[0].Entry != testScopeGraylogWrite || cov[0].Tools != 1 || cov[0].New != 1 {
		t.Errorf("coverage for the restricted caller = %+v, want the one write tool new", cov)
	}
	cov = exec.KitCoverage(context.Background(), kitCaller(testUserOwner, prodClassTrusted), kits[k], all)
	if len(cov) != 1 || cov[0].Tools != 1 || cov[0].New != 0 {
		t.Errorf("coverage for the trusted owner = %+v, want nothing new", cov)
	}
}
