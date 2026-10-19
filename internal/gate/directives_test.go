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

package gate

import (
	"bytes"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names of the directive and kit tests.
const (
	directiveLine  = "// toolmesh: enforce-with-kit\n"
	policyYields   = "a-yields.js"
	policyEnforced = "b-enforced.js"
	policyPost     = "c-post.js"
	reasonYields   = "yields refused"
	reasonEnforced = "enforced refused"
	testKitOne     = "kit-one"
	testUserOne    = "u1"
)

func TestParseDirectives(t *testing.T) {
	for _, tc := range []struct {
		name, src string
		want      bool
		unknown   []string
	}{
		{"line comment", directiveLine + "var x = 1;\n", true, nil},
		{"after a license header", "// Copyright\n//\n// Licensed under the License.\n\n" + directiveLine + "if (x) {}\n", true, nil},
		{"block comment", "/*\n * Policy\n * toolmesh: enforce-with-kit\n */\nvar x;\n", true, nil},
		{"one-line block comment", "/* toolmesh: enforce-with-kit */\nvar x;\n", true, nil},
		{"after code it is prose", "var x = 1;\n" + directiveLine, false, nil},
		{"code after a block comment ends the header", "/* toolmesh: other */ var x;\n" + directiveLine, false, []string{"other"}},
		{"a quoted mention is prose", "// no \"toolmesh: enforce-with-kit\" directive here\nvar x;\n", false, nil},
		{"several names", "// toolmesh: enforce-with-kit, future-one\n", true, []string{"future-one"}},
		{"unknown name", "// toolmesh: enforce-with-kits\n", false, []string{"enforce-with-kits"}},
		{"crlf", "// toolmesh: enforce-with-kit\r\nvar x;\r\n", true, nil},
		{"empty", "", false, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := parseDirectives(tc.src)
			if d.enforceWithKit != tc.want || !slices.Equal(d.unknown, tc.unknown) {
				t.Errorf("parseDirectives = %+v, want enforce %v, unknown %v", d, tc.want, tc.unknown)
			}
		})
	}
}

func TestGate_New_LogsDirectives(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, policyEnforced, directiveLine+"// toolmesh: no-such-directive\n")
	writePolicy(t, dir, policyYields, "// a policy without directives\n")
	var buf bytes.Buffer
	if _, err := New(dir, slog.New(slog.NewTextHandler(&buf, nil))); err != nil {
		t.Fatalf("New: %v", err)
	}
	log := buf.String()
	for _, want := range []string{
		`msg="loaded policy" name=` + policyYields + " pre_gate_with_kit=skipped",
		`msg="loaded policy" name=` + policyEnforced + " pre_gate_with_kit=enforced",
		"unknown directive\" name=" + policyEnforced + " directive=no-such-directive",
	} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
}

// newKitTestGate loads a policy that yields to kits, one with the directive
// that refuses the parameter "bad", and a post-execution policy that marks
// the response when a kit covers the call.
func newKitTestGate(t *testing.T) *Gate {
	t.Helper()
	dir := t.TempDir()
	writePolicy(t, dir, policyYields, `if (ctx.phase === "pre") { throw "`+reasonYields+`"; }`)
	writePolicy(t, dir, policyEnforced, directiveLine+`if (ctx.phase === "pre" && ctx.params.bad) { throw "`+reasonEnforced+`"; }`)
	writePolicy(t, dir, policyPost, `if (ctx.phase === "post" && ctx.kitCovered) { ctx.response.content[0].text = "seen " + ctx.kits.join(","); }`)
	g, err := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return g
}

func TestGate_KitCovered_SkipsPoliciesWithoutDirective(t *testing.T) {
	g := newKitTestGate(t)
	covered := GateContext{
		User:       userctx.UserContext{UserID: testUserOne, Authenticated: true},
		Tool:       testToolName,
		Params:     map[string]any{},
		Phase:      PhasePre,
		Kits:       []string{testKitOne},
		KitCovered: true,
	}
	res, err := g.Evaluate(covered)
	if err != nil || !res.Allowed || !slices.Equal(res.Skipped, []string{policyYields, policyPost}) {
		t.Fatalf("pre with kit = %+v, %v; want it allowed with the policies without directive skipped", res, err)
	}

	bad := covered
	bad.Params = map[string]any{"bad": true}
	if res, _ := g.Evaluate(bad); res.Allowed || !strings.Contains(res.Reason, reasonEnforced) {
		t.Errorf("pre with kit and a bad parameter = %+v, want the enforced policy to refuse", res)
	}

	plain := covered
	plain.Kits, plain.KitCovered = nil, false
	if res, _ := g.Evaluate(plain); res.Allowed || !strings.Contains(res.Reason, reasonYields) || res.Skipped != nil {
		t.Errorf("pre without kit = %+v, want every policy to run", res)
	}

	post := covered
	post.Phase = PhasePost
	post.Response = &backend.ToolResult{Content: []any{map[string]any{testContentKeyType: testContentText, testContentText: "x"}}}
	res, err = g.Evaluate(post)
	if err != nil || !res.Allowed || res.Skipped != nil {
		t.Fatalf("post with kit = %+v, %v; want every policy to run", res, err)
	}
	if got := post.Response.Content[0].(map[string]any)[testContentText]; got != "seen "+testKitOne {
		t.Errorf("the post policy saw %q, want the kits", got)
	}
}

func TestGate_KitsAlwaysArray(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, policyYields, `if (!Array.isArray(ctx.kits) || ctx.kits.length !== 0 || ctx.kitCovered !== false) { throw "kits " + ctx.kits + " covered " + ctx.kitCovered; }`)
	g, err := New(dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := g.Evaluate(GateContext{User: userctx.UserContext{UserID: testUserOne}, Tool: testToolName, Phase: PhasePre})
	if err != nil || !res.Allowed {
		t.Errorf("a caller without kits = %+v, %v; want ctx.kits to be an empty array", res, err)
	}
}

// skippingEvaluator allows every call and reports policies as skipped.
type skippingEvaluator struct {
	name    string
	skipped []string
}

func (s skippingEvaluator) Name() string { return s.name }

func (s skippingEvaluator) Evaluate(_ GateContext) (*EvalResult, error) {
	return &EvalResult{Allowed: true, Skipped: s.skipped}, nil
}

func TestPipeline_Outcome_CollectsSkipped(t *testing.T) {
	p := NewPipeline([]Evaluator{
		skippingEvaluator{name: "one", skipped: []string{policyYields}},
		skippingEvaluator{name: "two"},
		skippingEvaluator{name: "three", skipped: []string{policyPost, policyEnforced}},
	})
	out, err := p.EvaluatePre(GateContext{User: userctx.UserContext{UserID: testUserOne}, Tool: testToolName, KitCovered: true})
	if err != nil || !slices.Equal(out.Skipped, []string{policyYields, policyPost, policyEnforced}) || out.Modifications != nil {
		t.Errorf("EvaluatePre = %+v, %v; want the skipped policies of every evaluator in order", out, err)
	}
}

// TestProdAccessPolicy_YieldsToKit: the shipped prod-access policy carries
// no directive, so a kit that covers the tool replaces it.
func TestProdAccessPolicy_YieldsToKit(t *testing.T) {
	g := newProdAccessGate(t, nil)
	gctx := GateContext{
		User:       userctx.UserContext{UserID: testUserOne, Authenticated: true, CallerID: prodCallerClaude, CallerClass: prodClassRestricted},
		Tool:       prodToolCreateTag,
		ToolAccess: prodAccessWrite,
		Params:     map[string]any{},
		Phase:      PhasePre,
	}
	if res, _ := g.Evaluate(gctx); res.Allowed {
		t.Fatal("a restricted caller's write passed without a kit")
	}
	gctx.Kits, gctx.KitCovered = []string{testKitOne}, true
	res, err := g.Evaluate(gctx)
	if err != nil || !res.Allowed || !slices.Equal(res.Skipped, []string{prodAccessPolicyFile}) {
		t.Errorf("with a kit = %+v, %v; want the policy skipped", res, err)
	}
}
