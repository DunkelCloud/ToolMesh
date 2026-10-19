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
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// The shipped example policy under test, read from the repository so the
// tests pin the file operators actually copy into production.
const (
	examplePoliciesDir   = "../../config/policies/examples"
	prodAccessPolicyFile = "prod-access-by-caller-class.js"

	prodClassTrusted    = "trusted"
	prodClassStandard   = "standard"
	prodClassRestricted = "restricted"
	prodClassUntrusted  = "untrusted"
	prodClassUnknown    = "partner"

	prodAccessRead      = "read"
	prodAccessWrite     = "write"
	prodAccessAdmin     = "admin"
	prodAccessDangerous = "dangerous"
	prodAccessCustom    = "execute"
	prodAccessNone      = ""

	prodToolDeleteZone = "cloudflare_delete_zone"
	prodToolCreateTag  = "gitlab_create_tag"
	prodToolDropRepo   = "gitlab_delete_project"
	prodToolCreatePull = "github_create_pull"
	prodCallerRunner   = "release-runner"
	prodCallerClaude   = "claude-code"
)

// newProdAccessGate loads the shipped prod-access-by-caller-class.js example
// policy, plus any extra policies given as file name → source, into a fresh
// gate.
func newProdAccessGate(t *testing.T, extra map[string]string) *Gate {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(examplePoliciesDir, prodAccessPolicyFile)) //nolint:gosec // G304: fixed path inside the repository
	if err != nil {
		t.Fatalf("read example policy %s: %v", prodAccessPolicyFile, err)
	}
	dir := t.TempDir()
	writePolicy(t, dir, prodAccessPolicyFile, string(src))
	for name, source := range extra {
		writePolicy(t, dir, name, source)
	}
	g, err := New(dir, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return g
}

func evalProdAccess(t *testing.T, g *Gate, callerID, callerClass, tool, access string, phase Phase) *EvalResult {
	t.Helper()
	res, err := g.Evaluate(GateContext{
		User: userctx.UserContext{
			UserID:        "u1",
			Authenticated: true,
			CallerID:      callerID,
			CallerClass:   callerClass,
		},
		Tool:       tool,
		ToolAccess: access,
		Params:     map[string]any{},
		Phase:      phase,
		Response:   &backend.ToolResult{},
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	return res
}

// TestProdAccessPolicy_Matrix checks every cell of the caller class × access
// class matrix shipped in prod-access-by-caller-class.js, allowed and denied
// alike, plus the rows for a caller class the policy does not know and for an
// empty class. A change to the ALLOWED table in the policy has to be
// mirrored here on purpose.
func TestProdAccessPolicy_Matrix(t *testing.T) {
	g := newProdAccessGate(t, nil)

	accessClasses := []string{prodAccessRead, prodAccessWrite, prodAccessAdmin, prodAccessDangerous, prodAccessCustom, prodAccessNone}
	rows := []struct {
		class   string
		allowed map[string]bool
	}{
		{prodClassTrusted, map[string]bool{prodAccessRead: true, prodAccessWrite: true, prodAccessAdmin: true, prodAccessDangerous: true}},
		{prodClassStandard, map[string]bool{prodAccessRead: true, prodAccessWrite: true}},
		{prodClassRestricted, map[string]bool{prodAccessRead: true}},
		{prodClassUntrusted, map[string]bool{prodAccessRead: true}},
		{prodClassUnknown, map[string]bool{}},
		{"", map[string]bool{}},
	}

	cells := 0
	for _, row := range rows {
		for _, access := range accessClasses {
			want := row.allowed[access]
			label := access
			if label == prodAccessNone {
				label = "unclassified"
			}
			cells++
			t.Run(row.class+"/"+label, func(t *testing.T) {
				res := evalProdAccess(t, g, "caller-1", row.class, prodToolDeleteZone, access, PhasePre)
				if res.Allowed != want {
					t.Fatalf("class %q × access %q: allowed = %v, want %v (reason: %s)", row.class, access, res.Allowed, want, res.Reason)
				}
				if want {
					return
				}
				for _, part := range []string{prodToolDeleteZone, `caller class "` + row.class + `"`} {
					if !strings.Contains(res.Reason, part) {
						t.Errorf("denial reason %q does not name %q", res.Reason, part)
					}
				}
			})
		}
	}
	if wantCells := len(rows) * len(accessClasses); cells != wantCells {
		t.Fatalf("covered %d cells, want %d", cells, wantCells)
	}
}

// TestProdAccessPolicy_DenialNamesReason pins the three reasons a denial can
// carry, so an operator reading the tool result or the audit entry can tell
// a blocked access class from an unclassified tool from an unknown class.
func TestProdAccessPolicy_DenialNamesReason(t *testing.T) {
	g := newProdAccessGate(t, nil)

	cases := []struct {
		name       string
		class      string
		access     string
		wantReason string
	}{
		{"blocked access class", prodClassStandard, prodAccessDangerous, `access class "dangerous" is not allowed for this caller class`},
		{"custom access class", prodClassTrusted, prodAccessCustom, `access class "execute" is not allowed for this caller class`},
		{"unclassified tool", prodClassTrusted, prodAccessNone, "tool has no access classification"},
		{"unknown caller class", prodClassUnknown, prodAccessRead, "caller class is not listed in this policy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalProdAccess(t, g, "caller-1", tc.class, prodToolDeleteZone, tc.access, PhasePre)
			if res.Allowed {
				t.Fatal("expected denial")
			}
			for _, part := range []string{prodToolDeleteZone, `caller class "` + tc.class + `"`, tc.wantReason} {
				if !strings.Contains(res.Reason, part) {
					t.Errorf("reason %q does not contain %q", res.Reason, part)
				}
			}
		})
	}
}

// TestProdAccessPolicy_PostPhaseUntouched makes sure the policy is a pure
// pre-gate: a response that reaches the post phase is never rejected by it,
// whatever the caller class or access class.
func TestProdAccessPolicy_PostPhaseUntouched(t *testing.T) {
	g := newProdAccessGate(t, nil)
	for _, class := range []string{prodClassUntrusted, prodClassUnknown} {
		for _, access := range []string{prodAccessDangerous, prodAccessNone} {
			res := evalProdAccess(t, g, "caller-1", class, prodToolDeleteZone, access, PhasePost)
			if !res.Allowed {
				t.Errorf("post phase: class %q × access %q rejected: %s", class, access, res.Reason)
			}
		}
	}
}

// TestProdAccessPolicy_ComposesWithCallerIDPolicy runs the matrix policy next
// to a second pre-gate policy that reserves a set of tools for one caller ID
// — the shape of a release-runner restriction. Both only deny, so a call
// passes only when both allow it; neither cancels the other.
func TestProdAccessPolicy_ComposesWithCallerIDPolicy(t *testing.T) {
	runnerPolicy := `
		// Only the release runner may call the gitlab_* tools; everyone else is
		// rejected before execution, whatever their caller class.
		if (ctx.phase === "pre" && ctx.tool.indexOf("gitlab_") === 0 && ctx.user.callerId !== "release-runner") {
			throw "tool " + ctx.tool + " is reserved for caller release-runner";
		}
	`
	g := newProdAccessGate(t, map[string]string{"release-runner.js": runnerPolicy})

	cases := []struct {
		name        string
		callerID    string
		class       string
		tool        string
		access      string
		wantAllowed bool
		wantReason  string
	}{
		{"trusted caller blocked by the caller-ID policy", prodCallerClaude, prodClassTrusted, prodToolCreateTag, prodAccessWrite, false, "reserved for caller release-runner"},
		{"runner allowed by both policies", prodCallerRunner, prodClassStandard, prodToolCreateTag, prodAccessWrite, true, ""},
		{"runner still bound by the matrix", prodCallerRunner, prodClassStandard, prodToolDropRepo, prodAccessDangerous, false, `access class "dangerous" is not allowed`},
		{"other tools unaffected by the caller-ID policy", prodCallerClaude, prodClassTrusted, prodToolCreatePull, prodAccessWrite, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := evalProdAccess(t, g, tc.callerID, tc.class, tc.tool, tc.access, PhasePre)
			if res.Allowed != tc.wantAllowed {
				t.Fatalf("allowed = %v, want %v (reason: %s)", res.Allowed, tc.wantAllowed, res.Reason)
			}
			if tc.wantReason != "" && !strings.Contains(res.Reason, tc.wantReason) {
				t.Errorf("reason %q does not contain %q", res.Reason, tc.wantReason)
			}
		})
	}
}
