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
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/gate"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// testClassGuest is a caller class the shipped prod-access policy does not
// list, so that the policy refuses every call without a kit.
const testClassGuest = "guest"

// prodPolicyGate loads the shipped prod-access-by-caller-class.js into a
// gate pipeline.
func prodPolicyGate(t *testing.T) *gate.Pipeline {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(prodAccessPolicyDir, prodAccessPolicyFile)) //nolint:gosec // G304: fixed path inside the repository
	if err != nil {
		t.Fatalf("read example policy: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, prodAccessPolicyFile), src, 0o600); err != nil { //nolint:gosec // G703: test helper with controlled path
		t.Fatalf("write policy: %v", err)
	}
	g, err := gate.New(dir, newQuietMCPLogger())
	if err != nil {
		t.Fatalf("gate.New: %v", err)
	}
	return gate.NewPipeline([]gate.Evaluator{g})
}

// guestCaller is an authenticated caller of the class guest.
func guestCaller(user string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: user, CallerClass: testClassGuest, Authenticated: true})
}

// TestTellMeMyRights_PolicyRefusal: the verdicts take the pre-execution
// policies into account. The owner may call every tool, but as a caller of
// a class the prod-access policy does not list, the policy refuses every
// call: the read tool of graylog is escalatable through the kit that covers
// it, since a held kit replaces the policy, with the policy's reason; the
// write tool, which no kit covers, is denied, yet listed for its backend;
// vault, refused and covered by nothing, is left out of the overview. Bob,
// whom the authorizer refuses, stays escalatable through the same kit.
func TestTellMeMyRights_PolicyRefusal(t *testing.T) {
	s := newKitSetupWithGate(t, nil, prodPolicyGate(t))
	owner := guestCaller(testKitUserOwner)
	refusal := "policy " + prodAccessPolicyFile + ": "

	a := askRightsCtx(t, s.handler, owner, map[string]any{argNameTools: []any{testGraylogSearch, testGraylogDelete}})
	if len(a.Tools) != 2 {
		t.Fatalf("tools = %+v, want two", a.Tools)
	}
	if r := a.Tools[0]; r.Verdict != executor.VerdictEscalatable || !slices.Equal(r.Kits, []string{testKitNetDiag}) ||
		!strings.HasPrefix(r.Reason, reasonPolicyKits+refusal) || !strings.Contains(r.Reason, `"`+testClassGuest+`"`) {
		t.Errorf("%s = %+v, want escalatable through %s with the policy's reason", testGraylogSearch, r, testKitNetDiag)
	}
	if r := a.Tools[1]; r.Verdict != executor.VerdictDenied || len(r.Kits) != 0 || !strings.HasPrefix(r.Reason, reasonPolicy+refusal) {
		t.Errorf("%s = %+v, want denied with the policy's reason", testGraylogDelete, r)
	}
	if a.Bundle == nil || !slices.Equal(a.Bundle.Kits, []string{testKitNetDiag}) || !slices.Equal(a.Bundle.Covers, []string{testGraylogSearch}) {
		t.Errorf("bundle = %+v, want %s for %s", a.Bundle, testKitNetDiag, testGraylogSearch)
	}
	if len(a.Kits) != 1 || a.Kits[0].Name != testKitNetDiag {
		t.Errorf("kits = %+v, want %s described", a.Kits, testKitNetDiag)
	}

	b := askRightsCtx(t, s.handler, owner, map[string]any{argNameBackend: testBackendGraylog})
	verdicts := map[string]string{}
	for _, r := range b.Tools {
		verdicts[r.Tool] = r.Verdict
	}
	if len(b.Tools) != 2 || verdicts[testGraylogSearch] != executor.VerdictEscalatable || verdicts[testGraylogDelete] != executor.VerdictDenied {
		t.Errorf("backend listing = %+v, want both tools, the write tool denied", b.Tools)
	}

	o := askRightsCtx(t, s.handler, owner, map[string]any{})
	want := []rightsBackend{
		{Backend: testBackendGraylog, Escalatable: 1, Kits: []string{testKitNetDiag}},
		{Backend: testBackendUnifi, Escalatable: 1, Kits: []string{testKitNetDiag}},
	}
	if len(o.Backends) != len(want) {
		t.Fatalf("overview = %+v, want %+v", o.Backends, want)
	}
	for i, w := range want {
		if g := o.Backends[i]; g.Backend != w.Backend || g.Allowed != w.Allowed || g.Escalatable != w.Escalatable || !slices.Equal(g.Kits, w.Kits) {
			t.Errorf("overview[%d] = %+v, want %+v", i, g, w)
		}
	}

	p := askRightsCtx(t, s.handler, guestCaller(testKitUserBob), map[string]any{argNameTools: []any{testGraylogSearch}})
	if len(p.Tools) != 1 || p.Tools[0].Verdict != executor.VerdictEscalatable || !slices.Equal(p.Tools[0].Kits, []string{testKitNetDiag}) || p.Tools[0].Reason != "" {
		t.Errorf("bob's %s = %+v, want escalatable through %s without a policy reason", testGraylogSearch, p.Tools, testKitNetDiag)
	}
}
