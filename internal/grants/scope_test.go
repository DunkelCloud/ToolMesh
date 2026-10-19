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

package grants

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
)

// Names of the approver-scope tests.
const (
	testOpsApprover = "ops"
	testOpsKey      = "ops-key-for-tests" //nolint:gosec // test fixture, not a credential
	wantMayNot      = "may not approve"
	badSignature    = "smpAA=="
)

// limitApprover limits the approver with the name to the kits.
func limitApprover(cat *testCatalog, name string, kits ...string) {
	for i := range cat.approvers {
		if cat.approvers[i].Name == name {
			cat.approvers[i].Kits = kits
		}
	}
}

func TestApprove_OutsideApproverScope(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	limitApprover(env.cat, testApprover, testKitNetDiag)
	env.cat.approvers = append(env.cat.approvers, authz.Approver{Name: testOpsApprover, KeySHA256: keySum(testOpsKey)})

	id := env.request(t, testKitAdmin, "").Grant.ID
	_, err := env.svc.Approve(ctx, testApprover, id, 0)
	if !errors.Is(err, ErrForbidden) || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), testKitNetDiag) {
		t.Fatalf("Approve outside the scope = %v, want ErrForbidden naming the approver's kits", err)
	}
	if last := env.audit.last(t); last.Tool != auditApprove || last.Status != statusError || last.Metadata["approver"] != testApprover || !strings.Contains(last.Error, wantMayNot) {
		t.Errorf("refusal audited as %+v", last)
	}
	if _, err := env.svc.Lookup(ctx, id); err != nil {
		t.Errorf("the request is gone after the refusal: %v", err)
	}

	// Within the scope, and for an approver without one, approving works.
	if _, err := env.svc.Approve(ctx, testApprover, env.request(t, testKitNetDiag, "").Grant.ID, 0); err != nil {
		t.Errorf("Approve within the scope: %v", err)
	}
	g, err := env.svc.Approve(ctx, testOpsApprover, id, 0)
	if err != nil {
		t.Fatalf("Approve by an approver without a scope: %v", err)
	}

	// Denying and revoking are not limited.
	if _, err := env.svc.Revoke(ctx, testApprover, g.ID); err != nil {
		t.Errorf("Revoke outside the scope: %v", err)
	}
	if _, err := env.svc.Deny(ctx, testApprover, env.request(t, testKitAdmin, "").Grant.ID); err != nil {
		t.Errorf("Deny outside the scope: %v", err)
	}
}

func TestHTTP_ApproveOutsideScope(t *testing.T) {
	env := newTestEnv(t)
	limitApprover(env.cat, testApprover, testKitNetDiag)
	h := env.svc.Handler()
	id := env.request(t, testKitAdmin, "").Grant.ID
	var out map[string]string
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/approve", "", &out); code != http.StatusForbidden || !strings.Contains(out[jsonKeyError], wantMayNot) {
		t.Errorf("approve outside the scope = %d %v, want 403", code, out)
	}
	if code := call(t, h, http.MethodPost, PathPrefix+"/"+id+"/deny", "", nil); code != http.StatusOK {
		t.Errorf("deny outside the scope = %d, want 200", code)
	}
}

func TestApproveSigned_OutsideScope(t *testing.T) {
	env := newSigningEnv(t)
	ctx := context.Background()
	limitApprover(env.cat, testSigner, testKitNetDiag)
	id := env.request(t, testKitAdmin, "").Grant.ID

	if _, err := env.svc.Statement(ctx, id, testSigner, Approval{}, testAudience); !errors.Is(err, ErrForbidden) {
		t.Errorf("Statement outside the scope = %v, want ErrForbidden", err)
	}
	_, err := env.svc.ApproveSigned(ctx, id, SignedApproval{Approver: testSigner, Audience: testAudience, Signature: badSignature})
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("ApproveSigned outside the scope = %v, want ErrForbidden", err)
	}
	if last := env.audit.last(t); last.Status != statusError || last.Metadata["approved_with"] != ApprovedWithSignature || !strings.Contains(last.Error, wantMayNot) {
		t.Errorf("refusal audited as %+v", last)
	}

	// The page offers no approver for the kit, and refuses a signature.
	h := env.svc.ApprovalHandler()
	var view approvalView
	rec := serve(t, h, http.MethodGet, ApprovePathPrefix+"/"+id+"/request", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || rec.Code != http.StatusOK || len(view.Approvers) != 0 {
		t.Errorf("the page offers %+v for a kit the signer may not approve (status %d)", view.Approvers, rec.Code)
	}
	if rec := serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id, approvalBody{Approver: testSigner, Signature: badSignature}); rec.Code != http.StatusForbidden {
		t.Errorf("signed approval outside the scope = %d %s, want 403", rec.Code, rec.Body)
	}

	// The kit within the scope is offered and approved.
	id = env.request(t, testKitNetDiag, "").Grant.ID
	rec = serve(t, h, http.MethodGet, ApprovePathPrefix+"/"+id+"/request", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || len(view.Approvers) != 1 || view.Approvers[0].Name != testSigner {
		t.Errorf("the page offers %+v for a kit the signer may approve", view.Approvers)
	}
	if _, _, err := env.signed(t, id, testSignerKey, Approval{}); err != nil {
		t.Errorf("signed approval within the scope: %v", err)
	}
}
