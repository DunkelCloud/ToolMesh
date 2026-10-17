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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
)

const (
	// testSigner signs on the approval page with the key testSignerKey.
	testSigner    = "carla"
	testSignerKey = "0101010101010101010101010101010101010101010101010101010101010101" //nolint:gosec // test key, holds nothing
	// testOtherKey is a key that belongs to no approver.
	testOtherKey = "0202020202020202020202020202020202020202020202020202020202020202" //nolint:gosec // test key, holds nothing
	testAudience = "https://toolmesh.example.com"
)

// signingEnv is a test environment with the approver carla, who signs.
type signingEnv struct {
	*testEnv
	js *jsSigner
}

func newSigningEnv(t *testing.T) *signingEnv {
	t.Helper()
	env := newTestEnv(t)
	js := newJSSigner(t)
	env.cat.approvers = append(env.cat.approvers, authz.Approver{Name: testSigner, Address: js.address(testSignerKey, "bc")})
	env.svc.publicURL = testAudience
	return &signingEnv{testEnv: env, js: js}
}

// signed asks the service for the statement of the choices, signs it with
// key and approves with the signature.
func (e *signingEnv) signed(t *testing.T, id, key string, a Approval) (Grant, Statement, error) {
	t.Helper()
	st, err := e.svc.Statement(context.Background(), id, testSigner, a, testAudience)
	if err != nil {
		t.Fatalf("Statement: %v", err)
	}
	g, err := e.svc.ApproveSigned(context.Background(), id, SignedApproval{
		Approver: testSigner, Approval: a, Audience: testAudience, Signature: e.js.sign(key, st.Text),
	})
	return g, st, err
}

func TestStatement(t *testing.T) {
	env := newSigningEnv(t)
	res := env.request(t, testKitNetDiag, "6h")
	st, err := env.svc.Statement(context.Background(), res.Grant.ID, testSigner, Approval{TTL: 2 * time.Hour, Grants: []string{testScopeGraylog}}, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		StatementVersion + "\n\n",
		"\nToolMesh: " + testAudience + "\n",
		"\nRequest: " + res.Grant.ID + "\n",
		"\nNonce: " + res.Grant.Nonce + "\n",
		"\nApprover: " + testSigner + "\n",
		"\nKit: " + testKitNetDiag + "\n",
		"\nDescription: Network diagnosis (read-only)\n",
		"\nGrants: graylog:read\n",
		"\nLeft out grants: unifi:read\n",
		"\nDuration: 2h from the approval\n",
		"\nUser: " + testUser + "\n",
		"\nConnection: " + testCaller + "\n",
		"\nReason, as the requester states it: " + testReason + "\n",
	} {
		if !strings.Contains(st.Text, want) {
			t.Errorf("statement lacks %q:\n%s", want, st.Text)
		}
	}
	if st.Whole || st.TTL != 2*time.Hour || len(res.Grant.Nonce) != 32 {
		t.Errorf("statement = %+v, nonce %q", st, res.Grant.Nonce)
	}
	// The same choices give the same text: ToolMesh can write it again.
	again, _ := env.svc.Statement(context.Background(), res.Grant.ID, testSigner, Approval{TTL: 2 * time.Hour, Grants: []string{testScopeGraylog}}, testAudience)
	if again.Text != st.Text {
		t.Error("the statement differs for the same choices")
	}

	for _, tc := range []struct {
		approver string
		a        Approval
		want     string
	}{
		{testApprover, Approval{}, "no approver"}, // alice approves with a key only
		{testSigner, Approval{TTL: 7 * time.Hour}, "exceeds"},
		{testSigner, Approval{Grants: []string{"graylog:write"}}, "no grant"},
	} {
		if _, err := env.svc.Statement(context.Background(), res.Grant.ID, tc.approver, tc.a, testAudience); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Statement(%s, %+v) = %v, want %q", tc.approver, tc.a, err, tc.want)
		}
	}
	if _, err := env.svc.Statement(context.Background(), "nope", testSigner, Approval{}, testAudience); !errors.Is(err, ErrNotFound) {
		t.Errorf("Statement of an unknown request = %v", err)
	}
}

func TestStatement_RequesterTextIsOneLine(t *testing.T) {
	env := newSigningEnv(t)
	uc := caller(testCaller)
	uc.CallerName = "Claude\nApprover: mallory"
	res, err := env.svc.Request(context.Background(), uc, RequestInput{Kit: testKitNetDiag, Reason: "fix it\nKit: admin-10min\u202e"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := env.svc.Statement(context.Background(), res.Grant.ID, testSigner, Approval{}, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(st.Text, "\nApprover: ") != 1 || strings.Count(st.Text, "\nKit: ") != 1 || strings.ContainsRune(st.Text, '\u202e') {
		t.Errorf("requester text breaks the statement's lines:\n%s", st.Text)
	}
}

func TestApproveSigned(t *testing.T) {
	env := newSigningEnv(t)
	ctx := context.Background()
	res := env.request(t, testKitNetDiag, "")
	g, st, err := env.signed(t, res.Grant.ID, testSignerKey, Approval{TTL: time.Hour})
	if err != nil {
		t.Fatalf("ApproveSigned: %v", err)
	}
	if g.State != StateActive || g.ApprovedBy != testSigner || g.ApprovedWith != ApprovedWithSignature || g.TTL != time.Hour || !st.Whole {
		t.Errorf("grant = %+v", g)
	}
	if g.Part == nil || !slices.Equal(g.Part.Grants, []string{testScopeGraylog, testScopeUnifi}) {
		t.Errorf("a signed grant keeps the entries it lists, got %+v", g.Part)
	}
	if kits, parts := env.svc.HeldKits(ctx, testUser, testCaller); !slices.Equal(kits, []string{testKitNetDiag}) || len(parts) != 0 {
		t.Errorf("HeldKits = %v, %v, want the whole kit", kits, parts)
	}
	last := env.audit.last(t)
	if last.Tool != auditApprove || last.Status != statusSuccess || last.Metadata["approved_with"] != ApprovedWithSignature ||
		last.Metadata["statement"] != st.Text || last.Metadata["signature"] == "" || last.Metadata["address"] == "" || len(last.Metadata["statement_sha256"]) != 64 {
		t.Errorf("audit = %+v", last)
	}

	// The signature approves once.
	if _, err := env.svc.ApproveSigned(ctx, res.Grant.ID, SignedApproval{Approver: testSigner, Approval: Approval{TTL: time.Hour}, Audience: testAudience, Signature: env.js.sign(testSignerKey, st.Text)}); !errors.Is(err, ErrNotFound) {
		t.Errorf("replay = %v, want not pending", err)
	}

	// The kit gains an entry: the signed grant does not.
	env.cat.kits[1].Grants = append(env.cat.kits[1].Grants, "netbox:read")
	kits, parts := env.svc.HeldKits(ctx, testUser, testCaller)
	if len(kits) != 0 || len(parts) != 1 || slices.Contains(parts[0].Grants, "netbox:read") {
		t.Errorf("after the kit grew: HeldKits = %v, %+v, want the signed entries only", kits, parts)
	}
}

func TestApproveSigned_Refuses(t *testing.T) {
	env := newSigningEnv(t)
	ctx := context.Background()
	res := env.request(t, testKitNetDiag, "")
	id := res.Grant.ID

	if _, _, err := env.signed(t, id, testOtherKey, Approval{}); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "does not belong") {
		t.Errorf("signature by another key = %v", err)
	}
	if last := env.audit.last(t); last.Status != statusError || last.Metadata["approved_with"] != ApprovedWithSignature {
		t.Errorf("refused signature audited as %+v", last)
	}

	// A signature of other choices does not approve these.
	st, _ := env.svc.Statement(ctx, id, testSigner, Approval{TTL: time.Hour}, testAudience)
	sig := env.js.sign(testSignerKey, st.Text)
	for _, sa := range []SignedApproval{
		{Approver: testSigner, Approval: Approval{TTL: 2 * time.Hour}, Audience: testAudience, Signature: sig},
		{Approver: testSigner, Approval: Approval{TTL: time.Hour}, Audience: "https://other.example.com", Signature: sig},
		{Approver: testSigner, Approval: Approval{TTL: time.Hour, Grants: []string{testScopeUnifi}}, Audience: testAudience, Signature: sig},
		{Approver: testApprover, Approval: Approval{TTL: time.Hour}, Audience: testAudience, Signature: sig},
		{Approver: testSigner, Approval: Approval{TTL: time.Hour}, Audience: testAudience, Signature: "smpAA=="},
	} {
		if _, err := env.svc.ApproveSigned(ctx, id, sa); !errors.Is(err, ErrInvalid) {
			t.Errorf("ApproveSigned(%+v) = %v, want refused", sa.Approval, err)
		}
	}
	if _, err := env.svc.Lookup(ctx, id); err != nil {
		t.Errorf("the request is gone after refused signatures: %v", err)
	}
}

func TestApproveSigned_Part(t *testing.T) {
	env := newSigningEnv(t)
	res := env.request(t, testKitNetDiag, "")
	g, st, err := env.signed(t, res.Grant.ID, testSignerKey, Approval{Grants: []string{testScopeUnifi}})
	if err != nil {
		t.Fatal(err)
	}
	if st.Whole || !strings.Contains(st.Text, "\nLeft out grants: graylog:read\n") {
		t.Errorf("statement:\n%s", st.Text)
	}
	kits, parts := env.svc.HeldKits(context.Background(), testUser, testCaller)
	if len(kits) != 0 || len(parts) != 1 || !slices.Equal(parts[0].Grants, []string{testScopeUnifi}) {
		t.Errorf("HeldKits = %v, %+v, want the part", kits, parts)
	}
	if v := env.svc.view(g); v.Part == nil || v.ApprovedWith != ApprovedWithSignature {
		t.Errorf("view = %+v", v)
	}
}

func TestApproveWith_KeyPart(t *testing.T) {
	env := newSigningEnv(t)
	ctx := context.Background()
	res := env.request(t, testKitNetDiag, "")
	// Naming every entry with a key is the whole kit, as before.
	g, err := env.svc.ApproveWith(ctx, testApprover, res.Grant.ID, Approval{Grants: []string{testScopeUnifi, testScopeGraylog}})
	if err != nil || g.Part != nil || g.ApprovedWith != ApprovedWithKey {
		t.Fatalf("ApproveWith every entry = %+v, %v", g, err)
	}
	res = env.request(t, testKitAdmin, "")
	if _, err := env.svc.ApproveWith(ctx, testApprover, res.Grant.ID, Approval{Grants: []string{testScopeGraylog}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("ApproveWith an entry the kit lacks = %v", err)
	}
}

func TestFingerprint(t *testing.T) {
	g := Grant{ID: "abc", Nonce: "n", Kit: "k", UserID: "u", CallerID: "c", TTL: time.Hour, Reason: "r"}
	fp := g.Fingerprint()
	if len(fp) != 19 || strings.Count(fp, "-") != 3 || strings.ToUpper(fp) != fp {
		t.Errorf("Fingerprint = %q", fp)
	}
	other := g
	other.Reason = "r2"
	if other.Fingerprint() == fp {
		t.Error("the fingerprint does not depend on the reason")
	}
}

// serve calls the approval handler.
func serve(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestApprovalHandler(t *testing.T) {
	env := newSigningEnv(t)
	env.cat.kits[1].Description = `Network <script>alert(1)</script> diagnosis`
	res := env.request(t, testKitNetDiag, "")
	id := res.Grant.ID
	h := env.svc.ApprovalHandler()

	page := serve(t, h, http.MethodGet, ApprovePathPrefix+"/"+id, nil)
	body := page.Body.String()
	if page.Code != http.StatusOK || !strings.Contains(page.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("page = %d, CSP %q", page.Code, page.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(body, `property="og:title"`) || !strings.Contains(body, res.Grant.Fingerprint()) || strings.Contains(body, "<script>alert") {
		t.Errorf("page does not show an escaped preview:\n%s", body)
	}
	if strings.Contains(body, testReason) {
		t.Error("the link preview shows the requester's reason")
	}
	if code := serve(t, h, http.MethodGet, ApprovePathPrefix+"/nope", nil).Code; code != http.StatusNotFound {
		t.Errorf("page of an unknown request = %d", code)
	}
	if setup := serve(t, h, http.MethodGet, ApprovePathPrefix+"/", nil); setup.Code != http.StatusOK || !strings.Contains(setup.Body.String(), "Set up a signing key") {
		t.Errorf("setup page = %d", setup.Code)
	}
	for name, ctype := range approveAssets {
		if rec := serve(t, h, http.MethodGet, ApprovePathPrefix+"/"+name, nil); rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ctype {
			t.Errorf("asset %s = %d %q", name, rec.Code, rec.Header().Get("Content-Type"))
		}
	}

	var view approvalView
	rec := serve(t, h, http.MethodGet, ApprovePathPrefix+"/"+id+"/request", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("request view = %d %s", rec.Code, rec.Body)
	}
	if len(view.Approvers) != 1 || view.Approvers[0].Name != testSigner || view.Fingerprint != res.Grant.Fingerprint() || len(view.Entries) != 2 || view.TTLChoices[0] != "4h" {
		t.Errorf("request view = %+v", view)
	}

	choice := approvalBody{Approver: testSigner, TTL: "2h", Grants: []string{testScopeGraylog, testScopeUnifi}}
	var st statementView
	rec = serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id+"/statement", choice)
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != http.StatusOK || !st.Whole {
		t.Fatalf("statement = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(st.Statement, "\nToolMesh: "+testAudience+"\n") {
		t.Errorf("statement does not name the public URL:\n%s", st.Statement)
	}

	wrong := choice
	wrong.Signature = env.js.sign(testOtherKey, st.Statement)
	if rec := serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id, wrong); rec.Code != http.StatusBadRequest {
		t.Errorf("approve with another key = %d %s", rec.Code, rec.Body)
	}
	choice.Signature = env.js.sign(testSignerKey, st.Statement)
	var done signedView
	rec = serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id, choice)
	if err := json.Unmarshal(rec.Body.Bytes(), &done); err != nil || rec.Code != http.StatusOK || done.Status != StateActive || done.TTL != "2h" || done.Part != nil {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id, choice); rec.Code != http.StatusNotFound {
		t.Errorf("second approval = %d, want 404", rec.Code)
	}
	if rec := serve(t, h, http.MethodPost, ApprovePathPrefix+"/"+id, approvalBody{Approver: testSigner}); rec.Code != http.StatusBadRequest {
		t.Errorf("approval without signature = %d", rec.Code)
	}
}

func TestApprovalURL(t *testing.T) {
	env := newTestEnv(t)
	if got := env.svc.ApprovalURL("abc"); got != "" {
		t.Errorf("ApprovalURL without public URL and signers = %q", got)
	}
	signing := newSigningEnv(t)
	if got := signing.svc.ApprovalURL("abc"); got != testAudience+"/approve/abc" {
		t.Errorf("ApprovalURL = %q", got)
	}
	signing.svc.publicURL = ""
	if got := signing.svc.ApprovalURL("abc"); got != "" {
		t.Errorf("ApprovalURL without public URL = %q", got)
	}
}
