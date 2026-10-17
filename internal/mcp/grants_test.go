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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/grants"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names of the grant tests.
const (
	testGrantApprover = "alice"
	testGrantCaller   = "claude-code"
	testGrantReason   = "Debug the UniFi outage"
	// Scopes of the kit net-diag-read.
	testScopeGraylogRead = "graylog:read"
	testScopeUnifiRead   = "unifi:read"
)

// newGrantSetup is the kit setup with the approver alice and kit grants on
// a memory store.
func newGrantSetup(t *testing.T) (kitSetup, *grants.Service) {
	t.Helper()
	sum := sha256.Sum256([]byte("approver key of the grant tests"))
	s := newKitSetup(t, []authz.Approver{{Name: testGrantApprover, KeySHA256: hex.EncodeToString(sum[:])}})
	svc := grants.New(grants.Options{Store: grants.NewMemoryStore(), Kits: s.engine, Approvers: s.engine, Audit: s.audit, Logger: newQuietMCPLogger()})
	s.exec.SetKitHolder(svc)
	s.handler.SetGrants(svc)
	return s, svc
}

// grantCaller is bob, connected as callerID.
func grantCaller(callerID string) context.Context {
	return userctx.WithUserContext(context.Background(), &userctx.UserContext{UserID: testKitUserBob, CallerID: callerID, Authenticated: true})
}

// callTool calls a tool and returns whether it failed and its text.
func callTool(t *testing.T, h *Handler, ctx context.Context, tool string, params map[string]any) (failed bool, text string) {
	t.Helper()
	res, err := h.HandleToolCall(ctx, tool, params)
	if err != nil {
		t.Fatalf("HandleToolCall(%s): %v", tool, err)
	}
	return res.IsError, resultText(t, res)
}

func TestRequestGrant_Listed(t *testing.T) {
	without, _ := newKitHandler(t)
	s, _ := newGrantSetup(t)
	for _, tc := range []struct {
		name string
		h    *Handler
		want bool
	}{{"without grants", without, false}, {"with grants", s.handler, true}} {
		tools, err := tc.h.BuildToolList(grantCaller(testGrantCaller))
		if err != nil {
			t.Fatal(err)
		}
		listed := false
		for _, d := range tools {
			listed = listed || d.Name == toolRequestGrant
		}
		if listed != tc.want {
			t.Errorf("%s: request_grant listed = %v, want %v", tc.name, listed, tc.want)
		}
	}
}

// The whole path: denied, asked, approved, allowed for the caller that asked
// only, revoked.
func TestRequestGrant_EndToEnd(t *testing.T) {
	s, svc := newGrantSetup(t)
	h := s.handler
	ctx := grantCaller(testGrantCaller)

	failed, text := callTool(t, h, ctx, testGraylogSearch, map[string]any{})
	if !failed || !strings.Contains(text, toolRequestGrant) || !strings.Contains(text, testKitNetDiag) {
		t.Fatalf("call before the grant: failed=%v %q, want a denial naming the kit and %s", failed, text, toolRequestGrant)
	}

	failed, text = callTool(t, h, ctx, toolRequestGrant, map[string]any{argNameKit: testKitNetDiag, argNameReason: testGrantReason, argNameTTL: "2h"})
	if failed {
		t.Fatalf("request_grant failed: %s", text)
	}
	var answer grantAnswer
	if err := json.Unmarshal([]byte(text), &answer); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, text)
	}
	if answer.Status != grants.StatePending || answer.TTL != "2h" || answer.Description != "Network diagnosis (read-only)" ||
		answer.Warning != "Production systems." || answer.RequestID == "" || !strings.Contains(answer.Note, answer.RequestID) {
		t.Errorf("answer = %+v", answer)
	}

	rights := askRightsAs(t, h, ctx, map[string]any{argNameTools: []any{testGraylogSearch}})
	if len(rights.Requests) != 1 || rights.Requests[0].ID != answer.RequestID || len(rights.Grants) != 0 ||
		!strings.Contains(rights.Note, toolRequestGrant) || rights.Tools[0].Verdict != executor.VerdictEscalatable {
		t.Errorf("rights while pending = %+v", rights)
	}

	if _, err := svc.Approve(context.Background(), testGrantApprover, answer.RequestID, 0); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	if failed, text := callTool(t, h, ctx, testGraylogSearch, map[string]any{}); failed {
		t.Fatalf("call with the grant failed: %s", text)
	}
	if e := s.audit.entries[len(s.audit.entries)-1]; e.Tool != testGraylogSearch || e.Error != "" || e.Metadata["held_kits"] != testKitNetDiag {
		t.Errorf("audit of the call = %+v, want held_kits recorded", e)
	}
	// The kit covers reading only.
	if failed, _ := callTool(t, h, ctx, testGraylogDelete, map[string]any{}); !failed {
		t.Error("a write tool the kit does not cover was allowed")
	}
	// Another connection of the same user does not hold the kit.
	if failed, _ := callTool(t, h, grantCaller("claude-desktop"), testGraylogSearch, map[string]any{}); !failed {
		t.Error("the grant applied to another caller of the same user")
	}

	rights = askRightsAs(t, h, ctx, map[string]any{argNameTools: []any{testGraylogSearch, testUnifiClients}})
	if len(rights.Grants) != 1 || rights.Grants[0].Kit != testKitNetDiag || (rights.Grants[0].Remaining != "2h" && rights.Grants[0].Remaining != "1h59m") ||
		len(rights.Requests) != 0 || rights.Bundle != nil {
		t.Errorf("rights with the grant = %+v", rights)
	}
	for _, tool := range rights.Tools {
		if tool.Verdict != executor.VerdictAllowed {
			t.Errorf("verdict of %s = %s, want allowed", tool.Tool, tool.Verdict)
		}
	}
	if len(rights.Kits) != 1 || rights.Kits[0].Warning == "" {
		t.Errorf("held kit not described with its warning: %+v", rights.Kits)
	}

	if _, err := svc.Revoke(context.Background(), testGrantApprover, answer.RequestID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if failed, _ := callTool(t, h, ctx, testGraylogSearch, map[string]any{}); !failed {
		t.Error("call allowed after the grant was revoked")
	}
}

func TestRequestGrant_InvalidArguments(t *testing.T) {
	s, _ := newGrantSetup(t)
	ctx := grantCaller(testGrantCaller)
	tests := []struct {
		name   string
		params map[string]any
		want   string
	}{
		{"no reason", map[string]any{argNameKit: testKitNetDiag}, "request_grant: give a reason"},
		{"unknown kit", map[string]any{argNameKit: "nope", argNameReason: testGrantReason}, `there is no kit "nope"`},
		{"kit not a string", map[string]any{argNameKit: 3, argNameReason: testGrantReason}, "kit must be a string"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			failed, text := callTool(t, s.handler, ctx, toolRequestGrant, tc.params)
			if !failed || !strings.Contains(text, tc.want) {
				t.Errorf("result = failed %v %q, want an error containing %q", failed, text, tc.want)
			}
		})
	}
}

func TestRequestGrant_AlreadyPending(t *testing.T) {
	s, _ := newGrantSetup(t)
	ctx := grantCaller(testGrantCaller)
	params := map[string]any{argNameKit: testKitNetDiag, argNameReason: testGrantReason}
	_, first := callTool(t, s.handler, ctx, toolRequestGrant, params)
	_, second := callTool(t, s.handler, ctx, toolRequestGrant, params)
	var a, b grantAnswer
	_ = json.Unmarshal([]byte(first), &a)
	_ = json.Unmarshal([]byte(second), &b)
	if a.RequestID == "" || b.RequestID != a.RequestID || !b.AlreadyPending || a.AlreadyPending {
		t.Errorf("first %+v, second %+v; want the same request, marked already pending", a, b)
	}
}

func TestRequestGrant_WithoutService(t *testing.T) {
	h, _ := newKitHandler(t)
	if failed, text := callTool(t, h, grantCaller(testGrantCaller), toolRequestGrant, map[string]any{}); !failed || !strings.Contains(text, "cannot be granted") {
		t.Errorf("result = failed %v %q", failed, text)
	}
}

// With an approver who signs and a public URL, request_grant answers with
// the approval link, the fingerprint and what the kit would add; a grant of
// part of the kit allows that part only and tell_me_my_rights shows it.
func TestRequestGrant_ApprovalLinkAndPart(t *testing.T) {
	const publicURL = "https://toolmesh.example.com"
	s := newKitSetup(t, []authz.Approver{{Name: testGrantApprover, Address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}})
	svc := grants.New(grants.Options{Store: grants.NewMemoryStore(), Kits: s.engine, Approvers: s.engine, Audit: s.audit, Logger: newQuietMCPLogger(), PublicURL: publicURL + "/"})
	s.exec.SetKitHolder(svc)
	s.handler.SetGrants(svc)
	ctx := grantCaller(testGrantCaller)

	failed, text := callTool(t, s.handler, ctx, toolRequestGrant, map[string]any{argNameKit: testKitNetDiag, argNameReason: testGrantReason})
	if failed {
		t.Fatalf("request_grant failed: %s", text)
	}
	var answer grantAnswer
	if err := json.Unmarshal([]byte(text), &answer); err != nil {
		t.Fatal(err)
	}
	req, err := svc.Lookup(context.Background(), answer.RequestID)
	if err != nil {
		t.Fatal(err)
	}
	if answer.ApprovalURL != publicURL+"/approve/"+answer.RequestID || answer.Fingerprint != req.Fingerprint() || !strings.Contains(answer.Note, "approval_url") {
		t.Errorf("answer = %+v", answer)
	}
	want := map[string]grants.EntryCoverage{
		testScopeGraylogRead: {Entry: testScopeGraylogRead, Tools: 1, New: 1},
		testScopeUnifiRead:   {Entry: testScopeUnifiRead, Tools: 1, New: 1},
	}
	if len(req.Coverage) != 2 || req.Coverage[0] != want[req.Coverage[0].Entry] || req.Coverage[1] != want[req.Coverage[1].Entry] {
		t.Errorf("coverage = %+v", req.Coverage)
	}

	if _, err := svc.ApproveWith(context.Background(), testGrantApprover, answer.RequestID, grants.Approval{Grants: []string{testScopeGraylogRead}}); err != nil {
		t.Fatal(err)
	}
	if failed, text := callTool(t, s.handler, ctx, testGraylogSearch, map[string]any{}); failed {
		t.Errorf("the granted part is denied: %s", text)
	}
	if e := s.audit.entries[len(s.audit.entries)-1]; e.Metadata["held_kits"] != testKitNetDiag+" (part)" {
		t.Errorf("audit of the call = %+v", e.Metadata)
	}
	if failed, _ := callTool(t, s.handler, ctx, testUnifiClients, map[string]any{}); !failed {
		t.Error("the left-out part of the kit is allowed")
	}
	rights := askRightsAs(t, s.handler, ctx, map[string]any{})
	if len(rights.Grants) != 1 || rights.Grants[0].Part == nil || rights.Grants[0].Part.Grants[0] != testScopeGraylogRead {
		t.Errorf("rights = %+v", rights.Grants)
	}
}

// askRightsAs calls tell_me_my_rights in the given caller context.
func askRightsAs(t *testing.T, h *Handler, ctx context.Context, params map[string]any) rightsAnswer {
	t.Helper()
	failed, text := callTool(t, h, ctx, toolTellMeMyRights, params)
	if failed {
		t.Fatalf("tell_me_my_rights failed: %s", text)
	}
	var a rightsAnswer
	if err := json.Unmarshal([]byte(text), &a); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, text)
	}
	return a
}
