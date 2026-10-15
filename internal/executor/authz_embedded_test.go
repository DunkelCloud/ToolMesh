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
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/audit"
	"github.com/DunkelCloud/ToolMesh/internal/authz"
	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

// Names shared by the embedded-authorization tests.
const (
	testPlanPro            = "pro"
	testPlanFree           = "free"
	testToolWebFetch       = "web_fetch"
	testToolWebSearchQuery = "web_search_query"
)

// newEmbeddedExecutor builds an executor with the embedded engine and a
// composite backend with the backends "web" and "web_search", whose names
// share a prefix.
func newEmbeddedExecutor(t *testing.T, grants []authz.Grant) (*Executor, *recordingAudit) {
	t.Helper()
	engine, err := authz.OpenEmbedded(context.Background(), authz.EmbeddedOptions{Path: filepath.Join(t.TempDir(), authz.DBFileName)})
	if err != nil {
		t.Fatalf("OpenEmbedded: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })
	if _, err := engine.Apply(context.Background(), grants); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	composite := backend.NewCompositeBackend(map[string]backend.ToolBackend{
		"web":        &mockBackend{},
		"web_search": &mockBackend{},
	})
	rec := &recordingAudit{}
	return New(engine, nil, composite, nil, rec, time.Second, newTestLogger(), nil, nil), rec
}

func callerCtx(uc *userctx.UserContext) context.Context {
	return userctx.WithUserContext(context.Background(), uc)
}

func TestExecuteTool_EmbeddedAuthz(t *testing.T) {
	exec, rec := newEmbeddedExecutor(t, []authz.Grant{
		{Plan: testPlanPro, Backends: []string{"web"}},
		{Role: "searcher", Backends: []string{"web_search"}},
	})

	tests := []struct {
		name    string
		caller  *userctx.UserContext
		tool    string
		allowed bool
	}{
		{"backend grant", &userctx.UserContext{UserID: "u1", Plan: testPlanPro}, testToolWebFetch, true},
		// Routed to web_search by longest prefix: the grant on "web" must not
		// cover it, although the name starts with "web_".
		{"grant on a shorter backend name", &userctx.UserContext{UserID: "u1", Plan: testPlanPro}, testToolWebSearchQuery, false},
		{"role grant on the longer backend name", &userctx.UserContext{UserID: "u2", Roles: []string{"searcher"}}, testToolWebSearchQuery, true},
		{"no grant", &userctx.UserContext{UserID: "u3", Plan: testPlanFree}, testToolWebFetch, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec.last = audit.AuditEntry{}
			res, err := exec.ExecuteTool(callerCtx(tc.caller), ExecuteToolRequest{ToolName: tc.tool})
			if err != nil {
				t.Fatalf("ExecuteTool: %v", err)
			}
			if res.IsError == tc.allowed {
				t.Fatalf("IsError = %v, want allowed=%v (content %v)", res.IsError, tc.allowed, res.Content)
			}
			wantStatus := statusSuccess
			if !tc.allowed {
				wantStatus = statusDenied
			}
			if rec.last.Status != wantStatus || rec.last.Tool != tc.tool {
				t.Errorf("audit entry = %s/%q, want %s/%q", rec.last.Tool, rec.last.Status, tc.tool, wantStatus)
			}
		})
	}
}

func TestCheckChild_EmbeddedAuthz(t *testing.T) {
	exec, _ := newEmbeddedExecutor(t, []authz.Grant{{User: "u1", Tools: []string{testToolWebFetch}}})
	ctx := callerCtx(&userctx.UserContext{UserID: "u1"})
	if err := exec.CheckChild(ctx, testToolWebFetch, nil); err != nil {
		t.Errorf("granted child call rejected: %v", err)
	}
	err := exec.CheckChild(ctx, testToolWebSearchQuery, nil)
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Errorf("ungranted child call: err = %v, want not authorized", err)
	}
}

func TestFilterAuthorizedTools_Embedded(t *testing.T) {
	exec, _ := newEmbeddedExecutor(t, []authz.Grant{
		{Plan: testPlanFree, Access: []string{testAccessRead}},
		{User: "u1", Tools: []string{"web_search_delete"}},
	})
	tools := []backend.ToolDescriptor{
		{Name: testToolWebFetch, Access: testAccessRead},
		{Name: "web_post", Access: "write"},
		{Name: testToolWebSearchQuery, Access: testAccessRead},
		{Name: "web_search_delete", Access: "dangerous"},
	}

	got := exec.FilterAuthorizedTools(context.Background(), &userctx.UserContext{UserID: "u1", Plan: testPlanFree}, tools)
	names := make([]string, 0, len(got))
	for _, d := range got {
		names = append(names, d.Name)
	}
	if want := "web_fetch,web_search_query,web_search_delete"; strings.Join(names, ",") != want {
		t.Errorf("filtered = %v, want %s", names, want)
	}

	if got := exec.FilterAuthorizedTools(context.Background(), nil, tools); len(got) != 0 {
		t.Errorf("no caller: filtered = %v, want none", got)
	}
}

// recordingAudit must satisfy the interface the executor writes to.
var _ audit.AuditStore = (*recordingAudit)(nil)
