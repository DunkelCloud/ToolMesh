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

package authz

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// benchEngine opens an engine with the team preset plus a few hundred
// per-tool grants, so checks have to look past irrelevant tuples.
func benchEngine(b *testing.B) *Embedded {
	b.Helper()
	e, err := OpenEmbedded(context.Background(), EmbeddedOptions{Path: filepath.Join(b.TempDir(), DBFileName)})
	if err != nil {
		b.Fatalf("OpenEmbedded: %v", err)
	}
	b.Cleanup(func() { _ = e.Close() })
	grants, _ := PresetGrants(PresetTeam, testOwner)
	tools := make([]string, 300)
	for i := range tools {
		tools[i] = fmt.Sprintf("backend%d_tool%d", i%20, i)
	}
	grants = append(grants, Grant{Role: testRoleOps, Tools: tools}, Grant{Company: testAcme, Backends: []string{"backend1", "backend2"}})
	if _, err := e.Apply(context.Background(), grants); err != nil {
		b.Fatalf("Apply: %v", err)
	}
	return e
}

// A caller with a plan and roles that grant nothing for the tool: every
// relation of the model is evaluated before the answer is "no".
var benchDenied = Request{
	UserID: testCarol, CompanyID: "other", Plan: PlanFree, Roles: []string{"viewer", "support"},
	Tool: "backend7_tool7", Backend: "backend7", Access: testWrite,
}

func BenchmarkEmbeddedCheck_Allowed(b *testing.B) {
	e := benchEngine(b)
	req := Request{UserID: testBob, Plan: PlanPro, Tool: "backend7_tool7", Backend: "backend7", Access: testWrite}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if ok, err := e.Check(ctx, req); err != nil || !ok {
			b.Fatalf("Check = %v, %v", ok, err)
		}
	}
}

func BenchmarkEmbeddedCheck_Denied(b *testing.B) {
	e := benchEngine(b)
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if ok, err := e.Check(ctx, benchDenied); err != nil || ok {
			b.Fatalf("Check = %v, %v", ok, err)
		}
	}
}

// BenchmarkEmbeddedCheck_Parallel measures checks from many goroutines at
// once, as concurrent tool calls produce them.
func BenchmarkEmbeddedCheck_Parallel(b *testing.B) {
	e := benchEngine(b)
	ctx := context.Background()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.Check(ctx, benchDenied); err != nil {
				b.Fatalf("Check: %v", err)
			}
		}
	})
}

// BenchmarkEmbeddedCheck_ParallelDuringApply runs checks while the grants are
// rewritten in a loop, the worst case for SQLite locking.
func BenchmarkEmbeddedCheck_ParallelDuringApply(b *testing.B) {
	e := benchEngine(b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		alt := []Grant{{Role: testRoleOps, Backends: []string{"backend3"}}}
		for i := 0; ctx.Err() == nil; i++ {
			grants, _ := PresetGrants(PresetTeam, testOwner)
			if i%2 == 0 {
				grants = append(grants, alt...)
			}
			if _, err := e.Apply(ctx, grants); err != nil && ctx.Err() == nil {
				b.Errorf("Apply: %v", err)
				return
			}
		}
	}()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := e.Check(context.Background(), benchDenied); err != nil {
				b.Errorf("Check: %v", err)
				return
			}
		}
	})
	b.StopTimer()
	cancel()
	<-done
}

// BenchmarkEmbeddedCheckBatch_ToolListing filters a listing of 3000 tools
// across 40 backends and four access classes for one caller, as discover_tools
// does.
func BenchmarkEmbeddedCheckBatch_ToolListing(b *testing.B) {
	e := benchEngine(b)
	access := []string{AccessRead, testWrite, RoleAdmin, testDangerous}
	reqs := make([]Request, 3000)
	for i := range reqs {
		backend := fmt.Sprintf("backend%d", i%40)
		reqs[i] = Request{UserID: testCarol, Plan: PlanFree, Roles: []string{testRoleOps},
			Tool: fmt.Sprintf("%s_tool%d", backend, i), Backend: backend, Access: access[i%len(access)]}
	}
	ctx := context.Background()
	b.ResetTimer()
	for b.Loop() {
		if _, err := e.CheckBatch(ctx, reqs); err != nil {
			b.Fatalf("CheckBatch: %v", err)
		}
	}
}
