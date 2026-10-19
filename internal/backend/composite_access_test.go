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

package backend

import (
	"context"
	"testing"
)

// Fixture names for the access pass-through test, kept as constants so the
// literals do not pile up across the package's test files.
const (
	accessStubBackend  = "api"
	accessStubList     = "list_zones"
	accessStubPurge    = "purge_zones"
	accessStubScript   = "run_script"
	accessStubPlain    = "ping"
	accessStubPassRun  = "p_run"
	accessStubClassR   = "read"
	accessStubClassD   = "dangerous"
	accessStubClassA   = "admin"
	accessStubClassX   = "execute"
	accessStubNoAccess = ""
)

// TestCompositeBackend_ListTools_PassesAccessThrough pins the access
// classification on the discovery path: ListTools must carry each tool's
// Access for named backends (whose descriptors it rebuilds under the public
// prefix) as well as for passthroughs, and for every listed tool the value
// must equal what LookupTool — the gate's and audit's view — reports.
func TestCompositeBackend_ListTools_PassesAccessThrough(t *testing.T) {
	named := &lookupStub{name: accessStubBackend, tools: map[string]ToolDescriptor{
		accessStubList:   {Name: accessStubList, Access: accessStubClassR},
		accessStubPurge:  {Name: accessStubPurge, Access: accessStubClassD},
		accessStubScript: {Name: accessStubScript, Access: accessStubClassX},
		accessStubPlain:  {Name: accessStubPlain},
	}}
	pass := &lookupStub{name: "p", tools: map[string]ToolDescriptor{
		accessStubPassRun: {Name: accessStubPassRun, Access: accessStubClassA},
	}}
	c := NewCompositeBackend(map[string]ToolBackend{accessStubBackend: named})
	c.AddPassthrough(pass)

	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	prefix := accessStubBackend + "_"
	want := map[string]string{
		prefix + accessStubList:   accessStubClassR,
		prefix + accessStubPurge:  accessStubClassD,
		prefix + accessStubScript: accessStubClassX,
		prefix + accessStubPlain:  accessStubNoAccess,
		accessStubPassRun:         accessStubClassA,
	}
	if len(tools) != len(want) {
		t.Fatalf("got %d tools, want %d", len(tools), len(want))
	}
	for _, d := range tools {
		access, known := want[d.Name]
		if !known {
			t.Errorf("unexpected tool %q in ListTools", d.Name)
			continue
		}
		if d.Access != access {
			t.Errorf("ListTools %s: Access = %q, want %q", d.Name, d.Access, access)
		}
		desc, found := c.LookupTool(d.Name)
		if !found {
			t.Errorf("LookupTool(%s) not found although ListTools lists it", d.Name)
			continue
		}
		if desc.Access != d.Access {
			t.Errorf("%s: LookupTool Access = %q but ListTools Access = %q — gate and discovery disagree", d.Name, desc.Access, d.Access)
		}
	}
}
