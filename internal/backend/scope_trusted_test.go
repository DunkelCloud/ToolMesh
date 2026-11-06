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
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestDeclaredDestinations_Reachable pins that with allow_private_url only
// the hosts of tools that can be called count as declared private
// destinations: a tool outside include_tools does not make its host
// dialable for redirects, the health check tool does.
func TestDeclaredDestinations_Reachable(t *testing.T) {
	spec := &dadl.Spec{Backend: dadl.BackendDef{
		Name:    scopeEntryName,
		BaseURL: testBaseURLExample,
		Tools: map[string]dadl.ToolDef{
			reachNear: {Method: testMethodGET, Path: bindingPath},
			reachFar:  {Method: testMethodGET, Path: "http://10.0.0.7:8080/x"},
			"probe":   {Method: testMethodGET, Path: "http://10.0.0.8:9000/h"},
		},
		Health: &dadl.HealthConfig{Tool: "probe"},
	}}
	got := declaredDestinations(spec, reachableTools(spec, []string{reachNear}))
	for want, in := range map[string]bool{"api.example.com:443": true, "10.0.0.8:9000": true, "10.0.0.7:8080": false} {
		if got[want] != in {
			t.Errorf("trusted[%s] = %v, want %v (all: %v)", want, got[want], in, got)
		}
	}
	if all := declaredDestinations(spec, reachableTools(spec, nil)); !all["10.0.0.7:8080"] {
		t.Errorf("without include_tools every tool host counts: %v", all)
	}
}
