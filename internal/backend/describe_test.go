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
	"log/slog"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/dadl"
)

// TestRESTAdapter_DescriptorDeprecationAndReturns pins the LLM-facing
// descriptor decoration (spec §6.5/§6.7): the deprecation marker leads the
// description and the returns type trails it, in LookupTool and ListTools
// alike.
func TestRESTAdapter_DescriptorDeprecationAndReturns(t *testing.T) {
	spec := &dadl.Spec{
		Spec: testDADLSpecURL,
		Backend: dadl.BackendDef{
			Name:    testBackendNameAPI,
			Type:    transportTypeREST,
			BaseURL: "https://api.example.com",
			Types: map[string]any{
				"Customer": map[string]any{
					schemaKeyType:     schemaTypeObject,
					"properties":      map[string]any{"id": map[string]any{schemaKeyType: schemaTypeString}},
					schemaKeyRequired: []any{"id"},
				},
			},
			Tools: map[string]dadl.ToolDef{
				testToolGetCustomer: {
					Method: testMethodGET, Path: "/customers/{id}",
					Description: testDescGetItem,
					Returns:     "Customer",
					Params:      map[string]dadl.ParamDef{"id": {Type: schemaTypeString, In: "path", Required: true}},
				},
				"get_customer_v1": {
					Method: testMethodGET, Path: "/v1/customers/{id}",
					Description: "Old endpoint",
					Deprecated:  "slow",
					ReplacedBy:  testToolGetCustomer,
					Params:      map[string]dadl.ParamDef{"id": {Type: schemaTypeString, In: "path", Required: true}},
				},
			},
		},
	}
	a, err := NewRESTAdapter(spec, &testCredStore{}, slog.Default(), testRESTOpts)
	if err != nil {
		t.Fatal(err)
	}

	desc, ok := a.LookupTool("get_customer_v1")
	if !ok {
		t.Fatal("tool not found")
	}
	if !strings.HasPrefix(desc.Description, "DEPRECATED: slow — use "+testToolGetCustomer+" instead.") {
		t.Errorf("deprecation marker must lead the description, got %q", desc.Description)
	}

	desc, ok = a.LookupTool(testToolGetCustomer)
	if !ok {
		t.Fatal("tool not found")
	}
	if !strings.Contains(desc.Description, "Returns: Customer") {
		t.Errorf("returns note missing, got %q", desc.Description)
	}
	if strings.Contains(desc.Description, "DEPRECATED") {
		t.Errorf("non-deprecated tool must not carry the marker: %q", desc.Description)
	}

	// ListTools carries the same decoration.
	tools, err := a.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]ToolDescriptor{}
	for _, td := range tools {
		byName[td.Name] = td
	}
	if !strings.Contains(byName["get_customer_v1"].Description, "DEPRECATED") {
		t.Errorf("ListTools missing deprecation marker: %q", byName["get_customer_v1"].Description)
	}
	if !strings.Contains(byName[testToolGetCustomer].Description, "Returns: Customer") {
		t.Errorf("ListTools missing returns note: %q", byName[testToolGetCustomer].Description)
	}
}
