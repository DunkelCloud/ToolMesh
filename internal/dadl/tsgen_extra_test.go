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

package dadl

import (
	"strings"
	"testing"
)

func TestGenerateTypeScript_Composites(t *testing.T) {
	spec := &Spec{
		Spec: "https://dadl.ai/spec/dadl-spec-v0.1.md",
		Backend: BackendDef{
			Name: "api",
			Type: "rest",
			Composites: map[string]CompositeDef{
				"do_thing": {
					Description: "composite",
					Params: map[string]ParamDef{
						"id":      {Type: "string", Required: true},
						"verbose": {Type: "boolean"},
					},
					Code: "return 1",
				},
				"no_params": {
					Description: "composite without params",
					Code:        "return 1",
				},
			},
		},
	}
	ts := GenerateTypeScript(spec)
	if !strings.Contains(ts, "do_thing") {
		t.Errorf("missing composite name")
	}
	if !strings.Contains(ts, "id: string") {
		t.Errorf("missing required param")
	}
	if !strings.Contains(ts, "verbose?: boolean") {
		t.Errorf("missing optional param")
	}
}

func TestBuildCompositeParamType_Empty(t *testing.T) {
	if got := buildCompositeParamType(CompositeDef{}); got != "" {
		t.Errorf("empty: got %q", got)
	}
}
