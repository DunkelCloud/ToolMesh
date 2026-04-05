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

package tsdef

import (
	"testing"
)

func TestParseSource_ComplexTypes(t *testing.T) {
	src := `
/** Fetch user data */
export function getUser(params: {
  id: number;
  include_deleted?: boolean;
  tags?: string[];
}): Promise<any>;

/** Simple operation */
export function simple(): Promise<any>;
`
	tools, err := ParseSource(src, "test.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	var getUser ToolDef
	for _, td := range tools {
		if td.Name == "getUser" {
			getUser = td
		}
	}
	if len(getUser.Params) == 0 {
		t.Error("getUser has no params")
	}
}
