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

func TestCheckToolPathQuery(t *testing.T) {
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"/things/{id}", false},
		{"/things/{id}/parts/{part}", false},
		{"/things?format=json", false},
		{"https://api.example.com/v1/{id}", false},
		{"/search?q={q}", true},
		{"/things/{id}?expand={what}", true},
		{"/things?format=json&q={q}", true},
		{"https://api.example.com/v1/{id}?q={q}", true},
		{"/things/{id}#{anchor}", true},
		{"/things#x?{q}", true},
	}
	for _, c := range cases {
		err := CheckToolPathQuery(c.path)
		if (err != nil) != c.wantErr {
			t.Errorf("CheckToolPathQuery(%q) = %v, wantErr %v", c.path, err, c.wantErr)
		}
	}
}

// TestParse_PlaceholderInQueryOfPath pins that a DADL whose tool path
// carries a path parameter in its query part is refused when it is parsed,
// with a message that names the remedy. Path parameters are escaped as path
// segments, so "&" and "=" in the value would add query parameters.
func TestParse_PlaceholderInQueryOfPath(t *testing.T) {
	const doc = `spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
backend:
  name: search
  type: rest
  base_url: "https://api.example.com"
  description: "Search"
  auth:
    type: bearer
    credential: none
  tools:
    find:
      method: GET
      path: PATH
      description: "Find"
      params:
        q:
          type: string
          in: IN
`
	bad := strings.NewReplacer("PATH", `"/search?q={q}"`, "IN", "path").Replace(doc)
	if _, err := ParseBytes([]byte(bad)); err == nil || !strings.Contains(err.Error(), "in: query") {
		t.Errorf("ParseBytes accepted a placeholder in the query part, or does not name the remedy: %v", err)
	}
	good := strings.NewReplacer("PATH", "/search", "IN", "query").Replace(doc)
	if _, err := ParseBytes([]byte(good)); err != nil {
		t.Errorf("the same tool with in: query was refused: %v", err)
	}
}
