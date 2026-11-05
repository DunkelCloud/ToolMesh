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

import "testing"

func TestCheckToolPathAuthority(t *testing.T) {
	cases := []struct {
		path    string
		wantErr bool
	}{
		{"/things/{id}", false},
		{"https://places.googleapis.com/v1/places:searchText", false},
		{"https://api.example.com/v1/{id}?q={q}", false},
		{"http://{host}/v1/x", true},
		{"https://{region}.example.invalid/v1/x", true},
		{"https://api.example.com:{port}/x", true},
		{"{scheme}://api.example.com/x", true},
		{"https://user{u}@api.example.com/x", true},
	}
	for _, c := range cases {
		err := CheckToolPathAuthority(c.path)
		if (err != nil) != c.wantErr {
			t.Errorf("CheckToolPathAuthority(%q) = %v, wantErr %v", c.path, err, c.wantErr)
		}
	}
}
