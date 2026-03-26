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
	"encoding/json"
	"testing"
)

func TestApplyTransform(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		jqExpr  string
		want    string
		wantErr bool
	}{
		{
			name:   "identity",
			data:   `{"a": 1}`,
			jqExpr: ".",
			want:   `{"a":1}`,
		},
		{
			name:   "select field",
			data:   `{"a": 1, "b": 2}`,
			jqExpr: ".a",
			want:   `1`,
		},
		{
			name:   "map array",
			data:   `[{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]`,
			jqExpr: "[.[] | .id]",
			want:   `[1,2]`,
		},
		{
			name:   "filter array",
			data:   `[1, 2, 3, 4, 5]`,
			jqExpr: "[.[] | select(. > 3)]",
			want:   `[4,5]`,
		},
		{
			name:   "empty expr returns input",
			data:   `{"x": 1}`,
			jqExpr: "",
			want:   `{"x": 1}`,
		},
		{
			name:    "invalid jq",
			data:    `{}`,
			jqExpr:  "invalid[[[",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ApplyTransform([]byte(tt.data), tt.jqExpr)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Normalize JSON for comparison
			var gotVal, wantVal any
			if err := json.Unmarshal(got, &gotVal); err != nil {
				t.Fatalf("unmarshal got: %v (raw: %s)", err, got)
			}
			if err := json.Unmarshal([]byte(tt.want), &wantVal); err != nil {
				t.Fatalf("unmarshal want: %v", err)
			}
			gotJSON, _ := json.Marshal(gotVal)
			wantJSON, _ := json.Marshal(wantVal)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("got %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}
