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

func TestJSONPath_Extract(t *testing.T) {
	data := map[string]any{
		"data": []any{
			map[string]any{"id": float64(1), "name": "first"},
			map[string]any{"id": float64(2), "name": "second"},
			map[string]any{"id": float64(3), "name": "third"},
		},
		"meta": map[string]any{
			"next_cursor": "abc123",
			"total":       float64(100),
		},
		"message": "success",
	}

	tests := []struct {
		name    string
		expr    string
		want    any
		wantErr bool
	}{
		{name: "simple field", expr: "$.message", want: "success"},
		{name: "nested field", expr: "$.meta.next_cursor", want: "abc123"},
		{name: "nested number", expr: "$.meta.total", want: float64(100)},
		{name: "array first", expr: "$.data[0].name", want: "first"},
		{name: "array last", expr: "$.data[-1].name", want: "third"},
		{name: "array second", expr: "$.data[1].id", want: float64(2)},
		{name: "missing field", expr: "$.nonexistent", wantErr: true},
		{name: "index out of bounds", expr: "$.data[99]", wantErr: true},
		{name: "field on non-object", expr: "$.message.sub", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jp, err := NewJSONPath(tt.expr)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			got, err := jp.Extract(data)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v (%T), want %v (%T)", got, got, tt.want, tt.want)
			}
		})
	}
}

func TestExtractResult(t *testing.T) {
	body := `{"data": [1, 2, 3], "meta": {"total": 3}}`

	result, err := ExtractResult([]byte(body), "$.data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var arr []any
	if err := json.Unmarshal(result, &arr); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(arr) != 3 {
		t.Errorf("got %d items, want 3", len(arr))
	}
}

func TestExtractResult_EmptyPath(t *testing.T) {
	body := `{"key": "value"}`
	result, err := ExtractResult([]byte(body), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result) != body {
		t.Errorf("got %s, want %s", result, body)
	}
}
