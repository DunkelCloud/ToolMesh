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

package mcp

import (
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/dop251/goja"
)

func TestExtractJSValue(t *testing.T) {
	rt := goja.New()

	// Nil result → undefined.
	if v := extractJSValue(rt, nil); v != goja.Undefined() {
		t.Errorf("nil: got %v", v)
	}

	// Empty content → undefined.
	if v := extractJSValue(rt, &backend.ToolResult{}); v != goja.Undefined() {
		t.Errorf("empty: got %v", v)
	}

	// JSON text → parsed object.
	r := &backend.ToolResult{
		Content: []any{map[string]any{"type": "text", "text": `{"x": 1}`}},
	}
	v := extractJSValue(rt, r)
	exp := v.Export()
	m, ok := exp.(map[string]any)
	if !ok || m["x"] != float64(1) {
		t.Errorf("parsed: got %T %v", exp, exp)
	}

	// Non-JSON text → raw string.
	r2 := &backend.ToolResult{
		Content: []any{map[string]any{"type": "text", "text": "plain text"}},
	}
	if v := extractJSValue(rt, r2); v.Export() != "plain text" {
		t.Errorf("non-json: got %v", v)
	}

	// Non-text content type → fall through.
	r3 := &backend.ToolResult{
		Content: []any{map[string]any{"type": "image", "data": "abc"}},
	}
	v3 := extractJSValue(rt, r3)
	if v3 == goja.Undefined() {
		t.Error("expected non-undefined for image-only content")
	}
}
