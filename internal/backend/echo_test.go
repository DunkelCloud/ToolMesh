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
	"encoding/json"
	"strings"
	"testing"
)

func TestEchoBackend_Execute(t *testing.T) {
	b := NewEchoBackend()
	ctx := context.Background()

	t.Run("echo message", func(t *testing.T) {
		r, err := b.Execute(ctx, "echo", map[string]any{"message": "hi"})
		if err != nil {
			t.Fatal(err)
		}
		item := r.Content[0].(map[string]any)
		if item["text"] != "hi" {
			t.Errorf("echo text = %v", item["text"])
		}
	})

	t.Run("echo empty", func(t *testing.T) {
		r, err := b.Execute(ctx, "echo", nil)
		if err != nil {
			t.Fatal(err)
		}
		item := r.Content[0].(map[string]any)
		if item["text"] != "(empty)" {
			t.Errorf("empty echo = %v", item["text"])
		}
	})

	t.Run("add ints", func(t *testing.T) {
		r, err := b.Execute(ctx, "add", map[string]any{"a": 2, "b": 3})
		if err != nil {
			t.Fatal(err)
		}
		item := r.Content[0].(map[string]any)
		if item["text"] != "5" {
			t.Errorf("add = %v", item["text"])
		}
	})

	t.Run("add floats", func(t *testing.T) {
		r, _ := b.Execute(ctx, "add", map[string]any{"a": 1.5, "b": 2.25})
		item := r.Content[0].(map[string]any)
		if item["text"] != "3.75" {
			t.Errorf("add floats = %v", item["text"])
		}
	})

	t.Run("add json.Number", func(t *testing.T) {
		r, _ := b.Execute(ctx, "add", map[string]any{"a": json.Number("4"), "b": json.Number("6")})
		item := r.Content[0].(map[string]any)
		if item["text"] != "10" {
			t.Errorf("add json.Number = %v", item["text"])
		}
	})

	t.Run("add int64", func(t *testing.T) {
		r, _ := b.Execute(ctx, "add", map[string]any{"a": int64(1), "b": int64(2)})
		item := r.Content[0].(map[string]any)
		if item["text"] != "3" {
			t.Errorf("add int64 = %v", item["text"])
		}
	})

	t.Run("add invalid", func(t *testing.T) {
		r, _ := b.Execute(ctx, "add", map[string]any{"a": "x", "b": "y"})
		item := r.Content[0].(map[string]any)
		if !strings.Contains(item["text"].(string), "error") {
			t.Errorf("expected error text, got %v", item["text"])
		}
	})

	t.Run("time", func(t *testing.T) {
		r, err := b.Execute(ctx, "time", nil)
		if err != nil {
			t.Fatal(err)
		}
		item := r.Content[0].(map[string]any)
		text, _ := item["text"].(string)
		if text == "" {
			t.Error("time returned empty")
		}
	})

	t.Run("unknown tool", func(t *testing.T) {
		_, err := b.Execute(ctx, "nope", nil)
		if err == nil {
			t.Error("expected error for unknown tool")
		}
	})
}

func TestEchoBackend_ListTools(t *testing.T) {
	b := NewEchoBackend()
	tools, err := b.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 3 {
		t.Errorf("got %d tools, want 3", len(tools))
	}
}

func TestNewEchoBackendWithDefs(t *testing.T) {
	defs := []ToolDescriptor{{Name: "custom"}}
	b := NewEchoBackendWithDefs(defs)
	tools, _ := b.ListTools(context.Background())
	if len(tools) != 1 || tools[0].Name != "custom" {
		t.Errorf("got %v, want custom def", tools)
	}
}

func TestEchoBackend_Healthy(t *testing.T) {
	if err := NewEchoBackend().Healthy(context.Background()); err != nil {
		t.Error(err)
	}
}
