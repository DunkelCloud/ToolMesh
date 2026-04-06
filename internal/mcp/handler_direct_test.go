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
	"context"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/executor"
	"github.com/DunkelCloud/ToolMesh/internal/tsdef"
	"github.com/DunkelCloud/ToolMesh/internal/userctx"
)

func TestHandleToolCall_DirectBackendCall(t *testing.T) {
	mb := &mockTestBackend{}
	coercer := tsdef.NewCoercer([]tsdef.ToolDef{
		{
			Name: "test:tool",
			Params: []tsdef.ParamDef{
				{Name: "count", Type: tsdef.ParamType{Kind: "number"}},
			},
		},
	}, newQuietMCPLogger())
	exec := executor.New(nil, nil, mb, nil, nil, 5*time.Second, newQuietMCPLogger(), nil)
	h := NewHandler(exec, mb, coercer, "", newQuietMCPLogger())

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "u",
		Authenticated: true,
	})

	// Normal tool call routed through the default branch with coercion.
	// "count": "42" gets coerced to number.
	result, err := h.HandleToolCall(ctx, "test:tool", map[string]any{"count": "42"})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil {
		t.Fatal("nil result")
	}
}

func TestHandleToolCall_CoercionFailure(t *testing.T) {
	mb := &mockTestBackend{}
	coercer := tsdef.NewCoercer([]tsdef.ToolDef{
		{
			Name: "test:tool",
			Params: []tsdef.ParamDef{
				{Name: "req", Required: true, Type: tsdef.ParamType{Kind: "string"}},
			},
		},
	}, newQuietMCPLogger())
	exec := executor.New(nil, nil, mb, nil, nil, 5*time.Second, newQuietMCPLogger(), nil)
	h := NewHandler(exec, mb, coercer, "", newQuietMCPLogger())

	ctx := userctx.WithUserContext(context.Background(), &userctx.UserContext{
		UserID:        "u",
		Authenticated: true,
	})

	// Missing required "req" → coercer returns error.
	result, err := h.HandleToolCall(ctx, "test:tool", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.IsError {
		t.Errorf("expected error result, got %+v", result)
	}
}
