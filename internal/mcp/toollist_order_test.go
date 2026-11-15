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
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/backend"
	"github.com/DunkelCloud/ToolMesh/internal/config"
	"github.com/DunkelCloud/ToolMesh/internal/executor"
)

// testOrderTool is the one tool of a describedBackend.
const testOrderTool = "lookup"

// describedBackend is a backend with a description and one tool it exposes
// at the top level, as a REST backend with expose_tools is.
type describedBackend struct {
	name string
}

func (b *describedBackend) Execute(context.Context, string, map[string]any) (*backend.ToolResult, error) {
	return &backend.ToolResult{}, nil
}

func (b *describedBackend) ListTools(context.Context) ([]backend.ToolDescriptor, error) {
	return []backend.ToolDescriptor{{Name: testOrderTool, Description: "look in " + b.name}}, nil
}

func (b *describedBackend) Healthy(context.Context) error { return nil }

func (b *describedBackend) BackendSummaries() []backend.BackendInfo {
	return []backend.BackendInfo{{Name: b.name, Description: "the " + b.name + " API"}}
}

func (b *describedBackend) PromotedTools() []backend.Promotion {
	return []backend.Promotion{{
		Descriptor: backend.ToolDescriptor{
			Name:        b.name + "_" + testOrderTool,
			Description: "look in " + b.name,
			InputSchema: map[string]any{
				contentKeyType: jsonTypeObject,
				schemaKeyProperties: map[string]any{
					"q": map[string]any{contentKeyType: jsonTypeString}, "max": map[string]any{contentKeyType: jsonTypeInteger},
					"order": map[string]any{contentKeyType: jsonTypeString}, "from": map[string]any{contentKeyType: jsonTypeInteger},
				},
			},
		},
		Canonical: b.name + "_" + testOrderTool,
	}}
}

// The answer to tools/list is the same bytes on every request while the
// backends stay the same. A client keeps the list, and the model that reads
// it keeps a cache of its prompt: both are lost when backends merely come
// out of a map in another order.
func TestToolsList_SameBytesOnEveryRequest(t *testing.T) {
	names := []string{"weather", "orders", "notes", "tasks", "billing", "wiki", "alerts", "zones", "mail", "index", "crm", "tickets"}
	backends := make(map[string]backend.ToolBackend, len(names))
	for _, name := range names {
		backends[name] = &describedBackend{name: name}
	}
	composite := backend.NewCompositeBackend(backends)

	logger := newQuietMCPLogger()
	exec := executor.New(nil, nil, composite, nil, nil, 30*time.Second, logger, nil, nil)
	handler := NewHandler(exec, composite, nil, "", nil, logger, false)
	srv := NewServer(handler, &config.Config{APIKey: testAPIKey}, logger, nil, nil, nil, nil, nil, nil)
	mux := http.NewServeMux()
	srv.SetupRoutes(mux)

	const body = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + testStatelessMeta + `}}`
	first := mcpPost(t, mux, body, statelessHeaders(methodToolsList, "")).Body.Bytes()
	if !bytes.Contains(first, []byte(`"alerts_lookup"`)) {
		t.Fatalf("promoted tools missing: %s", first)
	}
	for i := 0; i < 50; i++ {
		got := mcpPost(t, mux, body, statelessHeaders(methodToolsList, "")).Body.Bytes()
		if !bytes.Equal(got, first) {
			t.Fatalf("request %d answered other bytes than the first:\n first %s\n   got %s", i+2, first, got)
		}
	}

	// The backends are named in ascending order, in the description and in
	// the list.
	text := string(first)
	last := -1
	slices.Sort(names)
	for _, name := range names {
		at := strings.Index(text, `"name":"`+name+`_`+testOrderTool+`"`)
		if at < 0 || at < last {
			t.Fatalf("tool of %q is missing or out of order (at %d, previous at %d)", name, at, last)
		}
		last = at
	}
}
