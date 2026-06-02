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

package unit_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/unit"
)

// TestUnit_RESTSubBackend exercises the full REST-sub-backend wiring: a
// unit bundles a DADL file in its own directory, the loader parses it,
// instantiates a RESTAdapter against an in-process httptest server, and
// the unit's JavaScript implementation reaches the server via
// api.<sub>.<tool>(args). The test asserts both the response shape and
// that the HTTP call really hit the test server (so the chain
// sandbox → api.* → RESTAdapter → HTTP cannot be stubbed past).
func TestUnit_RESTSubBackend(t *testing.T) {
	// Spin up a tiny REST API: GET /items?limit=N -> {"items": [...N strings]}
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/items" {
			http.NotFound(w, r)
			return
		}
		hits++
		limit := r.URL.Query().Get("limit")
		if limit == "" {
			limit = "1"
		}
		body, _ := json.Marshal(map[string]any{
			"items": []string{"alpha", "beta", "gamma"},
			"limit": limit,
		})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	unitDir := t.TempDir()

	// DADL: one GET tool, no auth, base_url overridden by unit.yaml below.
	dadl := `spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
backend:
  name: itemsapi
  type: rest
  base_url: "http://placeholder.invalid"
  description: "Items API"
  tools:
    list_items:
      method: GET
      path: /items
      description: "List items"
      params:
        limit:
          type: integer
          in: query
          description: "Max items to return"
`
	if err := os.WriteFile(filepath.Join(unitDir, "items.dadl"), []byte(dadl), 0o600); err != nil {
		t.Fatalf("write dadl: %v", err)
	}

	// unit.yaml: the REST sub-backend points at the local test server.
	// allow_private_url is required because the test server binds to
	// 127.0.0.1, which the SSRF guard would otherwise refuse.
	unitYAML := "" +
		"unit: items\n" +
		"implementation: ./items.js\n" +
		"backends:\n" +
		"  - name: itemsapi\n" +
		"    transport: rest\n" +
		"    dadl: ./items.dadl\n" +
		"    url: \"" + server.URL + "\"\n" +
		"    allow_private_url: true\n"
	if err := os.WriteFile(filepath.Join(unitDir, "unit.yaml"), []byte(unitYAML), 0o600); err != nil {
		t.Fatalf("write unit.yaml: %v", err)
	}

	js := `function describe() {
  return { tools: [{ name: "fetch", description: "Fetch items via REST",
    params: { count: { type: "integer", required: true } } }] };
}
async function fetch(args) {
  const r = await api.itemsapi.list_items({ limit: args.count });
  return r;
}
`
	if err := os.WriteFile(filepath.Join(unitDir, "items.js"), []byte(js), 0o600); err != nil {
		t.Fatalf("write items.js: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	creds := credentials.NewEmbeddedStore()
	ctx := context.Background()

	// Pass nil blobStore — this DADL has no binary responses so the
	// blob store is unused. The loader must tolerate that.
	res, err := unit.LoadUnit(ctx, unitDir, creds, nil, logger)
	if err != nil {
		t.Fatalf("LoadUnit: %v", err)
	}
	defer res.Adapter.Close()

	tools, err := res.Backend.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 1 || tools[0].Name != "fetch" {
		t.Fatalf("unexpected tools: %+v", tools)
	}

	result, err := res.Backend.Execute(ctx, "fetch", map[string]any{"count": 3})
	if err != nil {
		t.Fatalf("Execute fetch: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected exactly 1 HTTP hit on the test server, got %d", hits)
	}
	if len(result.Content) == 0 {
		t.Fatalf("empty content")
	}
	// The RESTAdapter returns the response body verbatim as the first
	// text content block — assert the items survived the marshal trip.
	block, _ := result.Content[0].(map[string]any)
	text, _ := block["text"].(string)
	if !strings.Contains(text, "alpha") || !strings.Contains(text, "limit") {
		t.Fatalf("response payload did not survive the chain: %q", text)
	}
	// And the limit query parameter must have been threaded through.
	var summary struct {
		Limit string `json:"limit"`
	}
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		// The REST adapter may wrap the body — fall back to substring check
		if !strings.Contains(text, `"limit": "3"`) {
			t.Fatalf("limit param not forwarded: %q", text)
		}
	} else if summary.Limit != "3" {
		t.Fatalf("limit=%q want 3", summary.Limit)
	}
}
