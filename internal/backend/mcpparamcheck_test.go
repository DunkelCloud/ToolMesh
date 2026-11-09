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
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/DunkelCloud/ToolMesh/internal/dadl"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	pcToolRetrieve  = "retrieve"
	pcParamTopK     = "top_k"
	pcParamAnything = "anything"
	pcTypeNull      = "null"
	pcServerName    = "srv"
	pcUnknownLimit  = `unknown parameter "limit"`
)

// closedRetrieveSchema is the shape the Go and TypeScript MCP SDKs generate:
// a property list with the set closed.
func closedRetrieveSchema() map[string]any {
	return map[string]any{
		schemaKeyType: schemaTypeObject,
		schemaKeyProperties: map[string]any{
			testParamQuery: map[string]any{schemaKeyType: schemaTypeString},
			pcParamTopK:    map[string]any{schemaKeyType: schemaTypeInteger},
		},
		schemaKeyRequired:             []any{testParamQuery},
		schemaKeyAdditionalProperties: false,
	}
}

func TestValidateMCPParams(t *testing.T) {
	openSchema := closedRetrieveSchema()
	openSchema[schemaKeyAdditionalProperties] = true
	noAdditional := closedRetrieveSchema()
	delete(noAdditional, schemaKeyAdditionalProperties)
	patterned := closedRetrieveSchema()
	patterned[schemaKeyPatternProperties] = map[string]any{"^x-": map[string]any{schemaKeyType: schemaTypeString}}

	tests := []struct {
		name        string
		schema      map[string]any
		params      map[string]any
		wantUnknown []string
		wantMissing []string
		wantSuggest string
	}{
		{
			name:   "complete call passes",
			schema: closedRetrieveSchema(),
			params: map[string]any{testParamQuery: "x", pcParamTopK: 3},
		},
		{
			name:        "undeclared argument is reported",
			schema:      closedRetrieveSchema(),
			params:      map[string]any{testParamQuery: "x", testParamLimit: 3},
			wantUnknown: []string{testParamLimit},
		},
		{
			name:        "camel-case spelling gets the declared name suggested",
			schema:      closedRetrieveSchema(),
			params:      map[string]any{testParamQuery: "x", "topK": 3},
			wantUnknown: []string{"topK"},
			wantSuggest: pcParamTopK,
		},
		{
			name:        "missing required argument is reported",
			schema:      closedRetrieveSchema(),
			params:      map[string]any{pcParamTopK: 3},
			wantMissing: []string{testParamQuery},
		},
		{
			name:        "absent additionalProperties still rejects an undeclared argument",
			schema:      noAdditional,
			params:      map[string]any{testParamQuery: "x", testParamLimit: 3},
			wantUnknown: []string{testParamLimit},
		},
		{
			name:   "open schema admits an undeclared argument",
			schema: openSchema,
			params: map[string]any{testParamQuery: "x", testParamLimit: 3},
		},
		{
			name:        "open schema still requires the required ones",
			schema:      openSchema,
			params:      map[string]any{testParamLimit: 3},
			wantMissing: []string{testParamQuery},
		},
		{
			name:   "pattern properties admit an undeclared argument",
			schema: patterned,
			params: map[string]any{testParamQuery: "x", "x-trace": "abc"},
		},
		{
			name:   "schema without properties is not checked",
			schema: map[string]any{schemaKeyType: schemaTypeObject},
			params: map[string]any{pcParamAnything: 1},
		},
		{
			name:   "nil schema is not checked",
			schema: nil,
			params: map[string]any{pcParamAnything: 1},
		},
		{
			name:        "closed schema without properties rejects every argument",
			schema:      map[string]any{schemaKeyType: schemaTypeObject, schemaKeyAdditionalProperties: false},
			params:      map[string]any{pcParamAnything: 1},
			wantUnknown: []string{pcParamAnything},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMCPParams(pcToolRetrieve, tt.schema, tt.params)
			if len(tt.wantUnknown) == 0 && len(tt.wantMissing) == 0 {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			var perr *dadl.ParamError
			if !errors.As(err, &perr) {
				t.Fatalf("expected a ParamError, got %v", err)
			}
			if strings.Join(perr.Unknown, ",") != strings.Join(tt.wantUnknown, ",") {
				t.Errorf("unknown = %v, want %v", perr.Unknown, tt.wantUnknown)
			}
			if strings.Join(perr.MissingRequired, ",") != strings.Join(tt.wantMissing, ",") {
				t.Errorf("missing = %v, want %v", perr.MissingRequired, tt.wantMissing)
			}
			if tt.wantSuggest != "" && perr.Suggestions[tt.wantUnknown[0]] != tt.wantSuggest {
				t.Errorf("suggestion = %q, want %q", perr.Suggestions[tt.wantUnknown[0]], tt.wantSuggest)
			}
		})
	}
}

// TestValidateMCPParams_MessageListsDeclaredSet checks the message carries
// what a caller needs to rewrite the call: the declared names with their
// types and which are required, in the REST form.
func TestValidateMCPParams_MessageListsDeclaredSet(t *testing.T) {
	err := validateMCPParams(pcToolRetrieve, closedRetrieveSchema(), map[string]any{testParamLimit: 3})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{
		`tool "retrieve"`,
		pcUnknownLimit,
		`missing required parameter "query"`,
		"declared parameters: query (string, required), top_k (integer)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

func TestSchemaPropertyType(t *testing.T) {
	tests := []struct {
		name string
		raw  any
		want string
	}{
		{"named type", map[string]any{schemaKeyType: schemaTypeString}, schemaTypeString},
		{"union from JSON", map[string]any{schemaKeyType: []any{schemaTypeString, pcTypeNull}}, "string|null"},
		{"union from Go", map[string]any{schemaKeyType: []string{schemaTypeInteger, pcTypeNull}}, "integer|null"},
		{"untyped property", map[string]any{schemaKeyDescription: "free"}, ""},
		{"not an object", schemaTypeString, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := schemaPropertyType(tt.raw); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// newMCPParamCheckAdapter wires an MCPAdapter to an in-memory MCP server that
// offers one tool with the given schema and counts how often the tool
// handler actually runs.
func newMCPParamCheckAdapter(t *testing.T, schema map[string]any, calls *atomic.Int32) *MCPAdapter {
	t.Helper()
	ctx := context.Background()

	server := mcp.NewServer(&mcp.Implementation{Name: pcServerName, Version: testVersion01}, nil)
	server.AddTool(
		&mcp.Tool{Name: pcToolRetrieve, Description: "retrieves", InputSchema: schema},
		func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			calls.Add(1)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
		},
	)

	ct, st := mcp.NewInMemoryTransports()
	go server.Connect(ctx, st, nil) //nolint:errcheck // test server, failure surfaces as a client connect error

	client := mcp.NewClient(&mcp.Implementation{Name: "tm", Version: testVersion01}, nil)
	session, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("connect in-memory: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })

	entry := BackendEntry{Name: testBackendNameTest}
	conn := &backendConn{entry: entry, session: session}
	adapter := &MCPAdapter{
		backends: map[string]*backendConn{entry.Name: conn},
		creds:    credentials.NewEmbeddedStore(),
		logger:   slog.Default(),
		client:   client,
	}
	if err := adapter.discoverTools(ctx, entry.Name, conn); err != nil {
		t.Fatalf("discover tools: %v", err)
	}
	return adapter
}

// TestMCPAdapter_Execute_RejectsUndeclaredArgument is the field case: the
// backend's schema does not know `limit`, and the call must fail here, in
// the REST error form, without reaching the backend.
func TestMCPAdapter_Execute_RejectsUndeclaredArgument(t *testing.T) {
	var calls atomic.Int32
	adapter := newMCPParamCheckAdapter(t, closedRetrieveSchema(), &calls)

	result, err := adapter.Execute(context.Background(), testBackendNameTest+"_"+pcToolRetrieve,
		map[string]any{testParamQuery: "x", testParamLimit: 5})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsError {
		t.Fatalf("expected an error result, got %+v", result)
	}
	if calls.Load() != 0 {
		t.Errorf("backend handler ran %d times, want 0", calls.Load())
	}
	if got := result.Metadata[metadataKeyErrorCode]; got != dadl.ErrCodeInvalidInput {
		t.Errorf("error_code = %v, want %q", got, dadl.ErrCodeInvalidInput)
	}
	if got := result.Metadata[metadataKeyStatusCode]; got != 400 {
		t.Errorf("status_code = %v, want 400", got)
	}
	text, _ := result.Content[0].(map[string]any)[contentTypeText].(string)
	for _, want := range []string{pcUnknownLimit, "declared parameters: query (string, required), top_k (integer)"} {
		if !strings.Contains(text, want) {
			t.Errorf("text %q lacks %q", text, want)
		}
	}
}

// TestMCPAdapter_Execute_PassesValidCall makes sure the check is transparent
// for a call that matches the schema.
func TestMCPAdapter_Execute_PassesValidCall(t *testing.T) {
	var calls atomic.Int32
	adapter := newMCPParamCheckAdapter(t, closedRetrieveSchema(), &calls)

	result, err := adapter.Execute(context.Background(), testBackendNameTest+"_"+pcToolRetrieve,
		map[string]any{testParamQuery: "x", pcParamTopK: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %+v", result)
	}
	if calls.Load() != 1 {
		t.Errorf("backend handler ran %d times, want 1", calls.Load())
	}
}

// TestMCPAdapter_Execute_LeavesUndeclaredSchemaAlone keeps a backend that
// says nothing about its properties callable with whatever the script
// sends — there is nothing to check against.
func TestMCPAdapter_Execute_LeavesUndeclaredSchemaAlone(t *testing.T) {
	var calls atomic.Int32
	adapter := newMCPParamCheckAdapter(t, map[string]any{schemaKeyType: schemaTypeObject}, &calls)

	result, err := adapter.Execute(context.Background(), testBackendNameTest+"_"+pcToolRetrieve,
		map[string]any{"whatever": true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error result: %+v", result)
	}
	if calls.Load() != 1 {
		t.Errorf("backend handler ran %d times, want 1", calls.Load())
	}
}
