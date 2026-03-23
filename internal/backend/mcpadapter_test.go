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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewMCPAdapter_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "backends.yaml")
	os.WriteFile(configPath, []byte(`
backends:
  - name: test-backend
    transport: http
    url: "https://example.com/mcp"
    api_key_env: "TEST_API_KEY"
  - name: local
    transport: stdio
    command: "./echo"
    args: ["--verbose"]
`), 0644)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter, err := NewMCPAdapter(configPath, creds, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(adapter.backends) != 2 {
		t.Errorf("expected 2 backends, got %d", len(adapter.backends))
	}

	if _, ok := adapter.backends["test-backend"]; !ok {
		t.Error("expected 'test-backend' to be registered")
	}
	if _, ok := adapter.backends["local"]; !ok {
		t.Error("expected 'local' to be registered")
	}
}

func TestNewMCPAdapter_MissingConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter, err := NewMCPAdapter("/nonexistent/path.yaml", creds, logger)
	if err != nil {
		t.Fatalf("expected no error for missing config, got: %v", err)
	}
	if len(adapter.backends) != 0 {
		t.Errorf("expected 0 backends, got %d", len(adapter.backends))
	}
}

func TestNewMCPAdapter_EmptyConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "backends.yaml")
	os.WriteFile(configPath, []byte("backends:\n"), 0644)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter, err := NewMCPAdapter(configPath, creds, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(adapter.backends) != 0 {
		t.Errorf("expected 0 backends, got %d", len(adapter.backends))
	}
}

func TestNewMCPAdapter_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "backends.yaml")
	os.WriteFile(configPath, []byte("{{invalid yaml"), 0644)

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	_, err := NewMCPAdapter(configPath, creds, logger)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestMCPAdapter_Execute_UnknownBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: make(map[string]*backendConn),
		creds:    creds,
		logger:   logger,
	}

	_, err := adapter.Execute(context.Background(), "unknown:tool", nil)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

func TestMCPAdapter_Execute_InvalidToolName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: make(map[string]*backendConn),
		creds:    creds,
		logger:   logger,
	}

	_, err := adapter.Execute(context.Background(), "no-colon-tool", nil)
	if err == nil {
		t.Fatal("expected error for tool name without colon, got nil")
	}
}

func TestMCPAdapter_Connect_MissingCredential(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"secure": {
				entry: BackendEntry{
					Name:      "secure",
					Transport: "http",
					URL:       "https://example.com/mcp",
					APIKeyEnv: "NONEXISTENT_KEY",
				},
			},
		},
		creds:  creds,
		logger: logger,
		client: mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.1"}, nil),
	}

	// Connect should log an error but not panic
	_ = adapter.Connect(context.Background())

	// Backend should not be connected
	if adapter.backends["secure"].session != nil {
		t.Fatal("expected nil session when credential is missing")
	}
}

func TestMCPAdapter_Execute_NotConnected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"mybackend": {
				entry: BackendEntry{
					Name:      "mybackend",
					Transport: "http",
					URL:       "https://example.com/mcp",
				},
				// session is nil — not connected
			},
		},
		creds:  creds,
		logger: logger,
	}

	_, err := adapter.Execute(context.Background(), "mybackend:search", map[string]any{"q": "test"})
	if err == nil {
		t.Fatal("expected error for not-connected backend, got nil")
	}
}

func TestMCPAdapter_ListTools(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"backend1": {
				entry: BackendEntry{Name: "backend1"},
				tools: []ToolDescriptor{
					{Name: "search", Description: "Search things"},
					{Name: "fetch", Description: "Fetch data"},
				},
			},
			"backend2": {
				entry: BackendEntry{Name: "backend2"},
				tools: []ToolDescriptor{
					{Name: "store", Description: "Store data"},
				},
			},
		},
		creds:  creds,
		logger: logger,
	}

	tools, err := adapter.ListTools(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(tools))
	}

	// Check that tools are prefixed with backend name
	names := make(map[string]bool)
	for _, tool := range tools {
		names[tool.Name] = true
	}
	for _, expected := range []string{"backend1:search", "backend1:fetch", "backend2:store"} {
		if !names[expected] {
			t.Errorf("expected tool %q not found", expected)
		}
	}
}

func TestMCPAdapter_RegisterTools(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"mybackend": {entry: BackendEntry{Name: "mybackend"}},
		},
		creds:  creds,
		logger: logger,
	}

	adapter.RegisterTools("mybackend", []ToolDescriptor{
		{Name: "tool1", Description: "First tool"},
	})

	if len(adapter.backends["mybackend"].tools) != 1 {
		t.Errorf("expected 1 tool after registration, got %d", len(adapter.backends["mybackend"].tools))
	}
}

func TestMCPAdapter_Healthy_NoBackends(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: make(map[string]*backendConn),
		creds:    creds,
		logger:   logger,
	}

	if err := adapter.Healthy(context.Background()); err == nil {
		t.Fatal("expected error for no backends, got nil")
	}
}

func TestMCPAdapter_Healthy_WithConnectedBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	// Simulate a connected backend by setting a non-nil session
	// We use an InMemory transport pair for a real session
	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0.1"}, nil)
	go server.Connect(context.Background(), serverTransport, nil)

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.1"}, nil)
	session, err := client.Connect(context.Background(), clientTransport, nil)
	if err != nil {
		t.Fatalf("failed to connect in-memory: %v", err)
	}
	defer session.Close()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"test": {
				entry:   BackendEntry{Name: "test"},
				session: session,
			},
		},
		creds:  creds,
		logger: logger,
	}

	if err := adapter.Healthy(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestMCPAdapter_Healthy_NotConnected(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	creds := credentials.NewEmbeddedStore()

	adapter := &MCPAdapter{
		backends: map[string]*backendConn{
			"test": {entry: BackendEntry{Name: "test"}},
		},
		creds:  creds,
		logger: logger,
	}

	if err := adapter.Healthy(context.Background()); err == nil {
		t.Fatal("expected error for not-connected backend, got nil")
	}
}
