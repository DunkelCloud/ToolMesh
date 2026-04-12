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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DunkelCloud/ToolMesh/internal/credentials"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// BackendConfig represents the YAML configuration for backend servers.
type BackendConfig struct {
	Backends []BackendEntry `yaml:"backends"`
}

// BackendEntry represents a single backend server configuration.
type BackendEntry struct {
	Name            string            `yaml:"name"`
	Transport       string            `yaml:"transport"` // "http", "stdio", or "rest"
	URL             string            `yaml:"url"`       // for HTTP transport
	APIKeyEnv       string            `yaml:"api_key_env"`
	Command         string            `yaml:"command"` // for STDIO transport
	Args            []string          `yaml:"args"`
	Hint            string            `yaml:"hint"`              // optional domain-specific hint for LLM tool descriptions
	DADL            string            `yaml:"dadl"`              // path to .dadl file (for transport: rest)
	AllowPrivateURL *bool             `yaml:"allow_private_url"` // allow private/loopback base_url (default: true)
	TLSSkipVerify   bool              `yaml:"tls_skip_verify"`   // accept invalid/self-signed TLS certificates
	Options         map[string]string `yaml:"options"`           // backend-specific options (e.g. blob_ttl: "1h")
	Env             map[string]string `yaml:"env"`               // credential env remapping (DADL name → actual env var)
}

// BackendInfo provides a summary of a backend for tool description enrichment.
type BackendInfo struct {
	Name string
	Hint string
}

// MCPAdapter connects ToolMesh as an MCP client to external MCP servers.
// It aggregates tools from all configured backends and routes execution
// to the correct one.
type MCPAdapter struct {
	mu       sync.RWMutex
	backends map[string]*backendConn
	creds    credentials.CredentialStore
	logger   *slog.Logger
	client   *mcp.Client
}

type backendConn struct {
	entry   BackendEntry
	session *mcp.ClientSession
	tools   []ToolDescriptor
}

// BackendCount returns the number of configured MCP server backends.
func (a *MCPAdapter) BackendCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.backends)
}

// NewMCPAdapter creates an MCPAdapter from a YAML configuration file.
func NewMCPAdapter(configPath string, creds credentials.CredentialStore, logger *slog.Logger) (*MCPAdapter, error) {
	adapter := &MCPAdapter{
		backends: make(map[string]*backendConn),
		creds:    creds,
		logger:   logger,
		client:   mcp.NewClient(&mcp.Implementation{Name: "toolmesh", Version: "0.1.0"}, nil),
	}

	data, err := os.ReadFile(configPath) //nolint:gosec // path from trusted config
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("backends config not found, starting with no backends", "path", configPath)
			return adapter, nil
		}
		return nil, fmt.Errorf("read backends config: %w", err)
	}

	var cfg BackendConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse backends config: %w", err)
	}

	for _, entry := range cfg.Backends {
		if entry.Name == "" {
			continue
		}
		// Skip REST Proxy backends — they are handled by RESTAdapter, not MCPAdapter
		if entry.Transport == "rest" {
			continue
		}
		adapter.backends[entry.Name] = &backendConn{
			entry: entry,
		}
		logger.Info("registered backend", "name", entry.Name, "transport", entry.Transport)
	}

	return adapter, nil
}

// Connect establishes MCP client sessions to all configured backends.
// It should be called after NewMCPAdapter, typically during server startup.
// Backends that fail to connect are logged but do not prevent other backends
// from connecting.
func (a *MCPAdapter) Connect(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	for name, conn := range a.backends {
		if conn.session != nil {
			continue
		}
		if err := a.connectBackend(ctx, name, conn); err != nil {
			a.logger.Error("failed to connect backend", "name", name, "error", err)
			continue
		}
	}
	return nil
}

func (a *MCPAdapter) connectBackend(ctx context.Context, name string, conn *backendConn) error {
	a.logger.Debug("connecting to backend",
		"name", name,
		"transport", conn.entry.Transport,
		"url", conn.entry.URL,
		"command", conn.entry.Command,
	)

	transport, err := a.createTransport(ctx, conn.entry)
	if err != nil {
		return fmt.Errorf("create transport: %w", err)
	}

	connectCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	session, err := a.client.Connect(connectCtx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", name, err)
	}

	conn.session = session
	a.logger.Info("connected to backend", "name", name, "transport", conn.entry.Transport)

	// Discover tools
	if err := a.discoverTools(ctx, name, conn); err != nil {
		a.logger.Warn("failed to discover tools", "name", name, "error", err)
	}

	return nil
}

func (a *MCPAdapter) createTransport(ctx context.Context, entry BackendEntry) (mcp.Transport, error) {
	switch entry.Transport {
	case "http":
		return a.createHTTPTransport(ctx, entry)
	case "stdio":
		return a.createSTDIOTransport(ctx, entry)
	default:
		return nil, fmt.Errorf("unsupported transport %q", entry.Transport)
	}
}

func (a *MCPAdapter) createHTTPTransport(ctx context.Context, entry BackendEntry) (mcp.Transport, error) {
	httpClient := &http.Client{Timeout: envDuration("TOOLMESH_MCP_TIMEOUT", 120*time.Second)}

	// Inject API key as Bearer token if configured
	if entry.APIKeyEnv != "" {
		apiKey, err := a.creds.Get(ctx, entry.APIKeyEnv, credentials.TenantInfo{})
		if err != nil {
			return nil, fmt.Errorf("credential lookup for %s: %w", entry.APIKeyEnv, err)
		}
		httpClient.Transport = &bearerTransport{
			base:  http.DefaultTransport,
			token: apiKey,
		}
	}

	// Try SSE transport first (for legacy servers like mcp/everything),
	// fall back to Streamable HTTP if the URL doesn't end with /sse.
	if strings.HasSuffix(entry.URL, "/sse") {
		return &mcp.SSEClientTransport{
			Endpoint:   entry.URL,
			HTTPClient: httpClient,
		}, nil
	}

	return &mcp.StreamableClientTransport{
		Endpoint:   entry.URL,
		HTTPClient: httpClient,
	}, nil
}

func (a *MCPAdapter) createSTDIOTransport(ctx context.Context, entry BackendEntry) (mcp.Transport, error) {
	if entry.Command == "" {
		return nil, fmt.Errorf("stdio transport requires a command")
	}
	cmd := exec.CommandContext(ctx, entry.Command, entry.Args...) //nolint:gosec // command from trusted backends config
	return &mcp.CommandTransport{Command: cmd}, nil
}

func (a *MCPAdapter) discoverTools(ctx context.Context, name string, conn *backendConn) error {
	if conn.session == nil {
		return fmt.Errorf("not connected")
	}

	result, err := conn.session.ListTools(ctx, nil)
	if err != nil {
		return fmt.Errorf("list tools: %w", err)
	}

	a.logger.Debug("raw tools from backend", "backend", name, "count", len(result.Tools))
	conn.tools = make([]ToolDescriptor, 0, len(result.Tools))
	for _, t := range result.Tools {
		schema := make(map[string]any)
		if t.InputSchema != nil {
			schemaBytes, _ := json.Marshal(t.InputSchema)
			_ = json.Unmarshal(schemaBytes, &schema)
		}

		a.logger.Debug("discovered tool", "backend", name, "tool", t.Name, "schema", schema)
		conn.tools = append(conn.tools, ToolDescriptor{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: schema,
			Backend:     "mcp:" + name,
		})
	}

	a.logger.Info("discovered tools", "backend", name, "count", len(conn.tools))
	return nil
}

// Execute routes a tool call to the appropriate backend via MCP.
// Tool names use underscore as separator: "backend_toolname".
func (a *MCPAdapter) Execute(ctx context.Context, toolName string, params map[string]any) (*ToolResult, error) {
	a.mu.RLock()
	// Debug: log all registered backend names for matching
	registeredNames := make([]string, 0, len(a.backends))
	for name := range a.backends {
		registeredNames = append(registeredNames, name)
	}
	a.logger.DebugContext(ctx, "MCPAdapter.Execute lookup",
		"toolName", toolName,
		"registeredBackends", registeredNames,
	)
	backendName, realTool, conn := a.matchBackend(toolName)
	a.mu.RUnlock()

	if conn == nil {
		a.logger.WarnContext(ctx, "MCPAdapter no match",
			"toolName", toolName,
			"matchedBackend", backendName,
			"realTool", realTool,
		)
		return nil, fmt.Errorf("no backend found for tool %q", toolName)
	}

	if conn.session == nil {
		return nil, fmt.Errorf("backend %q is not connected", backendName)
	}

	a.logger.InfoContext(ctx, "calling tool via MCP",
		"backend", backendName,
		"tool", realTool,
	)
	a.logger.DebugContext(ctx, "MCP CallTool request",
		"backend", backendName,
		"tool", realTool,
		"params", params,
	)

	result, err := conn.session.CallTool(ctx, &mcp.CallToolParams{
		Name:      realTool,
		Arguments: params,
	})
	if err != nil {
		a.logger.DebugContext(ctx, "MCP CallTool error",
			"backend", backendName,
			"tool", realTool,
			"error", err,
		)
		return nil, fmt.Errorf("call tool %s on backend %s: %w", realTool, backendName, err)
	}

	// Convert MCP Content to our ToolResult format
	content := make([]any, 0, len(result.Content))
	for _, c := range result.Content {
		content = append(content, contentToMap(c))
	}

	// Log the full response as JSON so it is always human-readable in the log
	if respJSON, err := json.Marshal(content); err == nil {
		a.logger.DebugContext(ctx, "MCP CallTool response",
			"backend", backendName,
			"tool", realTool,
			"isError", result.IsError,
			"contentItems", len(content),
			"content", string(respJSON),
		)
	}

	return &ToolResult{
		Content: content,
		IsError: result.IsError,
		Metadata: map[string]any{
			"backend":   backendName,
			"transport": conn.entry.Transport,
		},
	}, nil
}

// ListTools aggregates tools from all backends, prefixed with the backend name.
func (a *MCPAdapter) ListTools(ctx context.Context) ([]ToolDescriptor, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var all []ToolDescriptor
	for name, conn := range a.backends {
		for _, tool := range conn.tools {
			all = append(all, ToolDescriptor{
				Name:        name + "_" + tool.Name,
				Description: tool.Description,
				InputSchema: tool.InputSchema,
				Backend:     "mcp:" + name,
			})
		}
	}

	return all, nil
}

// Healthy checks if at least one backend is configured and connected.
func (a *MCPAdapter) Healthy(_ context.Context) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.backends) == 0 {
		return fmt.Errorf("no backends configured")
	}

	for name, conn := range a.backends {
		if conn.session != nil {
			return nil // at least one connected
		}
		a.logger.Warn("backend not connected", "name", name)
	}

	return fmt.Errorf("no backends connected")
}

// Close terminates all backend sessions.
func (a *MCPAdapter) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for name, conn := range a.backends {
		if conn.session != nil {
			_ = conn.session.Close()
			conn.session = nil
			a.logger.Info("disconnected backend", "name", name)
		}
	}
}

// BackendSummaries returns name and hint for each registered backend.
// Used to enrich MCP tool descriptions so LLMs know what backends are available.
func (a *MCPAdapter) BackendSummaries() []BackendInfo {
	a.mu.RLock()
	defer a.mu.RUnlock()

	infos := make([]BackendInfo, 0, len(a.backends))
	for _, conn := range a.backends {
		infos = append(infos, BackendInfo{
			Name: conn.entry.Name,
			Hint: conn.entry.Hint,
		})
	}
	return infos
}

// RegisterTools adds tools for a specific backend (used during discovery or testing).
func (a *MCPAdapter) RegisterTools(backendName string, tools []ToolDescriptor) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if conn, ok := a.backends[backendName]; ok {
		conn.tools = tools
		a.logger.Info("registered tools for backend",
			"backend", backendName,
			"count", len(tools),
		)
	}
}

// matchBackend finds the backend whose name is a prefix of the tool name.
// Returns the backend name, the real tool name (without prefix), and the connection.
func (a *MCPAdapter) matchBackend(toolName string) (name, realTool string, conn *backendConn) {
	for name, conn := range a.backends {
		prefix := name + "_"
		if strings.HasPrefix(toolName, prefix) {
			return name, strings.TrimPrefix(toolName, prefix), conn
		}
	}
	return "", toolName, nil
}

// contentToMap converts an MCP Content interface to a JSON-friendly map.
func contentToMap(c mcp.Content) map[string]any {
	data, err := json.Marshal(c)
	if err != nil {
		return map[string]any{"type": "text", "text": fmt.Sprintf("[marshal error: %s]", err)}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]any{"type": "text", "text": string(data)}
	}
	return m
}

// envDuration reads a duration in seconds from an environment variable,
// falling back to the provided default if unset or unparsable.
func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return fallback
}

// bearerTransport injects an Authorization header into HTTP requests.
type bearerTransport struct {
	base  http.RoundTripper
	token string
}

// RoundTrip implements http.RoundTripper by adding a Bearer token header.
func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}
