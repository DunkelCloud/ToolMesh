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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// UnmarshalBackendConfig decodes a backends.yaml document in strict mode: a
// key that no field claims is a parse error rather than a silent no-op.
//
// Leniency is the wrong default here. A backends.yaml is an operator's
// statement of intent about which tools an agent may reach; a typo in
// "expose_tools", or a field ToolMesh never had, would otherwise be dropped
// without a trace and leave the operator believing a restriction is active
// when it is not. Failing the parse turns that silent gap into a startup
// error naming the offending line.
//
// An empty document decodes to a zero config rather than an error, so an
// operator can comment a backends.yaml out entirely without the server
// refusing to boot.
func UnmarshalBackendConfig(data []byte, cfg *BackendConfig) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
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
	ExposeTools     []string          `yaml:"expose_tools"`      // tool names to also expose as direct top-level MCP tools (in addition to discover_tools)
	IncludeTools    []string          `yaml:"include_tools"`     // when set, the ONLY tools this backend exposes (restricts the surface); honored for every transport
	// AllowPrivateFileURL permits caller-supplied file_url parameters to resolve
	// to private/loopback/link-local addresses. Default false (independent of
	// allow_private_url, which only governs the admin-configured base_url).
	AllowPrivateFileURL *bool `yaml:"allow_private_file_url"`
	// FileURLAllowedHosts, when non-empty, restricts caller-supplied file_url
	// fetches to this exact set of hostnames (case-insensitive). Empty means no
	// host restriction (only the address-class policy above applies).
	FileURLAllowedHosts []string `yaml:"file_url_allowed_hosts"`
}

// BackendInfo provides a summary of a backend for tool description enrichment.
//
// SpecID is an opaque identifier shared by every instance that derives from the
// same DADL spec — typically the spec's ContentHash. Two instances with the
// same SpecID expose the same set of tools and the same hint; the description
// builder collapses them into a single line so the resulting tool description
// stays compact when the operator runs several instances of one API
// (e.g. "dokuwiki-prod" and "dokuwiki-staging" against the same .dadl file).
// Leave empty for backends without an underlying DADL spec — those are
// rendered individually.
type BackendInfo struct {
	Name   string
	Hint   string
	SpecID string
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
	// include is the include_tools allow-set, or nil when the backend places
	// no restriction on its surface. It is built once at registration and
	// never mutated afterwards — unlike session and tools, which discovery
	// and reconnect rewrite — so it is safe to read without holding the
	// adapter lock.
	include map[string]bool
}

// included reports whether a tool name is exposed by this backend. With no
// include_tools restriction configured (include == nil) every name is
// included; otherwise only names in the allow-set are.
func (c *backendConn) included(name string) bool {
	if c.include == nil {
		return true
	}
	return c.include[name]
}

// buildMCPIncludeSet turns an include_tools list into a lookup set, returning
// nil for an empty list ("no restriction").
//
// Unlike the REST path, entries cannot be validated here: an MCP backend's
// tool list is only known after the upstream ListTools call, which happens on
// connect. Names that match nothing upstream are reported by discoverTools.
func buildMCPIncludeSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// BackendCount returns the number of configured MCP server backends.
func (a *MCPAdapter) BackendCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.backends)
}

// NewMCPAdapter creates an MCPAdapter from a YAML configuration file.
func NewMCPAdapter(configPath string, creds credentials.CredentialStore, logger *slog.Logger) (*MCPAdapter, error) {
	data, err := os.ReadFile(configPath) //nolint:gosec // path from trusted config
	if err != nil {
		if os.IsNotExist(err) {
			logger.Warn("backends config not found, starting with no backends", "path", configPath)
			return newEmptyMCPAdapter(creds, logger), nil
		}
		return nil, fmt.Errorf("read backends config: %w", err)
	}

	var cfg BackendConfig
	if err := UnmarshalBackendConfig(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse backends config: %w", err)
	}
	return NewMCPAdapterFromEntries(cfg.Backends, creds, logger), nil
}

// NewMCPAdapterFromEntries builds an MCPAdapter from an in-memory list of
// backend entries. This is used by callers that synthesize the entry list
// outside of the global backends.yaml — most notably unit-backends, which
// declare their private MCP dependencies inside unit.yaml and never want
// those dependencies to appear in the global tool surface.
//
// REST entries are skipped because the MCPAdapter handles only MCP
// transports; non-MCP transports are wired separately by the caller.
func NewMCPAdapterFromEntries(entries []BackendEntry, creds credentials.CredentialStore, logger *slog.Logger) *MCPAdapter {
	adapter := newEmptyMCPAdapter(creds, logger)
	for _, entry := range entries {
		if entry.Name == "" {
			continue
		}
		if entry.Transport == transportTypeREST {
			continue
		}
		adapter.backends[entry.Name] = &backendConn{
			entry:   entry,
			include: buildMCPIncludeSet(entry.IncludeTools),
		}
		logger.Info("registered backend", "name", entry.Name, "transport", entry.Transport)
	}
	return adapter
}

func newEmptyMCPAdapter(creds credentials.CredentialStore, logger *slog.Logger) *MCPAdapter {
	return &MCPAdapter{
		backends: make(map[string]*backendConn),
		creds:    creds,
		logger:   logger,
		client:   mcp.NewClient(&mcp.Implementation{Name: "toolmesh", Version: "0.1.0"}, nil),
	}
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
	case transportTypeHTTP:
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

	// upstream holds every name the backend offered, before include_tools is
	// applied. The validation below needs it to tell "you excluded this
	// yourself" apart from "the backend has no such tool".
	upstream := make(map[string]struct{}, len(result.Tools))
	conn.tools = make([]ToolDescriptor, 0, len(result.Tools))
	hidden := 0
	for _, t := range result.Tools {
		upstream[t.Name] = struct{}{}

		if !conn.included(t.Name) {
			hidden++
			a.logger.Debug("tool hidden by include_tools", "backend", name, "tool", t.Name)
			continue
		}

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

	if hidden > 0 {
		a.logger.Info("tools hidden by include_tools",
			"backend", name,
			"hidden", hidden,
			"exposed", len(conn.tools),
		)
	}
	a.logger.Info("discovered tools", "backend", name, "count", len(conn.tools))

	a.validateSurfaceConfig(name, conn, upstream)

	return nil
}

// validateSurfaceConfig reports include_tools and expose_tools entries that
// do not line up with what the backend actually offers. Neither list can be
// checked before discovery, so the check runs on every (re)connect.
//
// Nothing here is fatal: a stale entry costs the operator that one tool, and
// dropping an entire backend over it would be the harsher failure. The
// warnings exist so the mismatch is visible in the log instead of showing up
// later as a tool that mysteriously never appears.
func (a *MCPAdapter) validateSurfaceConfig(name string, conn *backendConn, upstream map[string]struct{}) {
	for _, want := range conn.entry.IncludeTools {
		if _, ok := upstream[want]; !ok {
			a.logger.Warn("include_tools entry does not match any tool from backend, skipping",
				"backend", name,
				"tool", want,
			)
		}
	}

	for _, want := range conn.entry.ExposeTools {
		if _, ok := upstream[want]; !ok {
			a.logger.Warn("expose_tools entry does not match any tool from backend, skipping",
				"backend", name,
				"tool", want,
			)
			continue
		}
		// Promoting a tool that include_tools hides would advertise a
		// top-level tool that discover_tools and execute_code cannot see.
		// PromotedTools already skips it (it reads the filtered tool list);
		// the warning tells the operator their config contradicts itself.
		if !conn.included(want) {
			a.logger.Warn("expose_tools entry is excluded by include_tools, skipping",
				"backend", name,
				"tool", want,
			)
		}
	}
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

	// Enforce the include_tools allow-list at the execution boundary too, so a
	// hidden tool cannot be invoked by guessing its name even though it never
	// appears in discover_tools/execute_code.
	if !conn.included(realTool) {
		return nil, fmt.Errorf("tool %q not found in MCP backend %q", realTool, backendName)
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

		// Auto-reconnect: if the connection died, try once to re-establish it.
		if isConnectionClosed(err) {
			a.logger.WarnContext(ctx, "backend connection lost, attempting reconnect",
				"backend", backendName,
			)

			if reconnErr := a.reconnectBackend(ctx, backendName); reconnErr != nil {
				a.logger.ErrorContext(ctx, "reconnect failed",
					"backend", backendName,
					"error", reconnErr,
				)
				return nil, fmt.Errorf("call tool %s on backend %s (reconnect also failed): %w", realTool, backendName, reconnErr)
			}

			// Retry with the fresh session.
			a.mu.RLock()
			conn = a.backends[backendName]
			a.mu.RUnlock()

			result, err = conn.session.CallTool(ctx, &mcp.CallToolParams{
				Name:      realTool,
				Arguments: params,
			})
			if err != nil {
				return nil, fmt.Errorf("call tool %s on backend %s (after reconnect): %w", realTool, backendName, err)
			}
			a.logger.InfoContext(ctx, "retry after reconnect succeeded",
				"backend", backendName,
				"tool", realTool,
			)
		} else {
			return nil, fmt.Errorf("call tool %s on backend %s: %w", realTool, backendName, err)
		}
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
			metadataKeyBackend:   backendName,
			metadataKeyTransport: conn.entry.Transport,
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

// isConnectionClosed returns true when the error indicates the MCP session
// is no longer usable (server restart, network drop, idle timeout, etc.).
func isConnectionClosed(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, pattern := range []string{
		"connection closed",
		"client is closing",
		"broken pipe",
		"connection reset",
		"use of closed network connection",
	} {
		if strings.Contains(msg, pattern) {
			return true
		}
	}
	return false
}

// reconnectBackend closes the stale session and establishes a new one.
func (a *MCPAdapter) reconnectBackend(ctx context.Context, name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	conn, ok := a.backends[name]
	if !ok {
		return fmt.Errorf("backend %q not found", name)
	}

	// Tear down the old session if it still exists.
	if conn.session != nil {
		_ = conn.session.Close()
		conn.session = nil
	}

	return a.connectBackend(ctx, name, conn)
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

// PromotedTools returns one Promotion per tool that connected backends opted
// to expose as a direct top-level MCP tool (configured via backends.yaml
// expose_tools). Descriptor.Name is the bare tool name from the upstream
// MCP server; Canonical is "<backend>_<tool>" so the composite can dispatch.
// Names listed in expose_tools that have not yet been discovered (e.g. a
// backend that is still reconnecting) are silently skipped here; the
// late-bind on every call lets discovery catch up without restart.
func (a *MCPAdapter) PromotedTools() []Promotion {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var out []Promotion
	for name, conn := range a.backends {
		if len(conn.entry.ExposeTools) == 0 {
			continue
		}
		known := make(map[string]ToolDescriptor, len(conn.tools))
		for _, t := range conn.tools {
			known[t.Name] = t
		}
		for _, want := range conn.entry.ExposeTools {
			t, ok := known[want]
			if !ok {
				continue
			}
			out = append(out, Promotion{
				Descriptor: ToolDescriptor{
					Name:        t.Name,
					Description: t.Description,
					InputSchema: t.InputSchema,
					Backend:     "mcp:" + name,
					Access:      t.Access,
				},
				Canonical: name + "_" + t.Name,
			})
		}
	}
	return out
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

// LookupTool returns the descriptor for a tool owned by one of the connected
// MCP backends. Tools surface here with the backend prefix already applied
// ("backendname_tooltoolname"). Upstream MCP servers do not currently emit
// an access classification, so the returned descriptor's Access is empty —
// policies that need an explicit value should treat it as unclassified.
func (a *MCPAdapter) LookupTool(toolName string) (ToolDescriptor, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	for name, conn := range a.backends {
		prefix := name + "_"
		if !strings.HasPrefix(toolName, prefix) {
			continue
		}
		realTool := strings.TrimPrefix(toolName, prefix)
		for _, t := range conn.tools {
			if t.Name == realTool {
				return ToolDescriptor{
					Name:        toolName,
					Description: t.Description,
					InputSchema: t.InputSchema,
					Backend:     "mcp:" + name,
					Access:      t.Access,
				}, true
			}
		}
	}
	return ToolDescriptor{}, false
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
		return map[string]any{schemaKeyType: contentTypeText, contentTypeText: fmt.Sprintf("[marshal error: %s]", err)}
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]any{schemaKeyType: contentTypeText, contentTypeText: string(data)}
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
