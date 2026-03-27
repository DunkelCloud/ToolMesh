# ToolMesh

> The secure, durable execution layer between AI agents and enterprise infrastructure.

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DunkelCloud/ToolMesh)](https://goreportcard.com/report/github.com/DunkelCloud/ToolMesh)

## The Problem

MCP gateways pass tool calls straight through. That creates real risks in production:

- **Confused Deputy** — an LLM can invoke any tool with any user's privileges
- **Credential Leakage** — API keys end up in prompts, logs, and model context
- **No Durability** — if a tool call fails mid-flight, there is no retry or audit trail
- **No Input Control** — any parameter combination is accepted without validation
- **No Output Control** — raw backend responses flow directly to the model without filtering

ToolMesh solves this by sitting between the AI agent and your MCP servers, enforcing authorization, injecting credentials securely, providing durable execution, and gating output.

## The Six Pillars

| Pillar | What it does | Backed by |
|--------|-------------|-----------|
| **Code Mode** | LLMs write typed JS instead of error-prone JSON | AST-parsed tool calls |
| **Temporal** | Durable execution with retry, timeout, audit trail | Temporal.io |
| **OpenFGA** | Fine-grained authorization (user → plan → tool) | OpenFGA |
| **MCP Aggregation** | Connect any number of external MCP servers | Go MCP SDK |
| **REST Proxy Mode** | Declarative YAML describes any REST API — no MCP server needed | DADL (.dadl files) |
| **Credential Store** | Inject secrets at execution time, never in prompts | Per-request injection via Executor pipeline |
| **Gate** | JavaScript policies validate inputs (pre) and filter outputs (post) | goja |

## Quickstart

```bash
# Clone
git clone https://github.com/DunkelCloud/ToolMesh.git
cd ToolMesh

# Configure
cp .env.example .env
# Edit .env with your settings

# Start all services (runs in bypass mode by default — no authz required)
docker compose up -d

# Optional: Bootstrap OpenFGA and enable authorization
docker compose exec toolmesh /tm-bootstrap
# Set OPENFGA_MODE=restrict in .env and restart to enforce authz

# Connect from Claude Desktop or any MCP client
# MCP endpoint: http://localhost:8080/mcp
```

### Connect to Claude Desktop

Add to your Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "toolmesh": {
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

### Connect to Claude.ai (Custom Connector)

ToolMesh supports OAuth 2.1 with PKCE S256 for remote access. Configure users in `config/users.yaml` and use the public URL as the MCP endpoint.

## Authentication

ToolMesh supports two authentication methods that can be used independently or together. All OAuth state (tokens, auth codes, clients) is persisted in Redis and survives server restarts.

### OAuth 2.1 (Interactive Login)

Define users in `config/users.yaml` with bcrypt-hashed passwords:

```yaml
users:
  - username: admin
    password_hash: "$2a$10$..."
    company: dunkelcloud
    plan: pro
    roles: [admin]
```

Generate password hashes with the bootstrap tool:

```bash
docker compose exec toolmesh /tm-bootstrap hash-password "my-password"
```

For single-user setups, `TOOLMESH_AUTH_PASSWORD` still works as a fallback. Configure the identity with `TOOLMESH_AUTH_USER`, `TOOLMESH_AUTH_PLAN`, and `TOOLMESH_AUTH_ROLES` (defaults: `owner`, `pro`, `admin`).

### API Keys (Programmatic Access)

Define API keys in `config/apikeys.yaml` with bcrypt-hashed keys:

```yaml
keys:
  - key_hash: "$2a$10$..."
    user_id: claude-code-user
    company_id: dunkelcloud
    plan: pro
    roles: [tool-executor]
```

Each key maps to a distinct user identity with its own plan and roles, which flow through to OpenFGA authorization.

For single-key setups, `TOOLMESH_API_KEY` still works as a fallback. The same `TOOLMESH_AUTH_USER`, `TOOLMESH_AUTH_PLAN`, and `TOOLMESH_AUTH_ROLES` variables control the identity.

### DCR Rate Limiting

Dynamic Client Registration is rate-limited to 5 registrations per hour per IP to prevent abuse.

## Caller-Origin

ToolMesh tracks which AI client triggers each tool call. No known MCP gateway differentiates by the calling AI model — ToolMesh does.

**CallerID** is derived automatically from the authentication source:
- **OAuth clients:** The `client_name` from Dynamic Client Registration (e.g. `"claude-code"`)
- **API keys:** The `caller_id` field in `config/apikeys.yaml`
- **Anonymous:** Falls back to `"anonymous"`

**CallerClass** maps CallerIDs to trust levels via `config/caller-classes.yaml`:

```yaml
classes:
  trusted:
    - claude-code
    - claude-desktop
    - local-llm
  standard:
    - partner-*
  # Everything else defaults to "untrusted"
```

Trust levels affect the execution pipeline:

| CallerClass | PII Filtering | Tool Access | Audit |
|-------------|--------------|-------------|-------|
| `trusted` | Credentials only (AWS keys, API tokens) | Full | Temporal search attributes |
| `standard` | High-risk PII + credentials | Full | Temporal search attributes |
| `untrusted` | All PII patterns | Sensitive tools blocked | Temporal search attributes |

Temporal search attributes (`ToolMeshCallerID`, `ToolMeshCallerClass`, `ToolMeshUserID`, `ToolMeshCompanyID`, `ToolMeshToolName`) enable audit queries like:

```
ToolMeshCallerClass = "untrusted" AND ToolMeshToolName = "memorizer:retrieve_knowledge"
```

Register search attributes with: `docker compose exec toolmesh /tm-bootstrap temporal-search-attrs`

## Authorization Mode

`OPENFGA_MODE` controls whether OpenFGA authorization is enforced:

| Mode | Behavior |
|------|----------|
| `bypass` (default) | All tool calls are allowed without authz checks |
| `restrict` | OpenFGA enforces user → plan → tool authorization (requires `OPENFGA_STORE_ID`) |

Start with `bypass` to get running quickly, then switch to `restrict` after bootstrapping OpenFGA.

## Configuration

See [docs/configuration.md](docs/configuration.md) for all environment variables.

### Timeout tuning

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_MCP_TIMEOUT` | `120` | HTTP client timeout (seconds) for calls to downstream MCP servers |
| `TOOLMESH_ACTIVITY_TIMEOUT` | `120` | Temporal activity StartToClose timeout (seconds) for tool execution |

Increase these for backends that need more time (e.g. browser-based web fetchers):

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_ACTIVITY_TIMEOUT=180
```

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `debug` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | Output format: `json` or `text` |

The default level is `debug` so that MCP communication issues (requests, responses, errors) are fully traceable out of the box. For production, set `LOG_LEVEL=info` to reduce log volume.

At `debug` level, ToolMesh logs the complete request/response flow between clients and backends:
- Incoming JSON-RPC method, params, and request ID
- Outgoing JSON-RPC results and errors
- Backend connection lifecycle (connect, discover, disconnect)
- Tool call parameters sent to MCP backends and their responses
- Executor pipeline steps (authz, credential injection, gate pre, execution, gate post)

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full architecture documentation.

```mermaid
graph LR
    Agent[AI Agent] -->|"MCP + CallerID"| TM[ToolMesh]
    TM -->|AuthN/State| Redis
    TM -->|AuthZ| FGA[OpenFGA]
    TM -->|Durable Exec + Search Attrs| Temporal
    TM -->|Per-Request Injection| CS[Credential Store]
    TM -->|MCP Client| B1[MCP Server 1]
    TM -->|MCP Client| B2[MCP Server 2]
    TM -->|"Gate pre/post (CallerClass)"| Policy[JS Policies]
```

## Adding an External MCP Server

Create or edit `config/backends.yaml`:

```yaml
backends:
  - name: memorizer
    transport: http
    url: "https://memorizer.example.com/mcp"
    api_key_env: "MEMORIZER_API_KEY"

  - name: local-tools
    transport: stdio
    command: "./my-mcp-server"
    args: ["--port", "0"]
```

Set the credential as an environment variable:

```bash
CREDENTIAL_MEMORIZER_API_KEY=sk-mem-xxxxx
```

Tools from each backend are exposed with a prefix: `memorizer_retrieve_knowledge`, `local-tools_my_tool`. Credentials are injected by the Executor at runtime via the CredentialStore — the LLM never sees API keys.

## REST Proxy Mode (DADL)

MCP servers are structurally always a subset of the REST API they wrap. After just a few minutes of productive usage, you will hit endpoints that the MCP server does not expose. The REST Proxy Mode solves this permanently: describe any REST API in a `.dadl` file and ToolMesh calls it directly — no MCP server needed.

```
Current:    Claude → ToolMesh → MCP Server → REST API
New:        Claude → ToolMesh → REST API (via .dadl file)
```

Both modes run in parallel. Add a REST backend to `config/backends.yaml`:

```yaml
backends:
  - name: vikunja
    transport: rest
    dadl: /app/dadl/vikunja.dadl
    url: "https://vikunja.example.com/api/v1"  # overrides base_url in .dadl
```

The `url` field is optional — it overrides the `base_url` in the `.dadl` file. This is useful for APIs like Vikunja where each deployment has a different URL, while APIs like Stripe can hardcode their URL in the `.dadl` file.

### Writing a .dadl File

A `.dadl` file describes a REST API declaratively:

```yaml
version: "1.0"
backend:
  name: myapi
  type: rest
  base_url: https://api.example.com/v1  # optional if url is set in backends.yaml
  description: "My API service"

  auth:
    type: bearer                    # bearer, oauth2, session, apikey
    credential: my-api-token        # logical name for CredentialStore
    inject_into: header
    header_name: Authorization
    prefix: "Bearer "

  defaults:
    headers:
      Content-Type: application/json
    pagination:
      strategy: page                # cursor, offset, page, link_header
      request:
        page_param: page
        limit_param: per_page
        limit_default: 50
      response:
        total_pages_header: x-total-pages
      behavior: auto
      max_pages: 20
    errors:
      format: json
      message_path: "$.message"
      retry_on: [429, 502, 503]
      terminal: [400, 404]
      retry_strategy:
        max_retries: 3
        backoff: exponential
        initial_delay: 1s

  tools:
    list_items:
      method: GET
      path: /items
      description: "List all items"
      params:
        page: { type: integer, in: query }
        search: { type: string, in: query }

    get_item:
      method: GET
      path: /items/{id}
      description: "Get a single item"
      params:
        id: { type: integer, in: path, required: true }
      pagination: none

    create_item:
      method: POST
      path: /items
      description: "Create an item"
      params:
        name: { type: string, in: body, required: true }
        tags: { type: array, in: body }
      pagination: none
```

REST Proxy tools integrate seamlessly into Code Mode:

```javascript
const tasks = await toolmesh.vikunja_list_project_tasks({ project_id: 1 });
await toolmesh.vikunja_set_task_position({ id: 42, position: 1.5, project_view_id: 1 });
```

### DADL Features

- **Auth**: Bearer token, OAuth2 client_credentials, session-based login, API key (header or query)
- **Pagination**: Automatic multi-page fetching (cursor, offset, page number, Link header)
- **Error Handling**: Configurable retry on transient errors (429, 5xx) with exponential backoff
- **Response Transformation**: JSONPath extraction (`result_path`) and jq filters (`transform`)
- **Scoping**: Type definitions ready for large APIs (>100 tools) — implementation progressive

## Code Mode

Instead of raw JSON tool calls, LLMs can use typed JavaScript:

```javascript
// List available tools with TypeScript definitions
const tools = await toolmesh.list_tools();

// Execute tools with typed parameters
const result = await toolmesh.memorizer_retrieve_knowledge({
  query: "project architecture",
  top_k: 5
});
```

ToolMesh parses the code, extracts tool calls, and routes them through the full execution pipeline (AuthZ → Credentials → Gate pre → Backend → Gate post).

## Extension Model

ToolMesh uses a registry-based extension model inspired by Go's `database/sql` driver pattern. Three component types are extensible via `init()` registration:

| Component | Built-in | Config |
|-----------|----------|--------|
| Credential Store | `embedded` | `CREDENTIAL_STORE=<name>` |
| Tool Backend | `mcp`, `echo` | `config/backends.yaml` |
| Gate Evaluator | `goja` | `GATE_EVALUATORS=<list>` |

Enterprise extensions (InfisicalStore, VaultStore, Compliance-LLM, etc.) are available separately and included via Go build tags: `go build -tags enterprise ./cmd/toolmesh`.

See [docs/architecture.md](docs/architecture.md#extension-model) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — Copyright 2025 [Dunkel Cloud GmbH](https://dunkel.cloud)
