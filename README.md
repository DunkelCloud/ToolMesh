# ToolMesh — Turn any REST API into MCP tools

> The secure, durable execution layer between AI agents and enterprise infrastructure.

[![Go](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/DunkelCloud/ToolMesh)](https://goreportcard.com/report/github.com/DunkelCloud/ToolMesh)

## 30 lines of YAML. No server to build.

In practice, MCP servers only expose a fraction of the REST API they wrap — and you'll hit the gaps fast. ToolMesh lets you replace the wrapper layer with `.dadl` files — a declarative YAML format that describes any REST API as MCP tools. No wrapper server to build, deploy, or maintain.

```
Current:    Claude → ToolMesh → MCP Server → REST API
With DADL:  Claude → ToolMesh → REST API (via .dadl file)
```

You don't write the YAML by hand. You ask an LLM. Claude, GPT, Gemini — any model that knows the DADL spec generates a working `.dadl` file in seconds. Describe what you need, drop the file into `config/dadl/`, done.

> "Create a DADL for the GitHub API — list repos, open issues, and create pull requests."

10 seconds. Works with any LLM that knows the format.

And unlike MCP gateways that just pass tool calls through, ToolMesh adds what production deployments actually need:

- **Authorization** — fine-grained user → plan → tool control (OpenFGA)
- **Credential Security** — secrets injected at execution time, never in prompts
- **Audit Trail** — every tool call recorded with structured logging or queryable SQLite
- **Input & Output Gating** — JS policies validate parameters and filter responses

## The Six Pillars

| Pillar | What it does | Backed by |
|--------|-------------|-----------|
| **Any Backend** | Connect MCP servers or describe REST APIs declaratively via DADL | Go MCP SDK + DADL (.dadl files) |
| **Code Mode** | LLMs write typed JS instead of error-prone JSON | AST-parsed tool calls |
| **Audit** | Execution trail — every tool call recorded and queryable | slog / SQLite |
| **OpenFGA** | Fine-grained authorization (user → plan → tool) | OpenFGA |
| **Credential Store** | Inject secrets at execution time, never in prompts | Per-request injection via Executor pipeline |
| **Gate** | JavaScript policies validate inputs (pre) and filter outputs (post) | goja |

## Quickstart

```bash
# Clone
git clone https://github.com/DunkelCloud/ToolMesh.git
cd ToolMesh

# Configure
cp .env.example .env
# IMPORTANT: Set a password — without it, all requests are rejected:
#   TOOLMESH_AUTH_PASSWORD=my-secret-password
# Or set an API key for programmatic access:
#   TOOLMESH_API_KEY=my-api-key

# Start all services (runs in bypass mode by default — no authz required)
docker compose up -d

# Optional: Bootstrap OpenFGA and enable authorization
docker compose exec toolmesh /tm-bootstrap
# Set OPENFGA_MODE=restrict in .env and restart to enforce authz

# Verify it's running (default port: 8123)
curl http://localhost:8123/health

# MCP endpoint: http://localhost:8123/mcp
# Note: Most MCP clients require HTTPS — see TLS section below
```

### TLS (important)

ToolMesh itself serves plain HTTP. **Most MCP clients — including Claude Desktop — require HTTPS** and will reject `http://` URLs. You need a TLS-terminating reverse proxy in front of ToolMesh:

| Option | When to use |
|--------|-------------|
| **Caddy** | Self-hosted with a public domain — automatic Let's Encrypt certs |
| **Cloudflare Tunnel** | No open ports needed, zero-config TLS |
| **nginx / Traefik** | Already in your stack |

For **local development only**, you can bypass TLS by editing `claude_desktop_config.json` by hand (the GUI enforces `https://`).

### Connect to Claude Desktop

Add to your Claude Desktop MCP config:

```json
{
  "mcpServers": {
    "toolmesh": {
      "url": "https://toolmesh.example.com/mcp"
    }
  }
}
```

For local development without TLS proxy:

```json
{
  "mcpServers": {
    "toolmesh": {
      "url": "http://localhost:8123/mcp"
    }
  }
}
```

### Connect to Claude.ai (Custom Connector)

ToolMesh supports OAuth 2.1 with PKCE S256 for remote access. Configure users in `config/users.yaml` and use the public HTTPS URL as the MCP endpoint.

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

Generate password hashes with the bootstrap tool or any bcrypt-capable utility:

```bash
# Using tm-bootstrap (inside the container)
docker compose exec toolmesh /tm-bootstrap hash-password "my-password"

# Or using htpasswd (on the host)
htpasswd -nbBC 10 "" "my-password" | cut -d: -f2
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

ToolMesh tracks which AI client triggers each tool call. This lets operators restrict high-risk tools for low-trust clients, apply different PII filtering per caller, and audit who did what — all without maintaining separate MCP deployments.

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
| `trusted` | Credentials only (AWS keys, API tokens) | Full | Audit entry with caller context |
| `standard` | High-risk PII + credentials | Full | Audit entry with caller context |
| `untrusted` | All PII patterns | Sensitive tools blocked | Audit entry with caller context |

Audit entries include `caller_id`, `caller_class`, `user_id`, `company_id`, and `tool` fields. With the `sqlite` audit store, these are queryable:

```sql
SELECT * FROM audit_events WHERE caller_class = 'untrusted' AND tool = 'memorizer_retrieve_knowledge';
```

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
| `TOOLMESH_EXEC_TIMEOUT` | `120` | Tool execution timeout (seconds) — context deadline for backend calls |

Increase these for backends that need more time (e.g. browser-based web fetchers):

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_EXEC_TIMEOUT=180
```

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `debug` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | Output format: `json` or `text` |
| `DEBUG_BACKENDS` | *(empty)* | Comma-separated backend names for per-backend debug logging |
| `DEBUG_FILE` | *(empty)* | Path to a separate debug log file (e.g. `debug.log`) |

**Development default.** The default level is `debug` so that MCP communication issues are fully traceable out of the box. At this level, ToolMesh logs complete request/response payloads which may include sensitive data. **For production, set `LOG_LEVEL=info` or higher.**

At `debug` level, ToolMesh logs the complete request/response flow between clients and backends:
- Incoming JSON-RPC method, params, and request ID
- Outgoing JSON-RPC results and errors
- Backend connection lifecycle (connect, discover, disconnect)
- Tool call parameters sent to MCP backends and their responses
- Executor pipeline steps (authz, credential injection, gate pre, execution, gate post)

#### Per-backend debug file

When troubleshooting a specific backend, set `DEBUG_BACKENDS` and `DEBUG_FILE` to write debug-level output for only the named backends to a separate file. The file also includes the ToolMesh startup banner (version, commit, build date) so recipients have full context. Normal stdout logging continues at the global `LOG_LEVEL` unchanged.

```bash
DEBUG_BACKENDS=github
DEBUG_FILE=debug.log
LOG_LEVEL=error          # keep stdout quiet, debug goes to the file
```

The `./data` directory is typically volume-mounted to the host, so the debug file is directly accessible without `docker cp`.

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full architecture documentation.

```
                          ┌─────────────────────────────────┐
                          │          ToolMesh               │
                          │                                 │
                          │  Redis · OpenFGA · Audit        │
                          │  Credential Store · JS Gate     │
                          │                                 │
AI Agent ──MCP──────────▶ │   AuthZ ▸ Creds ▸ Gate ▸ Exec  │
                          │                                 │
                          └──┬──────┬───────┬───────┬───────┘
                             │      │       │       │
                          MCP Client  .dadl   .dadl   .dadl
                             │      │       │       │
                             ▼      ▼       ▼       ▼
                          MCP     Stripe  GitHub  Vikunja
                          Server   API     API     API
```

## Adding an External MCP Server

Create or edit `config/backends.yaml`:

```yaml
backends:
  - name: memorizer
    transport: http
    url: "https://memorizer.example.com/mcp"
    api_key_env: "MEMORIZER_API_KEY"
```

Set the credential as an environment variable:

```bash
CREDENTIAL_MEMORIZER_API_KEY=sk-mem-xxxxx
```

Tools from each backend are exposed with a prefix (e.g. `memorizer_retrieve_knowledge`). Credentials are injected by the Executor at runtime via the CredentialStore — the LLM never sees API keys.

## REST Proxy Mode (DADL)

When an MCP server doesn't expose an endpoint you need, describe it in a `.dadl` file and ToolMesh calls the REST API directly — no wrapper server needed.

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

### A taste of DADL

Want Claude to list GitHub issues? Here's all it takes:

```yaml
tools:
  list_issues:
    method: GET
    path: /repos/{owner}/{repo}/issues
    description: "List issues for a repository"
    params:
      owner: { type: string, in: path, required: true }
      repo:  { type: string, in: path, required: true }
      state: { type: string, in: query }
```

That's it — ToolMesh handles auth, pagination, retries, and error mapping. The full `.dadl` format below adds these as declarative defaults.

### Writing a .dadl File

A `.dadl` file describes a REST API declaratively:

```yaml
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
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

### Creating DADLs

As shown above, the fastest path is asking an LLM. If you use Claude Code with ToolMesh connected, it can create the `.dadl` file, add the backend entry to `config/backends.yaml`, and set the credential — all in one session.

Before submitting a DADL to the registry, validate it locally with `dadl validate myapi.dadl`. To share a DADL with the community, either email it to dadl@dunkel.cloud or open a PR on the [dadl-registry](https://github.com/DunkelCloud/dadl-registry).

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
