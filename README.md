# ToolMesh — Let AI agents touch real systems. Safely.

> The missing control layer between AI agents and enterprise systems. ToolMesh turns uncontrolled AI tool calls into a governed, auditable process — and connects any REST API or MCP server in minutes, not months.

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

- **Credential Security** — secrets injected at execution time, never in prompts or LLM client configs
- **Authorization** — fine-grained user → plan → tool control (OpenFGA)
- **Input & Output Gating** — JS policies block confidential data and filter responses
- **Audit Trail** — every tool call recorded with structured logging or queryable SQLite

## The Six Pillars

| Pillar | What it does | Backed by |
|--------|-------------|-----------|
| **Any Backend** | 30 lines of DADL replace a whole MCP server. Also proxies existing MCP servers. | Go MCP SDK + DADL (.dadl files) |
| **Code Mode** | 15 MCP servers at once? Without ToolMesh, impossible. Code Mode cuts 50,000+ tokens to ~1,000. | AST-parsed tool calls |
| **Credential Store** | Secrets injected at execution time — never in prompts, never in LLM client configs | Per-request injection via Executor pipeline |
| **OpenFGA** | Fine-grained authorization (user → plan → tool). Example: free users get read-only, pro gets everything. | OpenFGA |
| **Gate** | Block confidential data before execution, redact PII in responses | goja |
| **Audit** | Every tool call recorded and queryable — answer "what did that agent do?" with SQL | slog / SQLite |

## Try the demo

Want to try ToolMesh before installing? Connect to our public demo instance — no Docker, no config, no API keys:

**[demo.toolmesh.io](https://toolmesh.io/demo)** — Hacker News APIs via ToolMesh. Works with Claude Desktop, Claude Code, and ChatGPT. Login: `dadl` / `toolmesh`.

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

# Optional: local overrides (build locally, enable OpenFGA, HTTPS proxy, ...)
# cp docker-compose.override.yml.example docker-compose.override.yml
# # then edit docker-compose.override.yml — picked up automatically by Docker Compose

# Start (runs in bypass mode by default — no authz required)
docker compose up -d

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

Generate password hashes with any bcrypt-capable utility:

```bash
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

ToolMesh uses structured logging via `slog`. The default level is `debug` for full MCP traceability out of the box — **set `LOG_LEVEL=info` or higher for production** since debug logs include complete request/response payloads. Per-backend debug files, log formats, and all logging variables are documented in [docs/configuration.md](docs/configuration.md#logging).

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

## REST Proxy Mode ([DADL](https://dadl.ai))

When an MCP server doesn't expose an endpoint you need, describe it in a `.dadl` file and ToolMesh calls the REST API directly — no wrapper server needed. Both modes run in parallel.

Add a REST backend to `config/backends.yaml`:

```yaml
backends:
  - name: vikunja
    transport: rest
    dadl: /app/dadl/vikunja.dadl
    url: "https://vikunja.example.com/api/v1"
```

For internal services with private IPs or self-signed certificates:

```yaml
backends:
  - name: internal-api
    transport: rest
    dadl: internal.dadl
    url: "https://192.168.1.50:8443/api"
    allow_private_url: true    # allow private/loopback addresses (default: true)
    tls_skip_verify: true      # accept self-signed certificates (default: false)
```

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

ToolMesh handles auth, pagination, retries, and error mapping. DADL supports bearer tokens, OAuth2, session auth, API keys, automatic pagination, retry with backoff, response transformation, composite tools, and more.

For the full spec, examples, and the community registry, see [dadl.ai](https://dadl.ai). The fastest way to create a `.dadl` file is asking any LLM that knows the format.

## Code Mode

Connect 15 MCP servers to a single AI agent? Without ToolMesh, that simply does not work — the context window fills up, the client chokes. Code Mode makes it possible.

Instead of exposing hundreds of individual tool definitions (50,000+ tokens), ToolMesh exposes two meta-tools: `list_tools` and `execute_code`. The LLM gets compact TypeScript interfaces (~1,000 tokens) and writes JavaScript against them:

```javascript
const repos = await toolmesh.github_list_repos({ sort: "updated" });
const issues = await toolmesh.github_list_issues({
  owner: repos[0].owner.login,
  repo: repos[0].name,
  state: "open"
});
```

Multiple API calls in a single round-trip. ToolMesh parses the code, extracts tool calls, and routes them through the full execution pipeline.

## Extension Model

ToolMesh uses a registry-based extension model inspired by Go's `database/sql` driver pattern. Three component types are extensible via `init()` registration:

| Component | Built-in | Config |
|-----------|----------|--------|
| Credential Store | `embedded` | `CREDENTIAL_STORE=<name>` |
| Tool Backend | `mcp`, `rest` (DADL), `echo` | `config/backends.yaml` |
| Gate Evaluator | `goja` | `GATE_EVALUATORS=<list>` |

Enterprise extensions (InfisicalStore, VaultStore, Compliance-LLM, etc.) are planned and will be included via Go build tags: `go build -tags enterprise ./cmd/toolmesh`.

See [docs/architecture.md](docs/architecture.md#extension-model) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0 — Copyright 2025–2026 [Dunkel Cloud GmbH](https://dunkel.cloud)
