# ToolMesh — Getting Started with Claude Code

ToolMesh is a secure MCP gateway that turns REST APIs into tools using DADL (Declarative API Description Language). This guide helps you set up ToolMesh and connect your first backend — all from this Claude Code session.

## Quick Start

```bash
# 1. Copy the example config
cp .env.example .env

# 2. Start ToolMesh
docker compose up -d

# 3. Verify it's running
curl http://localhost:8123/health
```

The MCP endpoint is available at `http://localhost:8123/mcp`.

## Connect Your AI Agent

### Claude Code

```bash
claude mcp add -t http \
  -H "Authorization: Bearer <YOUR_API_KEY>" \
  -s user toolmesh http://localhost:8123/mcp
```

Set `YOUR_API_KEY` to the value of `TOOLMESH_API_KEY` from your `.env` file.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "toolmesh": {
      "url": "https://toolmesh.example.com/mcp"
    }
  }
}
```

> **Note:** Claude Desktop requires HTTPS. For local development without TLS, edit the JSON file directly (the GUI enforces `https://`). Use Caddy, Cloudflare Tunnel, or nginx as a reverse proxy for production.

## Authentication

Edit `.env` to set at least one auth method:

```bash
# Option A: API key (for Claude Code, scripts)
TOOLMESH_API_KEY=my-api-key

# Option B: Password (for Claude Desktop, browser-based clients)
TOOLMESH_AUTH_PASSWORD=my-password
```

Without either, all requests are rejected.

## Add a Backend

ToolMesh supports three backend types: REST via DADL, MCP over HTTP, and MCP over STDIO.

### 1. Get a DADL file

Browse pre-built DADLs at [dadl.ai/browse](https://dadl.ai/browse) — or ask Claude Code:

> "Create a DADL for the Hetzner Cloud API — list servers, create server, delete server"

Place the `.dadl` file in the `dadl/` directory.

### 2. Register the backend

Copy the example config and add your backend:

```bash
cp config/backends.yaml.example config/backends.yaml
```

Add an entry to `config/backends.yaml`:

```yaml
backends:
  - name: deepl
    transport: rest
    dadl: deepl.dadl
    url: "https://api.deepl.com/v2"
```

The `dadl` field is the filename only (no path prefix) — ToolMesh looks in its DADL directory.

### 3. Set credentials

Add the credential to `.env`. The DADL's `setup` section tells you which variable to use:

```bash
CREDENTIAL_DEEPL_AUTH_KEY=your-deepl-api-key
```

The naming convention: `CREDENTIAL_` + the DADL's `credential` field in UPPER_SNAKE_CASE.
Credentials are injected at execution time — the AI model never sees the raw secret.

### 4. Restart

```bash
docker compose restart toolmesh
```

Tools are now available as `deepl:translate`, `deepl:list_languages`, etc.

## DADL at a Glance

A DADL file describes a REST API in YAML. Minimal structure:

```yaml
spec: "https://dadl.ai/spec/dadl-spec-v0.1.md"
credits:
  - "Your Name"
source_name: "My API"
source_url: "https://api.example.com/docs"
date: "2026-01-01"

backend:
  name: myapi
  type: rest
  base_url: https://api.example.com
  description: "Short description of the API"

  auth:
    type: bearer
    credential: myapi_token
    inject_into: header
    header_name: Authorization
    prefix: "Bearer "

  tools:
    list_items:
      method: GET
      path: /items
      description: "List all items"
      params:
        limit:
          type: integer
          in: query
          description: "Max items to return"
```

Full spec: [dadl.ai/spec](https://dadl.ai/spec/dadl-spec-v0.1)

## Useful Commands

```bash
docker compose up -d              # Start ToolMesh
docker compose logs -f toolmesh   # View logs
docker compose restart toolmesh   # Restart after config changes
curl http://localhost:8123/health  # Health check
```

## Architecture

ToolMesh processes every tool call through a fail-closed pipeline:

```
Auth -> AuthZ -> Credential Injection -> Execution -> Output Gate -> Audit
```

- **Auth**: Validates the caller (API key or OAuth 2.1)
- **AuthZ**: Checks permissions via OpenFGA (optional, default: bypass)
- **Credential Injection**: Injects secrets at runtime, invisible to the model
- **Execution**: Calls the backend API
- **Output Gate**: Applies JavaScript policies (PII filtering, device restrictions)
- **Audit**: Logs every call to stdout or SQLite

## What's Next

- [Architecture](https://toolmesh.io/architecture) — understand the execution pipeline
- [DADL Spec](https://dadl.ai/spec/dadl-spec-v0.1) — full specification
- [DADL Registry](https://dadl.ai/browse) — pre-built API descriptions
- [Configuration](https://toolmesh.io/configuration) — all environment variables
- [Authentication](https://toolmesh.io/authentication) — OAuth 2.1, API keys, multi-user
