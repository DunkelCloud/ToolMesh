# ToolMesh

**Your agent gets the tools. ToolMesh keeps the keys.**

ToolMesh is a self-hosted MCP gateway. Claude, ChatGPT and other MCP clients connect to one endpoint and call tools from GitHub, NetBox, Stripe, Zammad or your own REST API. ToolMesh holds the API keys, checks for every call whether the caller may make it, and writes each call to an audit log.

REST APIs come in through DADL files, a few lines of YAML per endpoint that an LLM can write for you. Existing MCP servers, over HTTP or stdio, sit behind the same endpoint. Use it when agents need your internal systems and you want to decide who may call what without handing out API keys.

[![CI](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml/badge.svg)](https://github.com/DunkelCloud/ToolMesh/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## Why

An MCP client that talks to five systems usually holds five API keys in its configuration, and every agent that uses the client may call every tool those keys open. An MCP server offers the endpoints its author chose; when you need another one, you wait for a release or fork the server. And when an agent did something unexpected, the question "which tool did it call, with which parameters?" often has no answer.

ToolMesh moves the keys, the permissions and the record of calls into one service you run yourself.

## What you get

- One MCP endpoint for many backends: REST APIs through DADL files and existing MCP servers over HTTP or stdio. Tools are named `<backend>_<tool>`, for example `github_list_issues`.
- API keys stay on the server. ToolMesh reads them from its environment (`CREDENTIAL_<NAME>`) and adds them to the request at call time, so they appear neither in prompts nor in the client configuration.
- Authorization from the first start. OpenFGA runs inside ToolMesh; grants name users, roles, plans or companies and allow all tools, a backend, single tools or an access class such as `read`. Tool listings show each caller only what it may call. Rights that are needed only now and then can be bundled as kits: the agent asks for one, a person approves it, and the grant ends after its time.
- An audit entry for every call: who called which tool with which parameters, how long it took and how it ended. By default as structured log lines; with `AUDIT_STORE=sqlite` in a database you can query with SQL.
- Code Mode. The model sees two tools, `discover_tools` and `execute_code`, looks up the signatures it needs and writes short JavaScript that makes several calls in one round trip. A client with hundreds of tools behind ToolMesh does not load all their definitions into its context.
- Optional JavaScript policies that check a call before it runs and filter its result, for example to redact personal data. Examples are in [`config/policies/examples/`](config/policies/examples/).
- Optional house rules per backend. A `hint` in `backends.yaml` says what an agent must know before it uses a backend, such as a naming convention. With `hint_required_for`, writes are refused until the agent shows that it has received the hint, so every conversation gets it before its first write.

## How it works

Every tool call runs through the same steps. A step that fails stops the call, and every exit writes an audit entry.

```
MCP client (Claude Code, Claude Desktop, ChatGPT, ...)
   |
   |  one MCP endpoint, e.g. https://toolmesh.example.com/mcp
   v
ToolMesh
   1. authenticate     OAuth 2.1 or API key
   2. authorize        OpenFGA: may this caller call this tool?
   3. add credential   the backend's API key, from the server's environment
   4. policy, before   optional JavaScript check of the parameters
   5. call             REST API via DADL, or an MCP server
   6. policy, after    optional JavaScript filter of the result
   7. audit            one entry per call, also for denied and failed calls
   |
   v
GitHub API, NetBox API, your own REST API, existing MCP servers
```

A DADL file describes a REST API as MCP tools. This is all it takes for a tool that lists the issues of a GitHub repository:

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

The file also declares how the API authenticates (bearer token, API key, OAuth2, session login), how it pages and when to retry. ToolMesh does the HTTP work. The [DADL registry](https://dadl.ai/browse) has descriptions for 36 APIs; for others, ask an LLM that knows the [DADL spec](https://dadl.ai/spec/dadl-spec-v0.2) and test the result against the real API.

In Code Mode the model calls these tools from JavaScript:

```javascript
const repos = await toolmesh.github_list_repos({ sort: "updated" });
const issues = await toolmesh.github_list_issues({
  owner: repos[0].owner.login,
  repo: repos[0].name,
  state: "open"
});
```

The script runs in a sandbox (goja) inside ToolMesh, and each `toolmesh.*` call goes through the steps above. More in [docs/architecture.md](docs/architecture.md).

## Status

ToolMesh is at version 0.x. A minor release can still change the configuration; the [changelog](CHANGELOG.md) lists under *Changed* and *Deprecated* what an operator has to adjust.

`docker compose up` pulls the latest release (`ghcr.io/dunkelcloud/toolmesh:latest`, at present v0.6.0). This README describes `main`; when `main` is ahead of the latest release, this section names what the release does not have yet.

## Getting started

To look first, connect an MCP client to the public demo at [demo.toolmesh.io](https://www.toolmesh.io/en/demo/). It serves the Hacker News APIs; login `dadl` / `toolmesh`.

For your own instance you need:

- Docker with Docker Compose. The Compose file starts ToolMesh and KeyDB (Redis-compatible, holds the OAuth state).
- A free port, 8123 by default (`TOOLMESH_PORT`).
- For Claude Desktop, claude.ai and most other clients an HTTPS URL, so a reverse proxy with TLS in front of ToolMesh (see [Connecting clients](#connecting-clients)). Claude Code also connects over plain HTTP on localhost.

The following steps end with a first tool call. They use the Hacker News DADL that ships with ToolMesh and needs no API key.

1. Clone the repository.

   ```bash
   git clone https://github.com/DunkelCloud/ToolMesh.git
   cd ToolMesh
   ```

2. Create `.env` and set an API key. Without a password or API key ToolMesh rejects every request.

   ```bash
   cp .env.example .env
   # in .env:
   #   TOOLMESH_API_KEY=<output of: openssl rand -hex 32>
   ```

3. Register the Hacker News backend.

   ```bash
   cat > config/backends.yaml <<'EOF'
   backends:
     - name: hackernews
       transport: rest
       dadl: hackernews.dadl
   EOF
   ```

4. Start ToolMesh and check that it answers.

   ```bash
   docker compose up -d
   curl http://localhost:8123/health
   ```

5. Connect Claude Code.

   ```bash
   claude mcp add -t http \
     -H "Authorization: Bearer <YOUR_API_KEY>" \
     -s user toolmesh http://localhost:8123/mcp
   ```

6. Ask Claude Code: "What are the top stories on Hacker News right now?" It calls `hackernews_get_top_stories` through ToolMesh, and the audit entry shows up in `docker compose logs toolmesh`.

### Your own API

1. Take a DADL from [dadl.ai/browse](https://dadl.ai/browse) or have an LLM write one, and put the file into `dadl/`.
2. Add the backend to `config/backends.yaml`:

   ```yaml
   backends:
     - name: deepl
       transport: rest
       dadl: deepl.dadl
       url: "https://api.deepl.com/v2"
   ```

3. Put the API key into `.env`. The name is `CREDENTIAL_` plus the DADL's `credential` field in upper snake case; the DADL's `setup` section names it.

   ```bash
   CREDENTIAL_DEEPL_AUTH_KEY=your-deepl-api-key
   ```

4. Apply the change with `docker compose up -d` (a plain `restart` does not read a changed `.env`).

For internal services on private addresses or with self-signed certificates, a backend entry takes `allow_private_url` (default: true) and `tls_skip_verify` (default: false).

### An existing MCP server

```yaml
backends:
  - name: notes
    transport: http
    url: "https://notes.example.com/mcp"
    api_key_env: "NOTES_API_KEY"
```

with `CREDENTIAL_NOTES_API_KEY=...` in `.env`. A local MCP server runs with `transport: stdio`, `command` and `args`; [config/backends.yaml.example](config/backends.yaml.example) shows all fields.

## What it does not do

- It does not terminate TLS. ToolMesh serves plain HTTP; put a reverse proxy in front for anything beyond localhost.
- It holds the backends' keys. Each client still signs in to ToolMesh, with OAuth or with an API key that sits in its configuration.
- It enforces no policy until you add one. The policy engine runs every `.js` file directly in `config/policies/`; the shipped examples lie one level deeper and stay inactive.
- Its default audit log is write-only. Searching past calls with SQL needs `AUDIT_STORE=sqlite`.
- It speaks REST through DADL and MCP. Other protocols, such as gRPC, SOAP or direct database access, need an MCP server in front.
- It does not check a DADL an LLM wrote. Test new tools against the real API, best with a throwaway account or test data.
- An `execute_code` script makes at most 50 tool calls and runs at most 120 seconds (`TOOLMESH_CODE_TIMEOUT`).

## Telemetry

ToolMesh sends usage statistics once every 24 hours, the first time a few minutes after the first start: a random site ID, the SHA-256 hash of each DADL file, the number of tool calls and errors per DADL, the number of MCP server backends and the ToolMesh version. It sends no user IDs, keys, parameters, URLs, host names or request content; the receiving endpoint sees the sender's IP address. To switch it off, set `DO_NOT_SEND_ANONYMOUS_STATISTICS=yes` in `.env`. Details are in [.env.example](.env.example).

## Connecting clients

ToolMesh serves plain HTTP. Most MCP clients, Claude Desktop among them, accept only `https://` URLs, so they need a reverse proxy with TLS:

| Option | When to use |
|--------|-------------|
| Caddy | Self-hosted with a public domain, automatic Let's Encrypt certificates |
| Cloudflare Tunnel | No open ports |
| nginx / Traefik | Already in your stack |

Claude Desktop, in its MCP config:

```json
{
  "mcpServers": {
    "toolmesh": {
      "url": "https://toolmesh.example.com/mcp"
    }
  }
}
```

For local development without a proxy, `http://localhost:8123/mcp` works if you edit `claude_desktop_config.json` by hand (the settings dialog requires `https://`).

claude.ai (custom connector) and ChatGPT sign in with OAuth 2.1 (PKCE S256); use the public HTTPS URL as the MCP endpoint.

## Authentication

Clients sign in with OAuth 2.1, which suits clients with a login dialog, or send an API key as bearer token, which suits Claude Code and scripts. Both work side by side. OAuth state (tokens, codes, registered clients) is kept in Redis and survives restarts.

For one person, `TOOLMESH_AUTH_PASSWORD` (OAuth login) or `TOOLMESH_API_KEY` in `.env` is enough. `TOOLMESH_AUTH_USER`, `TOOLMESH_AUTH_PLAN` and `TOOLMESH_AUTH_ROLES` set the identity (defaults: `owner`, `pro`, `admin`).

For several users, list them in `config/users.yaml` with bcrypt hashes:

```yaml
users:
  - username: alice
    password_hash: "$2a$10$..."
    company: example
    plan: pro
    roles: [admin]
```

```bash
htpasswd -nbBC 10 "" "my-password" | cut -d: -f2
```

and API keys in `config/apikeys.yaml`, each named by the SHA-256 of the key:

```yaml
keys:
  - key_sha256: "<SHA-256 of the key, 64 hex characters>"
    user_id: ci-bot
    company_id: example
    plan: pro
    roles: [tool-executor]
```

```bash
KEY="tm_$(openssl rand -hex 32)"
printf '%s' "$KEY" | sha256sum | cut -d' ' -f1
```

Each key maps to its own identity, whose plan and roles flow into authorization. Entries with a bcrypt `key_hash` from earlier versions keep working. Failed logins are throttled per account and per address, and a request without a valid credential gets a `401` that starts the OAuth flow in MCP clients. See [docs/configuration.md](docs/configuration.md#api-keys) for keys, [login throttling](docs/configuration.md#login-throttling), [unauthenticated requests](docs/configuration.md#unauthenticated-requests) and [client registration](docs/configuration.md#client-registration).

## Authorization

Every tool call is checked, and tool listings show each caller only the tools it may call. ToolMesh runs [OpenFGA](https://openfga.dev) in its own process and keeps the data in `data/authz.db`; `TOOLMESH_AUTHZ_MODE=external` uses an OpenFGA server you operate instead, `disabled` switches checks off (reported at every start and in the audit trail).

Without a grants file a preset applies:

| Preset | Who may call what |
|--------|-------------------|
| `single-user` | the owner (`TOOLMESH_AUTH_USER`) and role `admin`: every tool. Default without `users.yaml`/`apikeys.yaml`. |
| `team` | as `single-user`, plus plan `pro`: every tool, plan `free`: every `read` tool. Default with `users.yaml` or `apikeys.yaml`. |
| `open` | every authenticated caller: every tool |

For finer control, copy `config/authz.yaml.example` to `config/authz.yaml`. Grants name all tools, backends, single tools or DADL access classes (`read`, `write`, ...); denies win over every grant. Changes take effect within seconds.

```yaml
grants:
  - plan: pro
    backends: [github, deepl]
  - plan: free
    access: [read]
  - role: support
    tools: [zammad_list_tickets]
denies:
  - plan: pro
    tools: [stripe_create_refund]
```

An installation upgraded from a version without authorization keeps every tool open to every authenticated caller (preset `open`) and says so at every start, until you pick a preset or write grants. Kits, approvers and the approval page are described in [docs/configuration.md](docs/configuration.md#kits).

## Configuration

All environment variables are in [docs/configuration.md](docs/configuration.md), among them [audit](docs/configuration.md#audit), [gate policies](docs/configuration.md#gate-policies), [timeouts](docs/configuration.md#timeouts), the [file broker](docs/configuration.md#file-broker), [backend health checks](docs/configuration.md#backend-health-checks) and [logging](docs/configuration.md#logging). Metrics are described in [docs/metrics.md](docs/metrics.md).

With `CREDENTIAL_STORE=command` ToolMesh takes the credentials from a command, such as a sops decryption, and keeps them in memory only, out of the environment that Docker writes into the container configuration on disk; see [docs/configuration.md](docs/configuration.md#command-store).

At startup ToolMesh logs one summary of every control that is still relaxed (missing credential, authorization disabled or open to everyone, open CORS, debug tools, login limits switched off, file broker without quota), each with how to tighten it. The entries are `WARN`; `TOOLMESH_DEV=true` reports them once at `INFO` on a development machine and changes nothing else.

The log level is `info`. At `debug`, ToolMesh logs complete request URLs and payloads, which puts query-string API keys into the log; keep it off in production.

Prometheus metrics are served on a separate, unauthenticated listener. The Compose file binds its host port (9090) to `127.0.0.1`; set `TOOLMESH_METRICS_HOST=0.0.0.0` only if you scrape from another host and have firewalled the port.

`TOOLMESH_DEBUG_TOOLS=true` adds two diagnostic tools: `debug_echo` returns size and SHA-256 of a payload, `debug_generate` produces a printable string of N bytes. They help to find transport size limits between the client and ToolMesh. Off by default and not meant for production.

## Extension model

Credential stores (`embedded` and `command`, selected with `CREDENTIAL_STORE`), tool backends (`mcp`, `rest`, `echo`, configured in `config/backends.yaml`) and gate evaluators (`goja`, `GATE_EVALUATORS`) register themselves via `init()`, in the style of Go's `database/sql` drivers. See [docs/architecture.md](docs/architecture.md#extension-model).

## Building from source

Go 1.26 or later.

```bash
make build    # binaries
make test     # go test ./...
make lint     # go vet, gofmt check, golangci-lint (as in CI)
make docker   # production image
```

To run your own build with Compose, see `docker-compose.override.yml.example`.

## Who's behind this

ToolMesh is built and maintained by [Axel Dunkel](https://github.com/axeldunkel) at [Dunkel Cloud GmbH](https://dunkel.cloud), a German company that has run cloud and edge infrastructure for businesses for years. ToolMesh and DADL grew out of that work and run in our own stack, and the people who answer `security@dunkel.cloud` write the code.

The [DADL registry](https://dadl.ai/browse) holds 36 API descriptions with about 4,500 tools, from 3 tools for YouTube video metadata to 608 tools for NetBox DCIM/IPAM. Each shows how much of its API it covers, in percent.

- Website: [toolmesh.io](https://www.toolmesh.io/)
- DADL spec and registry: [dadl.ai](https://dadl.ai)
- Security contact: security@dunkel.cloud (see [SECURITY.md](SECURITY.md))

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0, Copyright 2025–2026 [Dunkel Cloud GmbH](https://dunkel.cloud)
