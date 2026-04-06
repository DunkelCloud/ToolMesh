# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries here are kept short; see the corresponding
[GitHub Release](https://github.com/DunkelCloud/ToolMesh/releases)
for the full narrative and details.

## [0.1.3] - 2026-04-06

### Added

- Anonymous, opt-out telemetry: aggregated DADL usage statistics
  (content hash, call/error counts, MCP server count, version) sent
  to `tmc.dunkel.cloud` every 24 hours. Opt out via
  `DO_NOT_SEND_ANONYMOUS_STATISTICS=yes`. No individual data collected.
- SHA-256 `ContentHash` computed on DADL parse for telemetry
  identification.
- Telemetry state persisted to `toolmesh.json` across restarts;
  overdue sends triggered immediately on startup.

## [0.1.2] - 2026-04-05

### Security

- SSRF hardening: REST `base_url` and redirects validated against
  private/loopback/link-local/metadata ranges at both config load and
  connection time; DNS resolution fails closed.
- Sandbox scanner now walks class bodies, static blocks, and tagged
  template literals.
- OAuth 2.1: `client_id` verified in authorization_code and
  refresh_token grants.
- New `SecurityHeaders` and `PanicRecovery` HTTP middleware; `/mcp`
  enforces JSON content-type and a 10 MB body cap; `clientIP` uses
  rightmost-non-private X-Forwarded-For.
- CORS wildcard matching requires a proper subdomain boundary; blob
  store files written with 0600 and path traversal blocked.
- DADL jq transforms capped at 100k results / 10 MB output; error
  messages truncated at 1 KB.
- Sensitive parameters redacted in debug logs, not only audit records.

### Tests

- `go test -cover ./...` restored from 51.2% to 80.0% with 48 new
  unit-test files. See the v0.1.2 release notes for per-package
  numbers.

## [0.1.1] - 2026-04-04

### Security

- Composite/code-mode sandbox: `Function.prototype.constructor` frozen
  to block prototype-chain bypasses; scanner blocklist extended
  (`constructor`, `__proto__`, `Reflect`, …); `execute_code` runs
  through the same static analysis.
- OAuth 2.1: PKCE (S256) mandatory on all `/authorize` requests;
  `redirect_uri` validated on GET flow; DCR rejects non-HTTPS redirect
  URIs.
- Gate policy VM runs with a 5s timeout under `LockdownRuntime`;
  `RateLimiter.Check` separated from `Record` so policies cannot
  inflate counters.
- `list_tools` results filtered through the OpenFGA authorizer.
- Sensitive params redacted before audit persistence; credential env
  var names no longer leaked in error messages.
- Initial SSRF validation for DADL `base_url`.

### Changed

- REST HTTP client split into default (30s) and streaming (10min)
  variants; per-backend `timeout` / `streaming_timeout` options in
  `backends.yaml`.
- Missing `CREDENTIAL_*` env vars now silently skip the auth header
  instead of aborting, enabling optional-auth APIs (e.g. Semantic
  Scholar).

### Fixed

- PR container images tagged `pr-<N>` are correctly deleted on PR
  close.

## [0.1.0] - 2026-04-02

Initial release.

### Added

#### MCP Server

- Streamable HTTP transports
- Multi-backend aggregation with automatic tool prefixing (`backend_toolname`)
- Fail-closed execution pipeline: AuthZ → Credentials → Gate (pre) → Backend → Gate (post) → Audit
- Configurable timeouts for MCP communication and tool execution
- CORS origin control

#### Code Mode

- `list_tools` and `execute_code` meta-tools for LLM-driven orchestration
- LLMs write JavaScript instead of constructing JSON tool calls
- AST-parsed tool call extraction from code blocks

#### Backend Adapters

- **MCP adapter** — connect to any MCP server via HTTP or STDIO
- **REST adapter (DADL)** — declarative API definitions in YAML
- **Echo adapter** — built-in test backend
- **Composite tool engine** — server-side multi-endpoint orchestration with TypeScript, max 50 API calls per execution

#### DADL (Dunkel API Definition Language)

- YAML-based API descriptions with per-tool definitions
- Authentication strategies: Bearer, OAuth2, Session, API key
- Automatic pagination: cursor, offset, page, and link_header strategies
- Response transformation with JSONPath extraction and jq filters
- Error handling with configurable retry (exponential backoff)
- Per-tool access classification (`read`, `write`, `admin`, `dangerous`, custom)
- File handling with built-in file broker (upload/download)
- Form-encoded body serialization
- `lint-dadl` CLI for security linting of DADL files

#### Pre-built DADL Integrations

- GitHub API
- GitLab API
- Vikunja (task management)
- Shelly Cloud (IoT device control)
- DokuWiki

#### Authentication

- OAuth 2.1 with PKCE S256
- Dynamic Client Registration (DCR) with rate limiting (5/hour per IP)
- API key authentication with bcrypt hashing
- Single-user mode with password/API key fallback
- Redis-persisted OAuth state (survives container restarts)
- Multi-user support via `users.yaml` and `apikeys.yaml`

#### Authorization

- OpenFGA integration with User → Plan → Tool relationship model
- Bypass and restrict modes for development vs. production
- `tm-bootstrap` CLI for OpenFGA store setup and password hashing
- Caller-origin integration (CallerClass-aware policies)

#### Credential Store

- Runtime injection via `CREDENTIAL_*` environment variables
- Secrets never exposed in prompts or tool definitions
- Registry-based extension model (inspired by Go `database/sql` drivers)

#### Output Gate

- Pre- and post-execution JavaScript policies via goja engine
- Seven example policies included: default passthrough, PII protection, role-based field filtering, caller blocking, caller-class enforcement, GitHub branch protection, Shelly write protection

#### Audit

- Pluggable audit stores: slog (write-only) and SQLite (queryable)
- Configurable retention (default: 90 days for SQLite)
- Every tool call logged structurally with trace ID

#### Security

- CallerID spoofing prevention via DCR `client_name`
- Caller-origin tracking (CallerID, CallerName, CallerClass) with `caller-classes.yaml`
- PII filtering with role-based field filtering
- Input validation and sanitization for all tool parameters
- Credential isolation — secrets never exposed in tool responses or logs
- Binary response handling

#### Extension Model

- Registry pattern for Credential Stores, Tool Backends, and Gate Evaluators
- Enterprise extensions via Go build tags (`-tags enterprise`)
- Enterprise credential stores: Infisical, HashiCorp Vault / OpenBao
- Enterprise gate evaluator: Compliance-LLM (LLM-based content classification)

#### Deployment

- Alpine-based multi-stage Docker build with scratch final image
- Multi-platform builds (amd64 + arm64) via buildx
- Docker Compose orchestration with optional services (OpenFGA/MySQL, KeyDB, Caddy)
- Health checks for all services
- Example configuration files (`.env`, `backends.yaml`, `users.yaml`, `apikeys.yaml`, `caller-classes.yaml`, `docker-compose.override.yml`)

#### Logging & Debugging

- Structured logging via slog (JSON and text formats)
- Per-backend debug file logging (`DEBUG_BACKENDS`, `DEBUG_FILE`)
- Configurable log levels
- HTTP request tracing with trace ID propagation

#### Documentation

- Architecture overview with six-pillar model
- Configuration reference for all environment variables
- DADL specification v0.1
- Contributing guidelines, security policy, and code of conduct
