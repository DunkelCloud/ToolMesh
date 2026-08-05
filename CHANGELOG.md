# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries here are kept short; see the corresponding
[GitHub Release](https://github.com/DunkelCloud/ToolMesh/releases)
for the full narrative and details.

## [Unreleased]

### Fixed

- A backend's `hint:` (backends.yaml) is now honored for `transport: rest`.
  It was only ever read for MCP backends, so a hint configured on a REST
  backend was silently dropped — it reached neither the catalog blurb nor
  anything else. As a consequence the first-use notice was delivering the
  DADL's `backend.description` instead of the operator's hint, announcing what
  an API is to a caller who had just chosen a tool from it. `BackendInfo` now
  keeps the two apart: `Description` (what the backend is, from the API
  definition) drives the `execute_code` catalog line as before, while `Hint`
  (what the operator wants known here) drives the first-use notice and nothing
  else. Backends without a configured hint now stay silent.
- Long-running tool calls no longer abort with "The connector's server isn't
  responding." A `tools/call` is now delivered over an MCP Streamable HTTP SSE
  stream when the client accepts one, with a keepalive comment emitted every
  10s while the backend works, so the client's idle timer cannot fire mid-call
  (slow reasoning models, committees, batch evals inside `execute_code`). The
  per-request write deadline is also lifted for tool calls, so the executor and
  `execute_code` timeouts — not the HTTP server's 60s `WriteTimeout` — are the
  real bound. Because the result is streamed the moment the call returns,
  partial `execute_code` results that the buffered path lost when the client
  gave up early are now delivered. Tool-call timeouts surface a specific
  message ("Tool call timed out before the backend responded") instead of a
  generic "Internal error".

### Added

- A backend's `hint:` (backends.yaml) is now delivered with the first tool call
  each caller makes into that backend, in addition to the `execute_code` tool
  description. That description carries every backend's hint at once, so on a
  large mesh it grows long enough for clients to truncate it and the hints past
  the cut are never seen. Attaching the hint to the call delivers it in full, at
  the moment it is relevant, to whoever is actually using the backend. On a
  direct call the note arrives as its own content block ahead of the payload;
  inside `execute_code` it rides beside the result as `notice` (never merged
  into it — the script consumes the result as data). Delivery is per caller and
  best-effort: a missed or repeated note costs a few tokens and nothing else.
- `execute_code`'s wall-clock budget is configurable via `TOOLMESH_CODE_TIMEOUT`
  (seconds, default 120), so an orchestration of several slow backend calls is
  not capped below the backends' own timeouts.
- `include_tools` backends.yaml option restricts a backend's exposed surface to
  exactly the named tools/composites — everything else disappears from
  `discover_tools`, `execute_code`, and direct calls. Lets a broad shared DADL
  (e.g. `openai.dadl`) be pointed at a chat-only endpoint (Ollama, vLLM) while
  advertising only chat/embeddings, keeping the catalog small and preventing the
  LLM from picking an unimplemented endpoint. Honored for every transport: MCP
  backends (`http`, `stdio`) apply the allow-list to the upstream `tools/list`
  result and enforce it again on execution, so an MCP server's housekeeping
  tools can be kept off the agent's surface. Entries that match no upstream
  tool, and `expose_tools` entries the allow-list excludes, are reported in the
  log on connect.
- Progressive discovery for large tool catalogs. `discover_tools` now
  auto-scales its output with the number of matches (≤25 full TypeScript
  signatures, ≤250 one-line summaries, ≤2000 names only, above that a
  per-backend overview), supports BM25-ranked free-text search via the new
  `query` parameter (top 25 by default), accepts explicit `detail` and
  `limit` overrides, always appends a matched/shown footer with refine
  hints, and hard-caps every response at 50 KB. Previously a broad pattern
  like `netbox` returned ~320 KB of full declarations on a large instance.
- In-sandbox discovery for Code Mode: `toolmesh.discover("<free text>",
  limit?)` returns ranked `{name, description, backend}` matches and
  `toolmesh.describe("<tool_name>")` returns the full parameter schema —
  both run locally against the descriptor index, do not count toward the
  per-execution tool-call budget, and respect per-user authorization.
- New dependency-free `internal/toolindex` package: in-memory BM25 index
  over tool names, descriptions, and parameter names.
- DADL spec §6.2 file handling in the REST transport. Parameters declared
  `type: file_url, in: body` are fetched from the caller-provided URL
  (`http`/`https`, or `file` inside the allowed upload directory) and sent to
  the backend as the raw streamed request body — or as a multipart/form-data
  file part when the tool declares `content_type: multipart/form-data`
  (e.g. DeepL document upload). Tools declaring `response: {type: file_url,
  ttl: ...}` store binary responses in the file broker / blob store and
  return a download URL honoring the per-tool TTL, instead of inlining raw
  bytes as text. File fetches use a dedicated HTTP client that never carries
  the backend's cookies, credentials, or relaxed TLS settings, and are
  capped at 100 MB.

### Changed (BREAKING)

- `backends.yaml` is now parsed strictly: a key that no backend field claims
  aborts startup with the offending line instead of being silently dropped.
  Lenient parsing let a misspelled or invented option (e.g. `tools_filter`)
  vanish without a trace, leaving an operator convinced a restriction was in
  force while the backend exposed its full tool surface. Operators must remove
  or correct unknown keys before upgrading; a hot-reload that hits one keeps
  the previous backends running and logs the error rather than taking the
  server down. Empty or fully commented-out files still mean "no backends".
- The `list_tools` MCP meta-tool was renamed to `discover_tools`. There is no
  backwards-compatible alias — clients that hard-code the old name must be
  updated. The rename is harness-stable: clients that sort tool listings
  alphabetically now show `discover_tools` before `execute_code`, matching the
  intended discover-then-execute workflow. Affected: tool name, the `tool`
  label on `toolmesh_tool_calls_total` / `toolmesh_tool_call_duration_seconds`,
  and the structured-log message key when discovery is invoked.
- The `discover_tools` description shrank from a few thousand tokens (it
  duplicated the per-backend hint block) to under 100 tokens. The hint block
  remains on `execute_code`, which is the tool LLMs reach for when they want
  the discovery surface in front of them.
- Backend instances that share a DADL spec are now collapsed into a single
  hint line in the `execute_code` description (e.g.
  `dokuwiki-prod, dokuwiki-staging: DokuWiki JSON-RPC API` instead of two
  identical lines). Native backends without a DADL spec continue to render
  individually.

### Security

- Sandbox lockdown: the goja `LockdownRuntime` now clears the `constructor`
  reference on the intrinsic prototypes before the `eval`/`Function` stubs are
  installed. The previous order left `Function.prototype` shadowed, so the
  prototype-chain route to the Function constructor
  (`(function(){}).constructor('code')()`) stayed reachable in the composite,
  code-mode, unit, and gate runtimes.
- Static scanner: `ScanCode` now flags blocklisted property names in member
  access — both dot (`obj.constructor`) and string-literal bracket
  (`obj["constructor"]`) forms — not only bare identifiers.
- Composite child calls (`api.*`) are now authorized and pre-gated with the
  same OpenFGA check and pre-execution gate as a direct call to the same tool,
  fail-closed. Previously a composite could invoke a sibling tool the caller
  was not authorized for or that a gate policy would have blocked.
- `LOG_LEVEL` now defaults to `info` instead of `debug`. Debug-level logging
  intentionally includes full request URLs (which contain query-string API
  keys for `auth.inject_into: query` backends), so it is no longer the default.
- Caller-supplied `file_url` fetches are now governed by a dedicated
  `allow_private_file_url` option (default `false`) instead of inheriting the
  admin `allow_private_url` flag, plus an optional `file_url_allowed_hosts`
  allowlist. This closes an SSRF path to internal/metadata endpoints from the
  default configuration. `IsPrivateIP` also now rejects the unspecified address
  (`0.0.0.0`/`::`), and failed fetches no longer echo the upstream response
  body.
- goja runtimes get a soft heap limit via `TOOLMESH_MEM_LIMIT_BYTES` /
  `GOMEMLIMIT` plus a per-runtime call-stack cap, and `docker-compose.yml` sets
  `mem_limit` + `restart`, so a runaway sandbox allocation is contained to a
  restartable container instead of OOM-killing the host.
- `.mcpregistry_*` publisher credential files are now git-ignored and a
  `gitleaks` job runs in CI.

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
