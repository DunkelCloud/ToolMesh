# DADL — Dunkel API Description Language

**Specification Draft v0.2**

A **declarative YAML format** for describing REST APIs as [ToolMesh](https://toolmesh.io) backends.
Write a `.dadl` file — ToolMesh handles the rest.

| | |
|---|---|
| Version | 0.2.0-draft |
| Date | 2026-07-30 |
| Author | Dunkel Cloud GmbH |
| License | [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) |

**Changes from v0.1** (additive — every valid v0.1 file is a valid v0.2 file):

- Section 5.3: new `flow: refresh_token` for `auth.type: oauth2` (user-delegated APIs such as Google or Microsoft Graph), with the new field `refresh_token_credential`. Files using this flow MUST declare spec v0.2.
- Section 5.3: two more `oauth2` flows — `jwt_bearer` (service accounts, RFC 7523; e.g. Google Search Console and Workspace APIs) and `authorization_code` (three-legged consent driven by `toolmesh setup`, refresh token persisted in the credential store; e.g. YouTube).
- Section 4: documented `defaults.content_type` (backend-wide default request content type; implemented since v0.1 but previously undocumented).
- Section 5.5: corrected the API-key auth type to its implemented spelling `apikey` (the v0.1 document said `api_key`, which ToolMesh has never accepted; the canonical schema accepts both) and documented `query_param` for `inject_into: query` (implemented since v0.1 but previously undocumented).
- Section 4: corrected `base_url` to optional (the v0.1 document said required; the runtime has always treated it as optional — self-hosted APIs get their URL from the deployment's `backends.yaml`).
- Section 6: normative override semantics — a tool-level `response`, `errors`, or `pagination` object replaces the corresponding `defaults` object; `response.redact` is the deliberate exception and merges additively.
- Section 11.1: YAML merge keys (`<<`) are now discouraged (shallow-merge data loss, dropped from YAML 1.2, rejected by the public registry); examples use whole-node anchors.
- Section 12.3: composites can carry an `access` classification, mirroring tools (Section 6.4); the composite is the authorization boundary for its inner calls.
- Section 4.6: optional `health` declaration (absent = no check, nothing runs). Two forms: reference a declared tool or an inline endpoint. A declared check is exposed as a synthetic `health` tool returning a standardized result — including an optional `auth_expires_at` (from `auth_expires_path` or deployment metadata) for proactive credential-expiry warnings. For `toolmesh setup`, monitoring, and LLM self-diagnosis.
- Section 6: new per-tool fields `returns` (typed results, Section 6.5), `idempotency` (safe write retries, Section 6.6), and `deprecated` / `replaced_by` (migration paths, Section 6.7).
- Section 8.2: new `errors.map` — HTTP status codes are mapped to semantic error codes (`not_found`, `conflict`, `rate_limited`, …) so Code Mode error handling can branch on stable values.
- Section 9.3: new `response.redact` — declarative masking of sensitive response fields via JSONPath list, complementing the Output Gate.
- Section 3: new optional top-level `requires` block — minimum runtime version and feature requirements (fail-closed).
- Section 15: new Conformance chapter — canonical JSON Schema, document/consumer conformance, unknown-key policy, unknown-value policy for behavior-determining enums, `requires` bootstrap limitation.
- Section 16: non-normative outlook on v0.3 (session semantics for LLM backends).
- Section 6: documented `HEAD` as a supported HTTP method (implemented since v0.1 but previously undocumented).
- Section 5.3: PKCE (RFC 7636, S256) specified for public `authorization_code` clients; RFC 7523 `sub`-claim note for `jwt_bearer`.
- Section 8: the error-mapping trigger (non-2xx) and the default for unlisted statuses are now explicit; catch-all codes `client_error` / `server_error` / `unexpected_status`; automatic retries MUST NOT re-execute non-idempotent calls (new opt-in `retry_unsafe`).
- Section 9.4: the DADL JSONPath dialect is pinned — RFC 9535 syntax and semantics for name, index, and wildcard selectors.
- Section 5.3: refresh-token rotation supported via `rotates_refresh_token` (atomic persistence rules; feature identifier `refresh_token_rotation`); declarative `authorization_params`, `redirect_uri`, and `token_auth` replace provider-specific behavior.
- Section 12.3: composite authorization is fail-closed by default (inner calls re-checked against the caller); deliberate encapsulation requires declared `delegates` plus deployment-policy approval.
- Sections 6.2 / 9.1 / 15.2: consumer security requirements for `file_url` fetching (SSRF hardening), ad-hoc jq sandbox limits, and the registry publication profile (mandatory `access`).
- Section 15.4: consumer conformance restructured into three profiles (Document Validator, Core Runtime, Full Runtime).

**Compatibility notes** (why the additivity claim above holds, item by item):

| Topic | Status |
|---|---|
| `auth.type: api_key` (v0.1 spelling) | Runtimes and validators MUST accept it as an alias for `apikey` (Section 5.5). |
| YAML merge keys (`<<`, shown in v0.1 §11.1) | Merge keys are resolved by the YAML parser before validation — document conformance is unaffected. The public registry's rejection of `<<` is pre-existing CI policy, not a v0.2 conformance rule; Section 11.1 now documents the shallow-merge pitfall that motivated it. |
| Hint values (v0.1: "key-value pairs") | v0.2 pins values to scalars. This documents long-standing validation practice (the registry schema always required scalar values) and is a *relaxation* of that practice (numbers and booleans are now accepted alongside strings). |
| Tool-level `response`/`errors`/`pagination` overrides | The replace-not-merge semantics in Section 6 document behavior ToolMesh has always implemented; v0.2 adds the `redact` additive exception on top. No existing file changes behavior. |

---

## 1 Overview

**DADL** (Dunkel API Description Language) is a declarative YAML format that describes REST APIs for consumption by **ToolMesh** — a secure execution layer between AI agents and enterprise infrastructure.

Instead of building a dedicated MCP server for each REST API, you write a `.dadl` file. ToolMesh reads it, generates TypeScript interfaces, and exposes the API via **Code Mode** — two tools (`search` + `execute`) that give any AI agent access to the entire API in roughly 1,000 tokens.

```
# Without DADL
Claude → ToolMesh → custom Go/TS MCP Server → REST API

# With DADL
Claude → ToolMesh → REST API  (via declarative .dadl file)
```

> **Code Mode only.** DADL backends are always exposed via Code Mode. The LLM writes JavaScript against auto-generated TypeScript interfaces. No tool-per-endpoint explosion — regardless of API size.

Normative keywords (MUST, SHOULD, MAY, …) are used throughout this document as defined in Section 15.1.

This document mixes three concerns, marked as such where they appear: the **portable DADL document format** (normative for every consumer), **ToolMesh runtime behavior** (normative for ToolMesh; other consumers implement the equivalent contract), and **registry/deployment policy** (publication profiles and operator configuration — explicitly outside the document format). A future revision may split these into separate profiles.

---

## 2 Design Principles

**Describe the API, not the agent behavior.** DADL declares what endpoints exist and how to authenticate. ToolMesh decides how to present them to the LLM (always Code Mode). Temporal handles durability. OpenFGA handles authorization.

- **YAML-native** — every `.dadl` file is valid YAML. Existing editors, linters, and parsers work out of the box.
- **Code Mode only** — no tool-grouping syntax, no scope-exposure mechanics. The LLM writes code against TypeScript interfaces.
- **OpenAPI-compatible** — optional `openapi_source` field uses an existing OpenAPI spec for schemas. DADL adds only what OpenAPI lacks: credential injection, pagination strategy, response transformation.
- **No templating** — no variables, no conditionals, no loops. DADL is declarative, not generative.
- **No workflow syntax** — multi-step orchestration happens in Code Mode (the LLM writes sequential code) and Temporal (durability, retry, audit).

---

## 3 File Structure

A DADL file has the extension `.dadl` and is a YAML document with the following top-level fields:

| Field | Type | Required | Description |
|---|---|---|---|
| `spec` | string | yes | URL of the DADL specification this file conforms to. Currently `"https://dadl.ai/spec/dadl-spec-v0.2.md"` (files not using v0.2 features may keep declaring v0.1) |
| `requires` | object | no | Minimum runtime requirements (`toolmesh` semver range, `features` list). A runtime that cannot satisfy them MUST refuse to load the file. See Section 15.3. |
| `credits` | array of strings | no | Free-form list of contributors, maintainers, and sponsors. Each entry is a plain string — conventions emerge from usage (e.g. `"Jane Doe (@janedoe)"`, `"Acme Corp — sponsor"`). |
| `source_name` | string | no | Name of the source API being described (e.g. `"GitHub REST API"`) |
| `source_url` | string | no | URL to the original API specification or documentation |
| `date` | string | no | Creation or last-modified date of this file (`YYYY-MM-DD`) |
| `backend` | object | yes | The backend definition |
| `includes` | array | no | Reusable fragments to merge in |
| `_*` | any | no | Underscore-prefixed keys are ignored by ToolMesh (used for YAML anchors) |

```yaml
# minimal.dadl
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
credits:                                      # optional
  - "Jane Doe (@janedoe)"
  - "Acme Corp — verifies against production"
source_name: "Example REST API"              # optional
source_url: https://docs.example.com/api     # optional
date: "2026-03-26"                            # optional

backend:
  name: my-api
  type: rest
  version: "1.0"
  base_url: https://api.example.com/v1
  description: "My REST API"

  auth:
    type: bearer
    credential: vault/my-api-token

  tools:
    list_items:
      method: GET
      path: /items
      access: read
      description: "List all items"
```

---

## 4 Backend Object

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique backend identifier (slug format: lowercase, hyphens) |
| `type` | string | yes | Always `rest` for DADL backends |
| `version` | string | no | Semantic version of this DADL file (e.g. `"1.0"`, `"1.2.1"`). Used by ToolMesh to detect available upgrades from the registry. See Section 4.5. |
| `base_url` | string | no | Base URL for all API requests. Omit for self-hosted APIs (BookStack, NetBox, GitLab, …) where every installation has its own URL — the deployment's `backends.yaml` `url:` entry supplies it, and always overrides a declared `base_url`. *(corrected in v0.2: the v0.1 document said required; the runtime has always treated it as optional)* |
| `description` | string | yes | Human-readable description (used in Code Mode prompt) |
| `openapi_source` | string | no | Path or URL to OpenAPI 3.x spec. When provided, schemas and parameters are derived from it. |
| `arazzo_source` | string | no | Path or URL to Arazzo workflow file. Used as documentation context for Code Mode, not executed. |
| `auth` | object | yes | Authentication configuration |
| `defaults` | object | no | Default headers, pagination, error, and response config for all tools. Supports `headers` (map of default HTTP headers), `content_type` (default request-body content type; per-tool `content_type` overrides it), `pagination`, `errors`, and `response`. `content_type` governs body encoding *and* the `Content-Type` header — do not additionally set `defaults.headers.Content-Type`; when both are present, `content_type` wins. |
| `types` | object | no | Type definitions (JSON Schema subset). Only needed without `openapi_source`. |
| `tools` | object | yes | Map of tool definitions |
| `examples` | array | no | Code examples for multi-step workflows (few-shot prompts for the LLM). See Section 4.4. |
| `coverage` | object | no | API coverage metadata. Helps LLMs understand scope and users assess fitness. |
| `hints` | object | no | Per-tool domain knowledge for LLM consumers (structured key-value). Injected into tool descriptions at load time. Subject to security scanning. |
| `setup` | object | no | Human-readable setup instructions. Describes how to obtain credentials, configure backends.yaml, and required permissions. Powers `toolmesh setup <name>` CLI. |
| `health` | object | no | Health-check declaration: which cheap, side-effect-free call verifies this backend (a declared tool or an inline endpoint). Absent = no check. See Section 4.6. |

### 4.1 Coverage Object

Optional metadata describing how much of the target API this DADL file covers. Useful for discovery, community contributions, and LLM decision-making.

| Field | Type | Required | Description |
|---|---|---|---|
| `endpoints` | integer | no | Number of tools defined in this DADL file |
| `total_endpoints` | integer | no | Estimated total number of REST endpoints in the target API |
| `percentage` | integer | no | Approximate coverage percentage (0–100) |
| `focus` | string | no | Comma-separated list of covered API areas (e.g. "repos, issues, PRs, search") |
| `missing` | string | no | Notable uncovered API areas (e.g. "webhooks, teams, code scanning") |
| `last_reviewed` | string | no | ISO 8601 date when coverage was last verified (e.g. "2026-03-26") |

### 4.2 Hints Object

Structured domain knowledge that is injected into tool descriptions at load time. Helps LLMs use tools correctly without trial and error. Hints are per-tool and use key-value pairs rather than free text to reduce prompt injection surface. Hint values are scalars (strings, numbers, booleans) — nested objects or arrays are not allowed.

**Security:** Hint values are subject to automated security scanning. DADL files from untrusted sources (community registries) are scanned for imperative instructions, URLs, shell commands, and authority claims. Suspicious content is rejected or flagged.

| Field | Type | Required | Description |
|---|---|---|---|
| `<tool_name>` | object | no | Map of hint key-value pairs for a specific tool |

```yaml
# Example: coverage and hints
backend:
  name: github
  coverage:
    endpoints: 24
    total_endpoints: 900
    percentage: 3
    focus: "repos, issues, PRs, commits, search, releases, actions"
    missing: "git primitives, projects v2, teams, webhooks, code scanning"
    last_reviewed: "2026-03-26"

  hints:
    list_project_tasks:
      position_type: float64
      requires: "call list_views first to get view_id"
      kanban_note: "kanban views return buckets with nested tasks, not a flat list"
```

### 4.3 Setup Object

Human-readable instructions for setting up this DADL backend. Intended for operators, not LLMs. Powers the `toolmesh setup <name>` CLI command that guides users through credential creation and configuration.

| Field | Type | Required | Description |
|---|---|---|---|
| `credential_steps` | array of string | no | Step-by-step instructions to obtain the required credential (API key, PAT, etc.) |
| `env_var` | string | no | Name of the environment variable to set in `.env` |
| `backends_yaml` | string | no | Example `backends.yaml` entry (multiline YAML string) |
| `required_scopes` | array of string | no | API scopes or permissions needed for full functionality |
| `optional_scopes` | array of string | no | Additional scopes for extended features (read-only alternatives, etc.) |
| `docs_url` | string | no | Link to the API provider's credential/authentication documentation |
| `notes` | string | no | Additional setup notes (e.g. self-hosted URL patterns, regional endpoints) |

```yaml
# Example: setup
setup:
  credential_steps:
    - "Navigate to GitLab → Settings → Access Tokens"
    - "Create a token with scope: api (full access) or read_api (read-only)"
    - "Copy the token (starts with glpat-)"
  env_var: CREDENTIAL_GITLAB_TOKEN
  backends_yaml: |
    - name: gitlab
      transport: rest
      dadl: /app/dadl/gitlab.dadl
      url: "https://your-gitlab.example.com/api/v4"
  required_scopes:
    - api
  optional_scopes:
    - read_api
  docs_url: "https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"
  notes: "For self-hosted GitLab, replace the URL with your instance. The token prefix glpat- is for personal access tokens."
```

### 4.4 Examples Array

Code examples that serve as few-shot prompts for the LLM in Code Mode. Each example demonstrates a multi-step workflow using `api.*` calls, helping the LLM understand common patterns for this backend.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Short name for the example (e.g. `"Customer onboarding"`) |
| `description` | string | yes | What the example demonstrates |
| `code` | string | yes | JavaScript/TypeScript code using `api.*` calls. Same sandbox as composite tools. |

```yaml
# examples
examples:
  - name: "Customer onboarding"
    description: "Create a customer and retrieve their details"
    code: |
      const customer = await api.create_customer({
        email: "jane@example.com",
        name: "Jane Doe"
      });
      const details = await api.get_customer({ id: customer.id });
      return details;
```

### 4.5 Version

Optional semantic version string for the DADL file. Enables ToolMesh to detect when a newer version is available in the registry.

```yaml
backend:
  name: github
  version: "1.2"
  # ...
```

**Format:** SemVer-compatible shorthand — `MAJOR.MINOR` or `MAJOR.MINOR.PATCH` (`"1.2"`, `"1.2.1"`). Strict [Semantic Versioning](https://semver.org/) requires three components; DADL additionally permits the two-component form, which consumers compare as if `.0` were appended (`"1.2"` ≡ `"1.2.0"`).

**Semantics:**

| Change | Version bump | Example |
|--------|-------------|---------|
| New tools added | Minor | `1.1` → `1.2` |
| Bug fix in transform/pagination | Patch | `1.2.0` → `1.2.1` |
| Tool renamed or removed, breaking param change | Major | `1.2` → `2.0` |

**Registry integration:** The DADL registry (`dadl.ai`) publishes a manifest with the latest version and checksum for each DADL file. ToolMesh compares the local `version` against the manifest at startup and logs a notice when an upgrade is available. No automatic updates — the operator decides when to upgrade.

**When `version` is omitted:** ToolMesh skips the upgrade check for this backend. This is expected for private/local DADL files that are not published to the registry.

### 4.6 Health Check *(since v0.2)*

Optional backend-level declaration of the cheapest call that verifies the backend is reachable and the configured credential works. Authentication is injected exactly as for regular tools — a passing health check therefore validates connectivity **and** the credential in one request (an expired token turns into a visible failure here instead of a surprise `401` on the next real call). When `health` is absent, no check exists and nothing runs — fully backward compatible.

Two forms:

```yaml
# health — form 1: reference a declared tool
backend:
  health:
    tool: get_health       # existing tool in this file; MUST have no required params

# health — form 2: inline endpoint (when no tool is worth declaring for it)
backend:
  health:
    method: GET            # default: GET
    path: /status
    expect_status: 200     # optional — default: any 2xx
    timeout: 5s            # default: 5s
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `tool` | string | form 1: yes | Name of a declared tool to use as the check. The tool MUST NOT have required parameters. Mutually exclusive with `method`/`path`. |
| `method` | string | no | HTTP method (form 2). Default: `GET`. |
| `path` | string | form 2: yes | URL path relative to `base_url`. Must not contain `{param}` placeholders. |
| `expect_status` | integer | no | Exact expected status code. Default: any `2xx` passes. |
| `expect_path` | string | no | JSONPath that must exist in the response body (e.g. `"$.status"`). |
| `auth_expires_path` | string | no | JSONPath extracting the credential-expiry timestamp from the check response (e.g. GitLab `GET /personal_access_tokens/self` → `"$.expires_at"`). See `auth_expires_at` below. |
| `timeout` | string | no | Request timeout. Default: `5s`. |
| `expose` | boolean | no | Expose the check as a synthetic `health` tool in the generated interface. Default: `true`. |

**The synthetic `health` tool.** When a check is declared (either form) and `expose` is not `false`, ToolMesh adds a tool named `health` to the generated TypeScript interface. It returns the **standardized result** — never the raw API response:

```typescript
health(): Promise<{
  ok: boolean;              // check passed (status/expect rules)
  http_status?: number;     // raw HTTP status — absent when no response was received
  error_code?: string;      // transport failure: dns_error | tls_error | connection_refused | timeout | protocol_error
  latency_ms: number;
  checked_at: string;       // ISO 8601
  auth_expires_at?: string; // ISO 8601 — when the backend credential expires, if known
  error?: string;           // present when ok is false (mapped per Section 8.2 for HTTP errors)
}>
```

Semantics: `api.health()` **never rejects** — every outcome, including transport failures, is delivered as a result object (that is the point: LLM code branches on `ok`, not on exceptions). When no HTTP response was received, `http_status` is absent and `error_code` names the transport failure. `expect_path` asserts **existence** of the path in the response body — the value itself is not inspected. `expect_path` and `auth_expires_path` are evaluated against the **raw** response body of the check call, for both forms — a referenced tool's `response` pipeline (Section 9) does not apply to the check.

`auth_expires_at` turns the check from reactive (credential *is* expired → `ok: false`) into proactive (credential *will* expire). It is filled from two sources, in order of precedence:

1. **The check response**, when the DADL declares `auth_expires_path` — the API's own answer is authoritative. Runtimes SHOULD accept common timestamp formats (RFC 3339 / ISO 8601, Unix epoch) at that path and normalize to ISO 8601.
2. **Deployment metadata** — an operator-supplied expiry recorded next to the credential (`backends.yaml` / credential store), for APIs whose cheap check endpoint does not report it (e.g. a Tailscale API key: fixed 90-day lifetime, expiry known at creation time). Configuration syntax is deployment-specific, not part of the DADL.

When neither source yields a value, the field is absent. Monitoring consumers MAY raise a warning state once `auth_expires_at` falls within a configurable window (e.g. 7 days) — turning "surprise 401 in October" into a scheduled credential rotation.

The standardized shape is produced by the check layer, not by the API: with form 1, calling the referenced tool directly still returns its raw API response — only the synthetic `health` tool normalizes. This lets LLM-written code self-diagnose identically across backends (`if (!(await api.health()).ok) …` — distinguishing "backend or credential broken" from "my parameters are wrong") without leaking payload internals.

- **Name collision:** if the file declares its own tool or composite named `health`, the declared one wins and no synthetic tool is generated; validators warn. This is safe: the generated interface always shows the declared tool's real signature and JSDoc, so LLM code is written against what is actually there — and the synthetic tool, where it exists, is marked as such in its JSDoc ("standardized backend health check"). Referencing the declared tool via `health.tool: health` (with `expose: false`) still enables the check for setup and monitoring.
- **Discovery:** the synthetic tool exists on every backend that declares a check, so it MUST NOT be ranked in tool-discovery indexes — it is always reachable as `api.health()` and would only add noise.

**Consumers:**

- `toolmesh setup <name>` runs the health check after credential entry and reports success or the mapped error (Section 8.2) — the operator learns immediately whether the token works.
- ToolMesh MAY run the check at startup and MAY poll it periodically, aggregating results (e.g. a `degraded` state naming the failing backend) into its own monitoring endpoints. Whether and how often it polls is **deployment configuration** (`backends.yaml`), not part of the DADL. It MUST NOT run the check per tool call.

**Authoring rules:** the health endpoint MUST be side-effect-free (`read` semantics) and SHOULD be the cheapest such endpoint the API offers (e.g. Stripe `GET /balance`, GitHub `GET /rate_limit`) — not a list endpoint returning large payloads. Every DADL whose API offers a suitable endpoint SHOULD declare `health`.

---

## 5 Authentication

DADL supports five authentication patterns. Credentials are referenced by logical name and resolved at runtime by ToolMesh's three-tier Credential Store (Embedded → Infisical → Vault/OpenBao). **The LLM never sees credentials.**

### 5.1 Bearer Token

```yaml
# auth — bearer
auth:
  type: bearer
  credential: vault/stripe-secret-key
  inject_into: header          # default
  header_name: Authorization   # default
  prefix: "Bearer "             # default
```

### 5.2 Basic Authentication

```yaml
# auth — basic
auth:
  type: basic
  username_credential: vault/bitdefender-api-key
  password_credential: vault/bitdefender-password  # optional, default: ""
```

ToolMesh builds the `Authorization: Basic base64(username:password)` header automatically. If `password_credential` is omitted, an empty password is used — this is common for APIs that use an API key as the username (e.g. Bitdefender GravityZone, many JSON-RPC APIs).

### 5.3 OAuth 2.0

Four flows are supported via the `flow` field (default: `client_credentials`). For all of them, ToolMesh caches the access token in memory and renews it lazily: a request that finds the cached token within `refresh_before_expiry` of its expiry fetches a fresh one first. On a 401 the cache is invalidated and the request retried once with a new token. **The LLM never sees tokens** — acquisition, refresh, and injection happen entirely inside ToolMesh; tokens MUST NOT appear in logs, audit payloads, or workflow history.

Protocol details common to all flows: token requests and responses follow [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) (`access_token`, `token_type`, `expires_in`; scopes are space-separated). Client authentication on the token request is controlled by `token_auth`: `post` (credentials in the form body — default, matching the implemented behavior) or `basic` (HTTP Basic per RFC 6749 §2.3.1).

| Flow | Use case | Interactive consent |
|------|----------|---------------------|
| `client_credentials` | Machine-to-machine APIs | none |
| `refresh_token` *(v0.2)* | User-delegated APIs, refresh token obtained out-of-band | out-of-band, before deployment |
| `jwt_bearer` *(v0.2)* | Service accounts (RFC 7523) — Google Search Console, Workspace | none |
| `authorization_code` *(v0.2)* | User-delegated APIs without service-account support — YouTube | once, via `toolmesh setup` |

`client_credentials` — machine-to-machine APIs:

```yaml
# auth — oauth2 (machine-to-machine)
auth:
  type: oauth2
  flow: client_credentials
  token_url: https://api.example.com/oauth/token
  client_id_credential: vault/example-client-id
  client_secret_credential: vault/example-client-secret
  scopes: ["read", "write"]
  token_cache_key: example-api-token
  refresh_before_expiry: 60s
```

`refresh_token` *(since v0.2)* — user-delegated APIs (Google, Microsoft Graph, …) where a long-lived refresh token is exchanged for short-lived access tokens at runtime. Files using this flow MUST declare spec v0.2:

```yaml
# auth — oauth2 (user-delegated)
auth:
  type: oauth2
  flow: refresh_token
  token_url: https://oauth2.googleapis.com/token
  client_id_credential: vault/google-client-id
  client_secret_credential: vault/google-client-secret  # optional — omit for public (PKCE) clients
  refresh_token_credential: vault/google-refresh-token
  refresh_before_expiry: 60s
```

The interactive consent that produces the refresh token happens once, out-of-band — describe it in the `setup` section (for Google: OAuth client in production status, consent URL with `access_type=offline&prompt=consent`). `scopes` is not sent on this flow; scopes are fixed at consent time (declaring `scopes` anyway is not an error — the field is simply ignored).

**Refresh-token rotation.** Providers that issue a new refresh token on every exchange (common for public clients and modern OAuth security profiles) are supported via the declaration `rotates_refresh_token: true`. Files using a rotating provider MUST declare it — and MUST list the feature identifier `refresh_token_rotation` in `requires.features` (Section 15.3), because a runtime that silently ignored the declaration would lose the credential after the first refresh. Normative runtime behavior when the declaration is present:

- a newly issued refresh token **replaces** the stored one atomically; when the response carries no new refresh token, the stored one is kept;
- persistence failure fails the refresh (fail-closed) — the runtime MUST NOT continue with a possibly-invalidated old token;
- concurrent refreshes for the same credential are serialized or resolved by compare-and-swap;
- a runtime whose credential store cannot write (e.g. an environment-variable store) MUST refuse to load the file.

Without the declaration, the stored refresh token is treated as stable (Google does not rotate by default).

`jwt_bearer` *(since v0.2)* — service-account APIs per [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523): ToolMesh builds an RS256-signed JWT from a service-account key and exchanges it at the token endpoint for a short-lived access token. Fully headless — no consent screen, no refresh token. This is the preferred flow for Google APIs that support service accounts (Search Console: add the service-account email as a property user; Workspace APIs: domain-wide delegation). Files using this flow MUST declare spec v0.2:

```yaml
# auth — oauth2 (service account, JWT bearer)
auth:
  type: oauth2
  flow: jwt_bearer
  token_url: https://oauth2.googleapis.com/token
  service_account_credential: vault/gsc-service-account
  scopes: ["https://www.googleapis.com/auth/webmasters.readonly"]
  subject: admin@example.com     # optional — domain-wide delegation
  refresh_before_expiry: 60s
```

`service_account_credential` resolves to the **complete service-account key** (for Google: the JSON key file content with `client_email`, `private_key`, `token_uri`). A declared `token_url` takes precedence; when absent, the key's own `token_uri` is used. ToolMesh signs the assertion (`iss` = client email, `aud` = token URL, `scope` from `scopes`, `exp` ≤ 1 hour) and caches the resulting access token like any other flow. The optional `subject` sets the `sub` claim to impersonate a user — required for Google Workspace domain-wide delegation, omitted for APIs where the service account acts as itself. (RFC 7523 note: the RFC itself requires a `sub` claim; omitting it for self-acting service accounts follows Google's token-endpoint profile. Strictly RFC-conforming endpoints expect `sub` = `iss` — runtimes SHOULD send that when `subject` is absent and the endpoint rejects assertions without `sub`.)

`authorization_code` *(since v0.2)* — three-legged OAuth for user-delegated APIs that do **not** support service accounts (e.g. YouTube). Unlike `flow: refresh_token`, where the refresh token is obtained out-of-band, this flow declares the full consent configuration so ToolMesh can drive it: `toolmesh setup <name>` (or the identity plugin) opens `authorize_url` in a browser, receives the authorization code on a local callback, exchanges it at `token_url`, and **persists the refresh token** in the credential store under `refresh_token_credential`. At runtime the flow then behaves exactly like `refresh_token` — silent renewal, no user interaction. Files using this flow MUST declare spec v0.2:

```yaml
# auth — oauth2 (three-legged, consent driven by toolmesh setup)
auth:
  type: oauth2
  flow: authorization_code
  authorize_url: https://accounts.google.com/o/oauth2/v2/auth
  token_url: https://oauth2.googleapis.com/token
  client_id_credential: vault/youtube-client-id
  client_secret_credential: vault/youtube-client-secret  # optional — omit for public (PKCE) clients
  refresh_token_credential: vault/youtube-refresh-token
  scopes: ["https://www.googleapis.com/auth/youtube"]
  authorization_params:            # provider-specific extras, appended to the authorize request
    access_type: offline           # Google: required for a refresh token
    prompt: consent
  refresh_before_expiry: 60s
```

`scopes` is sent during consent and fixed afterwards. Provider-specific authorize-request parameters are declared in `authorization_params` — a plain string map appended to the authorize URL. There is no host-based provider detection; the DADL says what the provider needs (Google: `access_type=offline&prompt=consent`, without which no refresh token is issued). **PKCE:** public clients (no `client_secret_credential`) MUST use PKCE ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) with the `S256` challenge method — the setup tool generates the verifier, sends the challenge on the authorize request, and the verifier on the token exchange; confidential clients MAY add PKCE on top of the secret. **Redirect:** by default the setup tool uses a loopback redirect per [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252); providers that require an exact pre-registered URI get it declared via the optional `redirect_uri` field. Either way, the effective URI must be registered with the OAuth app. Rotation is handled as declared via `rotates_refresh_token` (see above).

Provider note (belongs in `setup`): Google OAuth apps in *Testing* status expire refresh tokens after 7 days — publish the app to *In production* (or *Internal* for Workspace) before relying on this flow.

### 5.4 Session-based (Login → Token → Use)

```yaml
# auth — session
auth:
  type: session
  login:
    method: POST
    path: /auth/login
    body:
      username_credential: vault/example-username
      password_credential: vault/example-password
    extract:
      token: "$.data.access_token"
      csrf: "$.data.csrf_token"
  inject:
    - header: Authorization
      value: "Bearer {{token}}"
    - header: X-CSRF-Token
      value: "{{csrf}}"
  refresh:
    trigger: status_code_401
    action: re_login
```

### 5.5 API Key

```yaml
# auth — apikey
auth:
  type: apikey
  credential: vault/my-api-key
  inject_into: header          # header | query
  header_name: X-API-Key       # when inject_into: header
  query_param: api_key         # when inject_into: query
```

The canonical type name is `apikey` *(corrected in v0.2: the v0.1 document spelled it `api_key`, which the ToolMesh parser has never accepted — published DADL files use `apikey`)*. Because the v0.1 text declared `api_key` valid, consumers MUST accept it: validators and runtimes MUST treat `api_key` as an alias for `apikey`. New files SHOULD write `apikey`.

With `inject_into: query`, `query_param` names the query parameter that carries the key (e.g. `?api_key=...`); `header_name` is ignored. With `inject_into: header` (the default), `header_name` names the header and `query_param` is ignored.

---

## 6 Tools

Each tool maps to one REST API endpoint. In Code Mode, tools become methods on the auto-generated TypeScript interface that the LLM writes code against.

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | yes | HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD *(HEAD implemented since v0.1, documented in v0.2)* |
| `path` | string | yes | URL path (may contain `{param}` placeholders) |
| `description` | string | yes | Used as JSDoc comment in TypeScript interface |
| `access` | string | no | Access classification for authorization and policy mapping. See Section 6.4. |
| `params` | object | no | Parameter definitions (path, query, header, body). See Section 6.1. |
| `content_type` | string | no | Request content type. Default: `application/json` (or `defaults.content_type` when set). Use `multipart/form-data` for file uploads. |
| `max_body_size` | string | no | Max upload size, e.g. `50MB` |
| `depends_on` | array | no | Informational: other tools that should be called first. Becomes JSDoc hint. |
| `response` | object | no | Response transformation config (overrides `defaults.response`) |
| `pagination` | string\|object | no | `none` to disable, or object to override default pagination |
| `errors` | object | no | Error mapping (overrides `defaults.errors`) |
| `returns` | string\|object | no | Result type for TypeScript generation — a `types` name or an inline schema. See Section 6.5. |
| `idempotency` | object | no | Idempotency-key configuration for safe retries of write calls. See Section 6.6. |
| `retry_unsafe` | boolean | no | Opt-in: allow automatic retries (Section 8) although the call is not idempotent and declares no `idempotency`. Default: `false`. |
| `deprecated` | boolean\|string | no | Marks the tool as deprecated; a string carries the reason. See Section 6.7. |
| `replaced_by` | string | no | Name of the successor tool in this file. See Section 6.7. |

**Override semantics** *(normative since v0.2)*: a tool-level `response`, `errors`, or `pagination` object **replaces** the corresponding `defaults` object as a whole — fields are not merged. A tool that sets only `response.result_path` therefore drops a default `transform`; repeat any default fields the tool still needs. One deliberate exception: `response.redact` is **additive** — the effective redaction list is the union of `defaults.response.redact` and the tool's own `redact`. A tool-level `response` block can extend the default redactions but never remove them (Section 9.3); anything else would let an unrelated override silently disable a security control.

### 6.1 Parameter Definition

All parameters — path, query, and **body** — are defined under the `params` key using `in:` to specify their location. There is no separate `body:` keyword in DADL. `in` is REQUIRED for tool parameters *(made explicit in v0.2)*: a parameter without a location cannot be placed in the request and is silently dropped by the runtime — validators reject it.

```yaml
# params — path, query, and body parameters in one place
params:
  id:
    type: string
    in: path
    required: true
  limit:
    type: integer
    in: query
    default: 10
    description: "Max items to return"
  name:
    type: string
    in: body
    required: true
    description: "Resource name"
  tags:
    type: array
    in: body
    description: "List of tags"
  metadata:
    type: object
    in: body
    description: "Arbitrary key-value metadata"
```

> **Important:** Do NOT use a separate `body:` block with `type: object` / `properties` / `required` (OpenAPI-style). ToolMesh only exposes parameters defined via `params` with `in: body` as tool inputs. A standalone `body:` block will be silently ignored and the tool will appear with zero parameters.

Supported `in:` values:

| Value | Sent as |
|-------|---------|
| `path` | URL path segment (`/items/{id}`) |
| `query` | URL query parameter (`?limit=10`) |
| `header` | HTTP request header (e.g. `X-Custom-Header: value`) |
| `body` | JSON body field (for `application/json`) or form field (for `application/x-www-form-urlencoded`) |

### 6.2 File Handling

Files in DADL are always referenced by **URL** — never as inline data or local file paths. This keeps tool calls lightweight (only a URL string in the context, not megabytes of Base64) and works with any storage backend (S3, MinIO, NextCloud, ToolMesh's built-in file broker).

> **Consumer security requirements** *(normative since v0.2)*: fetching caller-supplied URLs is an SSRF surface. A conforming consumer MUST support restricting fetches to an allowlist (or broker-only mode), MUST block private, loopback, and link-local address ranges by default (including after DNS resolution and after each redirect — re-validate the target, guard against DNS rebinding), MUST disable `file://` by default (same-host deployments may opt in), and MUST enforce size and content-type limits on fetched files.

#### 6.2.1 File Input (`type: file_url`)

When a tool accepts a file, the parameter type is `file_url`. The caller provides a URL, and ToolMesh fetches the file and builds the appropriate request (e.g. multipart/form-data upload) to the backend API.

Supported URL schemes:

- `https://s3.amazonaws.com/bucket/file.pdf` — S3 / MinIO / any HTTP(S) URL
- `https://toolmesh-host/files/f-abc123` — ToolMesh file broker (uploaded via `POST /files/upload`)
- `file:///path/on/host` — local filesystem (only for same-host deployments)

```yaml
# file upload tool — URL-based
convert_pdf:
  method: POST
  path: /api/v1/convert
  description: "Convert a PDF to Markdown"
  content_type: multipart/form-data
  max_body_size: 100MB
  params:
    file: { type: file_url, in: body, required: true }
    title: { type: string, in: body }
```

#### 6.2.2 File Output (`response.type: file_url`)

When a backend returns binary data (PDFs, images, exports), ToolMesh stores the response in its file broker and returns a download URL to the caller. The URL has a configurable TTL and can be shared across sessions.

```yaml
# binary response → file URL
export_report:
  method: GET
  path: /reports/{id}/export
  description: "Export report as PDF"
  params:
    id: { type: string, in: path, required: true }
  response:
    type: file_url
    ttl: 24h
```

#### 6.2.3 ToolMesh File Broker

ToolMesh provides a built-in file broker for uploading and downloading files outside the MCP channel. Files are stored temporarily with a TTL and referenced by ID. This avoids Base64 overhead in tool calls and enables session-independent file handling.

| Endpoint | Method | Description |
|---|---|---|
| `/files/upload` | POST | Upload a file (multipart). Returns `{"file_id": "f-...", "url": "...", "expires": "..."}` |
| `/files/{file_id}` | GET | Download a file by ID |
| `/files/{file_id}` | DELETE | Delete a file before TTL expires |

### 6.3 Binary Download & Streaming

```yaml
# binary & streaming responses
download_report:
  method: GET
  path: /reports/{id}/pdf
  description: "Download report as PDF"
  params:
    id: { type: string, in: path, required: true }
  response:
    binary: true
    content_type: application/pdf

event_stream:
  method: GET
  path: /events
  description: "Stream real-time events"
  response:
    streaming: true
    stream_handling: collect    # collect | skip
    max_duration: 30s
    max_items: 100
```

### 6.4 Access Classification

The optional `access` field classifies each tool by its risk level. This metadata enables policy files and authorization layers (OpenFGA) to group tools into roles without hard-coding tool names. Composites carry the same field with the same semantics (Section 12.3).

**DADL defines access per tool. Policy files define roles from access levels. OpenFGA assigns roles to users.** This three-layer separation keeps DADL portable while enabling fine-grained authorization at deployment time.

```yaml
# access classification
tools:
  list_repos:
    method: GET
    path: /repos
    access: read
    description: "List repositories"

  create_repo:
    method: POST
    path: /user/repos
    access: write
    description: "Create a repository"

  update_branch_protection:
    method: PUT
    path: /repos/{owner}/{repo}/branches/{branch}/protection
    access: admin
    description: "Update branch protection rules"

  delete_repo:
    method: DELETE
    path: /repos/{owner}/{repo}
    access: dangerous
    description: "Delete a repository"
```

#### Well-Known Values

The following values are well-known and understood by ToolMesh's built-in policy engine:

| Value | Typical Use | HTTP Methods |
|-------|-------------|--------------|
| `read` | Read-only operations, listing, searching | GET, HEAD |
| `write` | Create or update resources | POST, PUT, PATCH |
| `admin` | Privileged operations (permissions, settings, configuration) | Any |
| `dangerous` | Destructive or irreversible operations | DELETE, but also POST/PUT that are irreversible |

#### Custom Values

The `access` field is **not restricted** to the well-known values above. DADL authors can use domain-specific values that make sense for their API:

```yaml
# custom access values
tools:
  list_invoices:
    access: billing
  export_user_data:
    access: pii
  trigger_deploy:
    access: ops
  send_notification:
    access: messaging
```

Custom values are passed through to policy files and OpenFGA unchanged. ToolMesh does not validate or reject unknown access values — they are treated as opaque strings.

#### Defaults

When `access` is omitted, ToolMesh does **not** infer a default. Tools without an `access` field are unrestricted by access-based policies (they can still be restricted by explicit per-tool OpenFGA rules). This is intentional: inferring `read` from `GET` would be wrong for endpoints like `POST /search` or `GET /admin/reset-cache`.

> **Best practice:** Always set `access` explicitly. It costs one line per tool and makes the DADL file self-documenting for authorization purposes.

### 6.5 Typed Returns (`returns`) *(since v0.2)*

Without `openapi_source`, generated TypeScript methods return `Promise<any>` — the LLM has to guess the result shape. The optional `returns` field types the result:

```yaml
# returns — typed results without openapi_source
types:
  Customer:
    type: object
    properties:
      id: { type: string }
      email: { type: string }
      name: { type: string }
    required: [id]

tools:
  get_customer:
    method: GET
    path: /customers/{id}
    access: read
    description: "Retrieve a single customer"
    returns: Customer
    params:
      id: { type: string, in: path, required: true }

  list_customers:
    method: GET
    path: /customers
    access: read
    description: "List customers"
    returns:
      type: array
      items: Customer
```

Two forms are accepted:

- **String** — the name of a type defined in `types` (Section 10). The generated signature becomes `Promise<Customer>`.
- **Object** — an inline schema using the same JSON Schema subset as Section 10, plus one DADL extension: a **bare type name** (string) may stand in any *type position* (`returns` itself, `items`, a property value) and refers to a `types` entry. This shorthand is DADL-specific — it is not JSON Schema. `$ref`, by contrast, keeps its JSON Schema meaning and takes a pointer: `$ref: "#/backend/types/Customer"`. Do not put a bare name into `$ref`.

Type names match `^[A-Za-z_][A-Za-z0-9_]*$` (usable as TypeScript identifiers). Validators MUST reject a bare-name or `$ref` reference that does not resolve to a declared type (Section 15.2).

**Semantics:** `returns` describes the value **after** the response pipeline (`result_path`, `transform`, Section 9) has run — the shape the Code Mode caller actually receives, not the raw API body. It is used for TypeScript generation and documentation only; ToolMesh does NOT validate responses against it at runtime. When `openapi_source` is present, `returns` overrides the derived type — useful when a `transform` changes the shape the OpenAPI spec describes.

### 6.6 Idempotency (`idempotency`) *(since v0.2)*

Retries of write calls are dangerous: a `POST /charges` that times out after the server processed it creates a duplicate charge when retried. ToolMesh executes tool calls as Temporal Activities with automatic retries, so writes need protection. Many APIs support an idempotency-key header (the Stripe pattern): requests carrying the same key are executed once, subsequent deliveries return the recorded response.

```yaml
create_charge:
  method: POST
  path: /charges
  access: write
  description: "Create a charge"
  idempotency:
    header: Idempotency-Key    # required — header name the API expects
    generate: uuid_v4          # default — the only defined generator in v0.2
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `header` | string | yes | Header name the API expects (e.g. `Idempotency-Key`, `X-Request-Id`). |
| `generate` | string | no | Key generator. `uuid_v4` (default) is the only value defined in v0.2; further generators are reserved. |

**Semantics:** ToolMesh generates the key **before the first attempt** of a logical tool call and persists it as part of the durable Activity input (workflow history) — every retry of that call, including after a worker crash or process restart, replays the same key. Two distinct tool calls always get distinct keys. The header is managed by ToolMesh; callers cannot override it, and the declared header name MUST NOT collide with a `params` entry of `in: header` or a `defaults.headers` key (Section 15.2).

> **Best practice:** declare `idempotency` on every `POST` tool whose API supports it. `GET`/`PUT`/`DELETE` are typically idempotent by design and do not need it.

### 6.7 Deprecation & Replacement (`deprecated`, `replaced_by`) *(since v0.2)*

Tools evolve. Removing or renaming a tool is a breaking change requiring a major version bump (Section 4.5) — and it silently breaks recorded Code Mode workflows and composites that call the old name. `deprecated` and `replaced_by` provide the migration path:

```yaml
list_repos_v1:
  method: GET
  path: /repos
  access: read
  description: "List repositories (unpaginated)"
  deprecated: "unpaginated — fails on accounts with >1000 repos"
  replaced_by: list_repos
```

- `deprecated: true` (or a string carrying the reason) keeps the tool fully functional but marks it `@deprecated` in the generated TypeScript interface. The LLM sees the JSDoc tag — including the reason string — and prefers the successor.
- `replaced_by` names the successor tool **in the same file**; validators MUST reject a `replaced_by` value that does not match an existing tool or composite. It renders as "use `list_repos` instead" in the JSDoc.

**Migration path for breaking changes:** instead of removing a tool in one step, deprecate it in a minor release (`1.2`: old tool `deprecated` + `replaced_by`, new tool added) and remove it in the next major release (`2.0`). Registries SHOULD reject a new version that removes a tool which was not deprecated in a previously published version.

---

## 7 Pagination

Pagination config is adapted from the [Airbyte Low-Code CDK](https://docs.airbyte.com), battle-tested across 400+ connectors. Set it in `defaults.pagination` to apply to all list endpoints, or override per tool.

| Strategy | Description |
|---|---|
| `cursor` | Cursor-based (Stripe, Slack). Uses a token from the response to fetch the next page. |
| `offset` | Offset-based. Increments an offset parameter. |
| `page` | Page number-based. Increments a page parameter. |
| `link_header` | RFC 8288 Link header (GitHub). Follows the `next` relation. |

```yaml
# pagination — cursor example
pagination:
  strategy: cursor
  request:
    cursor_param: after
    limit_param: per_page
    limit_default: 50
  response:
    next_cursor: "$.meta.next_cursor"
    has_more: "$.meta.has_more"
  behavior: auto              # auto | expose
  max_pages: 10              # safety limit
```

When `behavior` is `auto`, ToolMesh fetches all pages transparently. When `expose`, the LLM controls pagination via the cursor parameter in Code Mode: ToolMesh injects the cursor/page parameter (named by `request.cursor_param` / `page_param`) into the generated TypeScript interface from the pagination config — declaring it in `params` is OPTIONAL and only useful to customize its description.

---

## 8 Error Mapping

Error mapping triggers on **non-2xx responses**. `2xx` bodies always flow through the response pipeline (Section 9) — APIs that embed error indicators in `200` responses cannot be mapped here. Redirects are followed by the HTTP transport; a `3xx` that still surfaces (redirect loop, limit reached) enters error mapping like any other status. A status listed in neither `retry_on` nor `terminal` is treated as terminal (no retry); a status MUST NOT appear in both lists (Section 15.2). The single automatic re-authentication retry on `401` (Sections 5.3/5.4) happens below error mapping and is not affected by `terminal: [401]` — it is safe for every method, because a `401` means the server rejected the request before executing it.

**Retry safety** *(normative since v0.2)*: an automatic retry re-executes the request — after a timeout or `5xx`, the provider may already have performed the operation. Consumers MUST therefore apply `retry_on` (and the rate-limit retries of Section 8.1) only when at least one of the following holds:

- the method is idempotent by HTTP semantics (`GET`, `HEAD`, `PUT`, `DELETE`),
- the tool declares `idempotency` (Section 6.6) — the reused key makes re-execution safe,
- the tool opts in explicitly with `retry_unsafe: true` (the author accepts duplicate execution).

A `POST` or `PATCH` without `idempotency` and without `retry_unsafe` fails on the first retryable error instead of being retried.

```yaml
# defaults.errors
errors:
  format: json
  message_path: "$.error.message"
  code_path: "$.error.code"
  retry_on: [429, 502, 503, 504]
  retry_strategy:
    max_retries: 3
    backoff: exponential
    initial_delay: 1s
  terminal: [400, 401, 403, 404, 409]
  rate_limit:
    header: X-RateLimit-Remaining
    retry_after_header: Retry-After
  map:                        # since v0.2 — see Section 8.2
    404: not_found
    409: conflict
    429: rate_limited
```

### 8.1 Rate Limit Behavior

When `rate_limit` is configured, ToolMesh performs **proactive throttling** — it inspects rate-limit headers on every response and acts before the API rejects requests.

**Request flow:**

1. Before each request, ToolMesh checks the cached value of `rate_limit.header` (e.g. `X-RateLimit-Remaining`).
2. If the remaining count is **0**, ToolMesh **pauses** the request and waits until the reset time.
3. The wait duration is determined by (in order of precedence):
   - The `retry_after_header` response header (e.g. `Retry-After: 30`) — seconds or HTTP date.
   - The `X-RateLimit-Reset` header if present — Unix timestamp.
   - Fallback: exponential backoff starting at `retry_strategy.initial_delay`.
4. After waiting, ToolMesh retries the request. This counts toward `retry_strategy.max_retries`.
5. If a `429` response arrives despite proactive throttling (race condition, shared quota), it is handled by `retry_on` with the same backoff strategy.

**When `rate_limit` is not configured:** ToolMesh relies solely on `retry_on` — a `429` response triggers reactive retries with the configured backoff strategy. No proactive throttling occurs.

| Field | Type | Description |
|-------|------|-------------|
| `header` | string | Response header containing remaining request quota (e.g. `X-RateLimit-Remaining`) |
| `retry_after_header` | string | Response header indicating when to retry (e.g. `Retry-After`). Supports seconds and HTTP date formats. |

### 8.2 Semantic Error Codes (`errors.map`) *(since v0.2)*

HTTP status codes are transport details; Code Mode error handling should branch on stable, API-independent values instead of parsing status numbers and message strings. `errors.map` maps HTTP status codes to **semantic error codes**:

```yaml
errors:
  map:
    400: not_found        # this API returns 400 for missing resources
    409: conflict
    422: invalid_input
    429: rate_limited
```

**Error object in Code Mode:** a failed call rejects with an error carrying:

| Field | Source |
|-------|--------|
| `code` | Semantic code from `errors.map` (falling back to the default mapping below) |
| `http_status` | Raw HTTP status code |
| `message` | Extracted via `errors.message_path` |
| `provider_code` | Extracted via `errors.code_path` (the API's own error code, e.g. Stripe's `resource_missing`) |

This lets composites and LLM-written code branch reliably:

```javascript
try {
  return await api.get_customer({ id });
} catch (e) {
  if (e.code === "not_found") return null;   // expected — customer may not exist
  throw e;                                    // everything else propagates
}
```

**Well-known codes and default mapping.** When `map` is absent or does not cover a status, ToolMesh applies these defaults:

| Code | Default HTTP status |
|------|---------------------|
| `invalid_input` | 400, 422 |
| `unauthorized` | 401 |
| `forbidden` | 403 |
| `not_found` | 404, 410 |
| `conflict` | 409 |
| `timeout` | 408 |
| `rate_limited` | 429 |
| `internal` | 500 |
| `unavailable` | 502, 503, 504 |
| `client_error` | any other 4xx |
| `server_error` | any other 5xx |
| `unexpected_status` | anything else that surfaces (e.g. an unresolved 3xx) |

The last three are catch-alls — every non-2xx status maps to *some* semantic code; `e.code` is never absent.

`map` overrides the defaults selectively — declare it only for statuses the API uses in a non-standard way (e.g. `400` for missing resources). Only `4xx`/`5xx` statuses can be mapped; `2xx` responses never enter error mapping (see the trigger rule above). Note for validation: YAML integer keys (`404:`) are stringified (`"404"`) when a document is checked against the canonical JSON Schema. Like `access`, the code values are not restricted: custom codes (e.g. `insufficient_funds`) are passed through as opaque strings, but the well-known codes above SHOULD be preferred so error-handling code stays portable across backends.

---

## 9 Response Transformation

Most APIs wrap results in container objects. Response transformation extracts the relevant data before it reaches the LLM, reducing token consumption. This is **critical for IoT and status APIs** that return large payloads with system internals (RAM, firmware, WiFi details) that are irrelevant for the LLM.

### 9.1 Defaults-Level Response Config

```yaml
# defaults.response — applies to all tools unless overridden
response:
  result_path: "$.data"             # JSONPath to the actual result
  metadata_path: "$.meta"           # extracted separately (for pagination, not sent to LLM)
  transform: |                      # optional jq filter — runs on the result_path extraction
    map({id, name, status})
  max_items: 100
  allow_jq_override: true           # LLM can pass ad-hoc jq filters
```

### 9.2 Tool-Level Response Override

Individual tools can override `defaults.response` to apply custom transformations. This is especially useful when a single API returns large, deeply nested payloads that should be flattened or filtered before reaching the LLM context.

```yaml
# tool-level response override — reduces a 60KB IoT status payload to ~2KB
get_all_device_status:
  method: POST
  path: /device/all_status
  description: "Get status of all devices"
  response:
    result_path: "$.data.devices_status"
    transform: |
      to_entries | map({
        id: .key,
        name: (.value._dev_info.name // .key),
        online: (.value._dev_info.online // false),
        relay_on: [.value.relays // [] | .[] | select(.ison)] | length > 0,
        switch_on: (.value."switch:0".output // false),
        power_w: (.value."switch:0".apower // 0)
      })
```

| Field | Type | Description |
|-------|------|-------------|
| `result_path` | string | JSONPath to extract before `transform` runs. Applied first. |
| `metadata_path` | string | JSONPath to pagination/meta info (not sent to LLM). |
| `transform` | string | jq filter applied after `result_path` extraction. Use to flatten, rename, or filter fields. |
| `max_items` | integer | Truncate arrays to this length (prevents context overflow). |
| `allow_jq_override` | boolean | When `true`, the LLM can pass ad-hoc jq filters at call time. Consumers MUST run such filters under resource limits: CPU/wall-clock time, memory, maximum serialized output size, and recursion depth — an ad-hoc filter can burn resources even though it cannot unmask redacted data. |
| `redact` | array of string | JSONPaths whose values are masked before the response leaves ToolMesh. *(since v0.2 — see Section 9.3)* |

> **Best practice:** Always add `response.transform` to status/list endpoints that return more than ~5KB per item. LLM context is expensive — strip firmware versions, MAC addresses, WiFi RSSI, uptime counters, and other system internals unless they are the primary purpose of the tool.

### 9.3 Redaction (`response.redact`) *(since v0.2)*

Some API responses embed secrets that the caller has no business seeing: webhook configurations with signing secrets, user objects with API keys, SMTP settings with passwords. `response.redact` masks them declaratively:

```yaml
# redact — mask embedded secrets before the LLM sees them
list_webhooks:
  method: GET
  path: /webhooks
  access: read
  description: "List configured webhooks"
  response:
    result_path: "$.data"
    redact:
      - "$[*].secret"
      - "$[*].auth.password"
```

**Semantics:**

- Each entry is a JSONPath evaluated against the response; every matched value is replaced with the string `"[REDACTED]"`. Paths that match nothing are a no-op, not an error.
- **Pipeline order:** `result_path` → `transform` → `redact` → ad-hoc jq override (if allowed) → `max_items`. Paths are therefore relative to the *transformed* result, and an `allow_jq_override` filter supplied at call time operates on already-redacted data — the override cannot be used to exfiltrate masked values.
- Redaction cannot be disabled by the caller. It applies to Code Mode results, composite-internal `api.*` calls, and audit-log payloads alike.
- Unlike the rest of the `response` object, `redact` merges **additively** across levels: a tool-level `response` block extends `defaults.response.redact` but can never remove a default redaction (Section 6, override semantics).

**Relation to the Output Gate:** the Output Gate applies deployment-specific policies (PII rules, caller-dependent filtering) configured by the operator. `response.redact` complements it from the other side: the DADL author knows *where this particular API leaks secrets* and encodes that knowledge portably in the file itself. Defense in depth — both layers run.

**Scope:** redaction operates on the response pipeline only. Error responses (Section 8) never enter it — their caller-visible surface is limited to the extracted `message` and `provider_code` fields, not the raw error body.

### 9.4 JSONPath Dialect *(pinned in v0.2)*

Every field that takes a JSONPath expression — `result_path`, `metadata_path`, `redact`, `errors.message_path` / `code_path`, `pagination.response.next_cursor` / `has_more`, `health.expect_path`, and session `extract` — uses [RFC 9535](https://www.rfc-editor.org/rfc/rfc9535) syntax and semantics, restricted to this subset:

| Construct | Example | Support |
|-----------|---------|---------|
| Root + name selectors (dot notation) | `$.data.items` | REQUIRED |
| Index selector, including negative | `$.data[-1].id` | REQUIRED |
| Wildcard selector | `$[*].secret` | REQUIRED |
| Descendant segments, slices, filters | `$..id`, `$[1:3]`, `$[?(...)]` | Not part of the dialect — authors MUST NOT use them |

All three selector kinds are REQUIRED in **every** JSONPath field — a conforming consumer supports the same dialect everywhere, so a valid document behaves identically across consumers. Validators MUST reject paths outside the dialect (Section 15.2).

A consumer that encounters a construct it does not implement MUST fail the call (or reject the file at load time) rather than silently returning nothing — for `redact`, a non-matching path is a no-op only when the path is *valid* and simply absent from the data, never because the engine could not parse it.

---

## 10 Types *(optional)*

When `openapi_source` is provided, types are derived from the OpenAPI spec. Without it, you can define types inline using a JSON Schema subset. These are used to generate TypeScript interfaces for Code Mode. Tools reference them by name via `returns` (Section 6.5).

```yaml
# types — inline definitions
types:
  Customer:
    type: object
    properties:
      id: { type: string }
      email: { type: string }
      name: { type: string }
      metadata:
        type: object
        additionalProperties: { type: string }
    required: [id]
```

**Supported JSON Schema keywords** (for TypeScript generation):

`type`, `properties`, `items`, `required`, `$ref`, `enum`, `description`, `additionalProperties`, `oneOf`, `anyOf`, `allOf`.

Validation keywords (`minLength`, `pattern`, `minimum`, etc.) are accepted but not used for TypeScript generation. This allows copy-paste from OpenAPI schemas without modification.

---

## 11 Includes & Composability

DADL supports two levels of reuse: standard YAML anchors (intra-file) and DADL includes (cross-file). There is no templating, no inheritance, no conditionals.

### 11.1 YAML Anchors (intra-file)

```yaml
# YAML anchors — native DRY
# Underscore-prefixed keys are ignored by ToolMesh
_defaults:
  pagination: &default-pagination
    strategy: cursor
    request:
      cursor_param: starting_after
      limit_param: limit
      limit_default: 50
    behavior: auto
    max_pages: 20

backend:
  defaults:
    pagination: *default-pagination    # alias replaces the whole node
```

An alias (`*name`) substitutes the **entire** anchored node. Variants need their own anchors — there is no partial override via anchors.

> **Do not use YAML merge keys (`<<`).** *(clarified in v0.2)* Merge keys look like partial override but merge **shallowly**: a nested map in the overriding block replaces the anchored map entirely, silently dropping its other fields (`request: { cursor_param: x }` would lose `limit_param` and `limit_default`). The feature was also dropped from YAML 1.2, and the public DADL registry rejects files containing `<<`. Authors SHOULD NOT use merge keys; use whole-node anchors or spell the variant out.

### 11.2 Cross-file Includes

```yaml
# includes
includes:
  - path: common/oauth2-client-credentials.dadl.yaml
    merge_into: backend.auth
    overrides:
      token_url: https://api.stripe.com/oauth/token
      client_id_credential: vault/stripe-client-id

  - path: common/standard-rest-errors.dadl.yaml
    merge_into: backend.defaults.errors
```

Include fragments are files with `_fragment: true` at the top level. Merge semantics: deep merge, overrides win. Arrays are replaced, not appended. Includes are flat — no nested includes (max 1 level).

Fragments are **not standalone DADL documents**: they carry `_fragment: true` instead of `spec`/`backend` and do not validate against the canonical schema on their own. Document conformance (Section 15.2) is evaluated on the **composed result** after includes are merged. The `.dadl.yaml` extension distinguishes fragments from loadable `.dadl` files.

---

## 12 Composite Tools

Composite tools are server-side TypeScript functions that combine multiple primitive tools into a single, higher-level operation. They solve problems that `response.transform` (jq) cannot: cross-endpoint joins, multi-step workflows, and business logic that requires branching or loops.

### 12.1 When to Use Composites

| Problem | Solution |
|---------|----------|
| Single endpoint has too much data | `response.transform` (jq) |
| Join data from two endpoints (e.g. names + status) | **Composite tool** |
| Multi-step workflow (create → configure → verify) | **Composite tool** |
| Conditional logic (if device is X, call Y) | **Composite tool** |

### 12.2 Definition

Composites are defined under the `composites` key at the same level as `tools`. They appear as regular tools in the TypeScript interface — callers cannot distinguish them from primitive tools.

```yaml
composites:
  get_named_status:
    description: "Get all device status with human-readable names and on/off state"
    access: read
    params:
      only_on:
        type: boolean
        default: false
        description: "If true, return only devices that are currently on"
    timeout: 30s
    code: |
      const devices = await api.list_devices();
      const nameMap = Object.fromEntries(devices.map(d => [d.id, d.name]));
      const status = await api.get_all_device_status();
      const result = status.map(d => ({
        ...d,
        name: nameMap[d.id] || d.id
      }));
      if (params.only_on) {
        return result.filter(d => d.relay_on || d.light_on || d.switch_on);
      }
      return result;
```

### 12.3 Composite Tool Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `description` | string | yes | Used as JSDoc comment in TypeScript interface |
| `access` | string | no | Access classification, same values and policy mapping as for tools (Section 6.4). *(since v0.2)* |
| `delegates` | array | no | Inner tools this composite intends to call under **its own** authority instead of the caller's — effective only with deployment-policy approval. See Authorization below. *(since v0.2)* |
| `params` | object | no | Input parameters (same syntax as tool params, but `in:` is not used) |
| `code` | string | yes | TypeScript/JavaScript function body. Has access to `api.*` (all tools in this backend) and `params` (input parameters). |
| `timeout` | string | no | Max execution time (default: `30s`). Killed after timeout. |
| `depends_on` | array | no | Informational: primitive tools called internally. |

**Authorization** *(since v0.2)*: the policy layer treats a composite exactly like a tool — its `access` value feeds the same role mapping. For its inner calls, the default is **fail-closed**: every inner `api.*` call is additionally checked against the **caller's** per-tool permissions. A caller cannot reach anything through a composite that it could not call directly — a DADL file, including one installed from a registry, can never widen privileges by itself.

Deliberate encapsulation (hard-wired parameters turning a broad `write` primitive into one specific, safe operation that e.g. `read` users should be able to invoke) uses a two-key mechanism:

1. The composite **declares** which inner tools it intends to run under its own authority: `delegates: [delete_item]`. The declaration alone changes nothing; validators check that every entry names an existing tool (Section 15.2), registries and audits can flag it.
2. The **deployment policy** approves the delegation (per backend or per composite). Only then do the listed inner calls skip the caller re-check and run under the composite's authority.

Runtimes MUST NOT honor `delegates` without deployment approval — the author proposes, the operator decides, mirroring the `access` → policy-mapping split. Inner calls are audited individually in every mode (Section 12.4). `access` SHOULD reflect what the composite does from the caller's perspective; with approved delegation the narrower value is exactly the point.

### 12.4 Sandbox & Security

Composite code runs in a **restricted sandbox** with the following constraints:

| Allowed | Forbidden |
|---------|-----------|
| `api.*` calls (tools in the same backend) | `fetch()`, `XMLHttpRequest`, any network I/O |
| `params` (input parameters) | `require()`, `import`, dynamic module loading |
| Pure JS: `map`, `filter`, `reduce`, `JSON.*`, `Math.*`, `Date.*` | `fs`, `process`, `child_process`, `os` |
| `console.log` (captured to audit log) | `eval()`, `Function()`, `globalThis` mutation |
| `await` (for `api.*` calls) | Accessing other backends or services |
| String/Array/Object manipulation | `setTimeout`, `setInterval` (use `timeout` field instead) |

**Additional runtime constraints:**

- **Timeout:** Hard-killed after the configured timeout (default 30s, max 120s).
- **Call depth:** Composites can only call primitive tools, not other composites. Max 50 `api.*` calls per execution.
- **No side-channel:** Composites cannot construct URLs or make HTTP calls outside of `api.*`. All network access is mediated by ToolMesh.
- **Audit:** Every `api.*` call within a composite is logged individually in the audit trail with the composite's name as parent context.

> **Security note:** When DADL files contain composites, ToolMesh sets `contains_code: true` in the backend metadata. Deployment pipelines should flag DADL files with composites for automated static analysis (AST scanning for forbidden globals, network calls, eval patterns). Manual review is not scalable — automated scanning at CI/CD time is the primary gate. See the ToolMesh Security Guide for reference AST rules.

### 12.5 Best Practices

- Keep composites **short** (< 30 lines). If it is longer, the logic probably belongs in a dedicated microservice.
- Use composites for **read-only** joins and aggregations. Avoid composites that write to multiple endpoints — use Temporal workflows for durable multi-step mutations.
- Always set a **`description`** that explains what the composite does, not how. The LLM sees this in the TypeScript interface.
- Prefer `response.transform` (jq) when a single endpoint is involved. Composites are for multi-endpoint orchestration.

---

## 13 Full Example

```yaml
# stripe.dadl
spec: "https://dadl.ai/spec/dadl-spec-v0.2.md"
requires:
  features: [idempotency]      # load-bearing — must not degrade silently (Section 15.3)

backend:
  name: stripe
  type: rest
  version: "1.0"
  base_url: https://api.stripe.com/v1
  description: "Stripe payment processing API"
  openapi_source: https://raw.githubusercontent.com/stripe/openapi/master/openapi/spec3.yaml

  auth:
    type: bearer
    credential: vault/stripe-secret-key

  health:
    method: GET
    path: /balance
    timeout: 5s

  defaults:
    content_type: application/x-www-form-urlencoded
    pagination:
      strategy: cursor
      request:
        cursor_param: starting_after
        limit_param: limit
        limit_default: 100
      response:
        next_cursor: "$.data[-1].id"
        has_more: "$.has_more"
      behavior: expose
      max_pages: 10
    errors:
      format: json
      message_path: "$.error.message"
      code_path: "$.error.type"
      retry_on: [429, 502, 503]
      map:
        402: card_declined
        404: not_found
    response:
      result_path: "$.data"
      allow_jq_override: true

  tools:
    list_customers:
      method: GET
      path: /customers
      access: read
      description: "List all customers"
      params:
        email: { type: string, in: query, required: false }
        limit: { type: integer, in: query, default: 10 }

    get_customer:
      method: GET
      path: /customers/{id}
      access: read
      description: "Retrieve a single customer by ID"
      params:
        id: { type: string, in: path, required: true }
      response:
        result_path: "$"
      pagination: none

    create_customer:
      method: POST
      path: /customers
      access: write
      description: "Create a new customer"
      idempotency:
        header: Idempotency-Key
      params:
        email: { type: string, in: body, required: true }
        name: { type: string, in: body }
        metadata: { type: object, in: body }
      response:
        result_path: "$"
      pagination: none

  examples:
    - name: "Customer onboarding"
      description: "Create a customer and retrieve their details"
      code: |
        const customer = await api.create_customer({
          email: "jane@example.com",
          name: "Jane Doe"
        });
        const details = await api.get_customer({ id: customer.id });
        return details;
```

---

## 14 ToolMesh Integration

DADL files are consumed by **ToolMesh** and integrated into its six-pillar architecture:

| Pillar | DADL Integration |
|---|---|
| **Code Mode** | TypeScript interfaces are auto-generated from DADL tools and types. The LLM writes code against `api.*` methods. |
| **Temporal** | Each `execute()` call runs as a Temporal Activity — retry, timeout, and full audit trail. |
| **OpenFGA** | Per-tool authorization. The `access` field on each tool enables role-based policy mapping (e.g. `read` → reader role). Policies can further restrict by user, plan, or caller origin. |
| **MCP Aggregation** | DADL backends mix seamlessly with native MCP backends in the same ToolMesh instance. |
| **Credential Store** | `credential: vault/xxx` references are resolved through the three-tier store (Embedded → Infisical → Vault/OpenBao). |
| **Output Gate** | Responses pass through goja-based policies (PII redaction, rate limiting, caller-dependent filtering). |

---

## 15 Conformance *(since v0.2)*

### 15.1 Normative Language

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when, and only when, they appear in all capitals.

### 15.2 Canonical JSON Schema & Document Conformance

The canonical, machine-readable schema for this version is published at:

> **https://dadl.ai/schema/v0.2.json**

(source of truth: `docs/schema/dadl-v0.2.schema.json` in the ToolMesh repository). It is the shared foundation for linters, the `dadl validate` CLI, and registry CI pipelines — one schema, every validator.

A file is a **conforming DADL document** when:

1. it is valid YAML,
2. it validates against the canonical JSON Schema of the spec version it declares in `spec` (v0.1 predates this chapter and has no canonical schema of its own — documents declaring v0.1 are validated against the v0.2 schema, which is additive, so every valid v0.1 document passes), and
3. it satisfies the constraints that JSON Schema cannot express. Machine-checkable — validators MUST enforce:
   - every `{param}` placeholder in a `path` has a matching `params` entry with `in: path`, and vice versa;
   - `replaced_by` references an existing tool or composite in the same file;
   - every load-bearing feature the file uses (`redact`, `idempotency`, `rotates_refresh_token` — Section 15.3) is declared in `requires.features`;
   - a file using any feature marked *(since v0.2)* declares a v0.2 `spec` URL;
   - `health.tool` references an existing tool in the same file, and that tool has no required parameters;
   - every `delegates` entry references an existing tool in the same file;
   - every `returns` / bare-name / `$ref` type reference resolves to a declared type (Section 6.5);
   - every JSONPath expression parses within the Section 9.4 dialect;
   - no status code appears in both `retry_on` and `terminal`;
   - a declared `idempotency.header` does not collide with a `params` entry of `in: header` or a `defaults.headers` key;
   - includes are at most one level deep, and include fragments carry `_fragment: true`.

   Author obligations — not machine-checkable; registries enforce by review:
   - composite `code` calls only primitive tools of the same backend (statically checkable only in the absence of dynamic access such as `api[name]`);
   - the `health` endpoint is side-effect-free.

Document conformance is evaluated **after includes are resolved**; fragment files themselves (Section 11.2) are exempt.

**Validation strictness is context-dependent** (see Section 15.3): publish-time validators (registry CI, `dadl validate`) MUST treat unknown keys as errors; runtime consumers MUST NOT.

The canonical schema is the **strict publish-time profile** (unknown keys are errors). Runtimes do not consume it with these settings — their warn-and-ignore behavior (Section 15.3) is a different validation profile by design; the two must not be conflated.

Registries MAY impose additional publication requirements beyond document conformance — the public DADL registry, for example, requires `credits`, `source_name`, `source_url`, `date`, and an explicit `access` classification on every tool and composite (tools without `access` are unrestricted by access-based policies, Section 6.4 — an acceptable default for private files, not for published ones).

### 15.3 Forward Compatibility: Unknown Keys & `requires`

DADL files and DADL consumers evolve independently — a file written against a newer spec revision will meet older runtimes. Three rules keep that safe:

**Unknown-key policy:**

| Context | Unknown key handling |
|---------|---------------------|
| Publish-time validation (registry CI, `dadl validate`, linters) | MUST **reject** — catches typos and unspecified fields before they spread |
| Runtime consumers (ToolMesh) | MUST **warn and ignore** — a file using only additive newer features keeps working, degraded but visibly |
| Underscore-prefixed keys (`_*`) | Ignored silently by every consumer, validators and runtimes alike (YAML anchor workspace). The canonical schema permits them at the document top level. |

**Unknown-value policy.** Keys can be ignored; values of a key the consumer *does* implement cannot. For **behavior-determining enum fields** — `backend.type`, `auth.type`, `auth.flow`, `pagination.strategy`, `pagination.behavior`, `idempotency.generate`, `response.stream_handling` — a consumer that does not implement the declared value MUST reject the file (fail-closed) rather than guess, substitute a default, or call the API with wrong semantics. Fields defined as opaque pass-through strings (`access`, `errors.map` codes) are exempt.

**`requires` — declared hard requirements.** Warn-and-ignore is wrong when a feature is load-bearing: a runtime that ignored an unknown `response.redact` would silently expose the very secrets the author masked. When a file *depends* on a feature for correctness or security, it MUST declare it:

```yaml
# top level, next to spec:
requires:
  toolmesh: ">=0.9.0"        # semver range — minimum runtime version
  features: [redact, jwt_bearer]
```

A runtime that cannot satisfy every entry in `requires` MUST refuse to load the file (fail-closed) with a message naming the missing capability. `toolmesh` takes a semver range using comparison operators `>=`, `>`, `<=`, `<`, `=` with comma-separated AND (e.g. `">=0.9.0, <2.0.0"`); `features` takes feature identifiers defined by spec releases. Prefer `features` over `toolmesh`: it names the capability portably instead of one implementation's version number — use the version range only for implementation-specific needs (e.g. a runtime bug fixed in a given release). v0.2 defines:

| Feature identifier | Section |
|--------------------|---------|
| `refresh_token` | 5.3 |
| `jwt_bearer` | 5.3 |
| `authorization_code` | 5.3 |
| `health` | 4.6 |
| `returns` | 6.5 |
| `idempotency` | 6.6 |
| `deprecation` | 6.7 |
| `semantic_errors` | 8.2 |
| `redact` | 9.3 |
| `refresh_token_rotation` | 5.3 |

> **Authoring rule:** files MUST declare `requires.features` for every feature whose silent absence would change semantics dangerously — `redact`, `idempotency`, and `refresh_token_rotation` always; `returns` or `deprecation` (documentation-only) need not be declared. Validators enforce this mechanically (feature used ⟹ feature declared). The OAuth flows themselves need no `requires` entry: they are covered by the unknown-value policy (`auth.flow` is behavior-determining) plus the mandatory v0.2 `spec` URL.

**Bootstrap limitation.** The fail-closed guarantee of `requires` binds only consumers that implement `requires` itself (spec v0.2 and later). A consumer predating it sees an unknown top-level key and — under its own policy — ignores it; the `spec:` URL is the only signal such a consumer can act on. This is inherent to introducing the mechanism and is why a consumer SHOULD warn whenever it loads a file declaring a spec version newer than the one it implements (Section 15.4).

The design rationale is recorded in ADR-0003 (*DADL Spec Versioning & Forward Compatibility*) in the ToolMesh repository.

### 15.4 Consumer Conformance

Consumer conformance comes in three profiles, so "supports DADL v0.2" always has a precise meaning:

**Profile 1 — Document Validator** (registry CI, `dadl validate`, linters): implements the canonical schema plus every machine-checkable constraint of Section 15.2, with strict unknown-key handling. Makes no claims about execution.

**Profile 2 — Core Runtime**: executes DADL files and MUST, without exception:

- implement the unknown-key policy (warn and ignore) and honor `requires` fail-closed;
- reject files declaring an unsupported value of a behavior-determining enum (`backend.type`, `auth.type`, `auth.flow`, `pagination.strategy`, `pagination.behavior`, `idempotency.generate`, `response.stream_handling`) rather than guessing — never call the API unauthenticated or with wrong semantics;
- accept `api_key` as an alias for `apikey`;
- resolve credentials outside the LLM context — credential values, tokens, and signed assertions MUST NOT appear in tool results, generated interfaces, logs, or workflow history;
- apply `response.redact` before any caller-visible output (including ad-hoc jq overrides and audit payloads), enforce the retry-safety rules of Section 8, keep idempotency keys stable across retries, apply the composite authorization default of Section 12.3, and meet the `file_url` security requirements of Section 6.2 for the features it implements;
- implement the Section 9.4 JSONPath dialect wherever it accepts JSONPath.

A Core Runtime MAY leave whole features unimplemented (an auth flow, pagination strategy, composites, the file broker) — the unknown-value policy and `requires` turn every such gap into a clean load-time rejection instead of wrong behavior. It MAY load files declaring a *newer* spec version than it implements (best effort, with a warning and per-key warnings) — unless `requires` says otherwise.

**Profile 3 — Full Runtime**: a Core Runtime that implements **every** non-optional semantic this specification defines — all auth types and flows (Section 5), all pagination strategies (Section 7), health checks, composites, and file handling. "Full v0.2 support" claims this profile; anything less names the profile and its gaps (e.g. "Core Runtime; no `jwt_bearer`, no composites").

---

## 16 Outlook: v0.3 *(non-normative)*

The following area is under active design and explicitly **not** part of v0.2:

- **Session semantics for LLM backends** — a `session:` block (system prompt, TTL, context-window strategy) and a backend `type: llm` with `provider:`/`model:`, turning stateful conversations with an expert model into a DADL backend. Each session keeps an isolated context; the caller passes in only what it explicitly sends.

These constructs are not part of v0.2, and Section 15.3 already governs what happens when they appear: the `session:` key is an unknown *key* (validators reject it, runtimes warn and ignore it), while `type: llm` is an unknown *value* of a behavior-determining field — every v0.2 consumer rejects such a file outright.

---

*DADL is created and maintained by [Dunkel Cloud GmbH](https://dunkel.cloud)*

[ToolMesh](https://toolmesh.io) · [GitHub](https://github.com/DunkelCloud) · This specification is licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). ToolMesh source code is licensed under Apache 2.0.
