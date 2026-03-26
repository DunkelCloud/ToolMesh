# DADL — Dunkel API Description Language

**Specification Draft v0.1**

A **declarative YAML format** for describing REST APIs as [ToolMesh](https://toolmesh.io) backends.
Write a `.dadl` file — ToolMesh handles the rest.

| | |
|---|---|
| Version | 0.1.0-draft |
| Date | 2026-03-26 |
| Author | Dunkel Cloud GmbH |
| License | Apache 2.0 |

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
| `version` | string | yes | DADL spec version. Currently `"1.0"` |
| `author` | string | no | Author of this DADL file (person or organization) |
| `source_name` | string | no | Name of the source API being described (e.g. `"GitHub REST API"`) |
| `source_url` | string | no | URL to the original API specification or documentation |
| `date` | string | no | Creation or last-modified date of this file (`YYYY-MM-DD`) |
| `backend` | object | yes | The backend definition |
| `includes` | array | no | Reusable fragments to merge in |
| `_*` | any | no | Underscore-prefixed keys are ignored by ToolMesh (used for YAML anchors) |

```yaml
# minimal.dadl
version: "1.0"
author: "Jane Doe"                          # optional
source_name: "Example REST API"              # optional
source_url: https://docs.example.com/api     # optional
date: "2026-03-26"                            # optional

backend:
  name: my-api
  type: rest
  base_url: https://api.example.com/v1
  description: "My REST API"

  auth:
    type: bearer
    credential: vault/my-api-token

  tools:
    list_items:
      method: GET
      path: /items
      description: "List all items"
```

---

## 4 Backend Object

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | Unique backend identifier (slug format: lowercase, hyphens) |
| `type` | string | yes | Always `rest` for DADL backends |
| `base_url` | string | yes | Base URL for all API requests |
| `description` | string | yes | Human-readable description (used in Code Mode prompt) |
| `openapi_source` | string | no | Path or URL to OpenAPI 3.x spec. When provided, schemas and parameters are derived from it. |
| `arazzo_source` | string | no | Path or URL to Arazzo workflow file. Used as documentation context for Code Mode, not executed. |
| `auth` | object | yes | Authentication configuration |
| `defaults` | object | no | Default pagination, error, and response config for all tools |
| `types` | object | no | Type definitions (JSON Schema subset). Only needed without `openapi_source`. |
| `tools` | object | yes | Map of tool definitions |
| `examples` | array | no | Code examples for multi-step workflows (few-shot prompts for the LLM) |
| `coverage` | object | no | API coverage metadata. Helps LLMs understand scope and users assess fitness. |
| `hints` | object | no | Per-tool domain knowledge for LLM consumers (structured key-value). Injected into tool descriptions at load time. Subject to security scanning. |
| `setup` | object | no | Human-readable setup instructions. Describes how to obtain credentials, configure backends.yaml, and required permissions. Powers `toolmesh setup <name>` CLI. |

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

Structured domain knowledge that is injected into tool descriptions at load time. Helps LLMs use tools correctly without trial and error. Hints are per-tool and use key-value pairs rather than free text to reduce prompt injection surface.

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

---

## 5 Authentication

DADL supports three authentication patterns. Credentials are referenced by logical name and resolved at runtime by ToolMesh's three-tier Credential Store (Embedded → Infisical → Vault/OpenBao). **The LLM never sees credentials.**

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

### 5.2 OAuth 2.0 Client Credentials

```yaml
# auth — oauth2
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

### 5.3 Session-based (Login → Token → Use)

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

### 5.4 API Key

```yaml
# auth — api_key
auth:
  type: api_key
  credential: vault/my-api-key
  inject_into: header          # header | query
  header_name: X-API-Key
```

---

## 6 Tools

Each tool maps to one REST API endpoint. In Code Mode, tools become methods on the auto-generated TypeScript interface that the LLM writes code against.

| Field | Type | Required | Description |
|---|---|---|---|
| `method` | string | yes | HTTP method: GET, POST, PUT, PATCH, DELETE |
| `path` | string | yes | URL path (may contain `{param}` placeholders) |
| `description` | string | yes | Used as JSDoc comment in TypeScript interface |
| `params` | object | no | Parameter definitions (path, query, header) |
| `body` | object | no | Request body schema |
| `content_type` | string | no | Request content type. Default: `application/json`. Use `multipart/form-data` for file uploads. |
| `max_body_size` | string | no | Max upload size, e.g. `50MB` |
| `depends_on` | array | no | Informational: other tools that should be called first. Becomes JSDoc hint. |
| `response` | object | no | Response transformation config (overrides `defaults.response`) |
| `pagination` | string\|object | no | `none` to disable, or object to override default pagination |
| `errors` | object | no | Error mapping (overrides `defaults.errors`) |

### 6.1 Parameter Definition

All parameters — path, query, and **body** — are defined under the `params` key using `in:` to specify their location. There is no separate `body:` keyword in DADL.

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
| `body` | JSON body field (for `application/json`) or form field (for `application/x-www-form-urlencoded`) |

### 6.2 File Handling

Files in DADL are always referenced by **URL** — never as inline data or local file paths. This keeps tool calls lightweight (only a URL string in the context, not megabytes of Base64) and works with any storage backend (S3, MinIO, NextCloud, ToolMesh's built-in file broker).

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

When `behavior` is `auto`, ToolMesh fetches all pages transparently. When `expose`, the LLM controls pagination via the cursor parameter in Code Mode.

---

## 8 Error Mapping

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
```

---

## 9 Response Transformation

Most APIs wrap results in container objects. Response transformation extracts the relevant data before it reaches the LLM, reducing token consumption. This is **critical for IoT and status APIs** that return large payloads with system internals (RAM, firmware, WiFi details) that are irrelevant for the LLM.

### 9.1 Defaults-Level Response Config

```yaml
# defaults.response — applies to all tools unless overridden
response:
  result_path: "$.data"             # JSONPath to the actual result
  metadata_path: "$.meta"           # extracted separately (for pagination, not sent to LLM)
  transform: |                      # optional jq filter
    .data | map({id, name, status})
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
| `allow_jq_override` | boolean | When `true`, the LLM can pass ad-hoc jq filters at call time. |

> **Best practice:** Always add `response.transform` to status/list endpoints that return more than ~5KB per item. LLM context is expensive — strip firmware versions, MAC addresses, WiFi RSSI, uptime counters, and other system internals unless they are the primary purpose of the tool.

---

## 10 Types *(optional)*

When `openapi_source` is provided, types are derived from the OpenAPI spec. Without it, you can define types inline using a JSON Schema subset. These are used to generate TypeScript interfaces for Code Mode.

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
      limit_param: limit
      limit_default: 50
    behavior: auto
    max_pages: 20

backend:
  defaults:
    pagination:
      <<: *default-pagination
      request:
        cursor_param: starting_after
```

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
    params:
      only_on:
        type: boolean
        default: false
        description: "If true, return only devices that are currently on"
    timeout: 30s
    code: |
      const devices = await api.list_devices();
      const nameMap = Object.fromEntries(devices.map(d => [d.id, d.name]));
      const status = await api.get_all_device_status({ show_info: true });
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
| `params` | object | no | Input parameters (same syntax as tool params, but `in:` is not used) |
| `code` | string | yes | TypeScript/JavaScript function body. Has access to `api.*` (all tools in this backend) and `params` (input parameters). |
| `timeout` | string | no | Max execution time (default: `30s`). Killed after timeout. |
| `depends_on` | array | no | Informational: primitive tools called internally. |

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
version: "1.0"

backend:
  name: stripe
  type: rest
  base_url: https://api.stripe.com/v1
  description: "Stripe payment processing API"
  openapi_source: https://raw.githubusercontent.com/stripe/openapi/master/openapi/spec3.yaml

  auth:
    type: bearer
    credential: vault/stripe-secret-key

  defaults:
    headers:
      Content-Type: application/x-www-form-urlencoded
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
    response:
      result_path: "$.data"
      allow_jq_override: true

  tools:
    list_customers:
      method: GET
      path: /customers
      description: "List all customers"
      params:
        email: { type: string, in: query, required: false }
        limit: { type: integer, in: query, default: 10 }

    get_customer:
      method: GET
      path: /customers/{id}
      description: "Retrieve a single customer by ID"
      params:
        id: { type: string, in: path, required: true }
      response:
        result_path: "$"
      pagination: none

    create_customer:
      method: POST
      path: /customers
      description: "Create a new customer"
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

## 13 ToolMesh Integration

DADL files are consumed by **ToolMesh** and integrated into its six-pillar architecture:

| Pillar | DADL Integration |
|---|---|
| **Code Mode** | TypeScript interfaces are auto-generated from DADL tools and types. The LLM writes code against `api.*` methods. |
| **Temporal** | Each `execute()` call runs as a Temporal Activity — retry, timeout, and full audit trail. |
| **OpenFGA** | Per-tool authorization. Policies can restrict access by user, plan, or caller origin. |
| **MCP Aggregation** | DADL backends mix seamlessly with native MCP backends in the same ToolMesh instance. |
| **Credential Store** | `credential: vault/xxx` references are resolved through the three-tier store (Embedded → Infisical → Vault/OpenBao). |
| **Output Gate** | Responses pass through goja-based policies (PII redaction, rate limiting, caller-dependent filtering). |

---

*DADL is created and maintained by [Dunkel Cloud GmbH](https://dunkel.cloud)*

[ToolMesh](https://toolmesh.io) · [GitHub](https://github.com/DunkelCloud) · Apache 2.0
