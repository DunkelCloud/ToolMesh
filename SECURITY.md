# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| main    | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in ToolMesh, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@dunkel.cloud**

You will receive an acknowledgment within 48 hours, and we aim to provide
a detailed response within 5 business days.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Scope

The following are in scope:
- Authentication/authorization bypass
- Credential leakage through the Output Gate
- Injection attacks via tool parameters
- Policy engine (goja) sandbox escapes

The following are out of scope:
- Vulnerabilities in upstream dependencies (report to the dependency maintainer)
- Vulnerabilities in external MCP servers connected via MCPAdapter
- Denial of service through legitimate API usage

## Security Architecture

ToolMesh follows a security-by-default design:

- **Fail-Closed:** Credential lookup failures abort the request
- **Output Gate:** Every tool result passes through the policy engine
- **Credential Isolation:** Secrets are injected at runtime, never exposed in prompts
- **Audit Trail:** Every tool execution is recorded via Temporal workflow history
- **Authorization on by default:** Every tool call is checked by OpenFGA, built into ToolMesh (user, role, plan or company -> tool). Switching it off takes `TOOLMESH_AUTHZ_MODE=disabled`, which is reported at every start and recorded in the audit trail.
- **Authentication required:** With no `TOOLMESH_AUTH_PASSWORD`/`TOOLMESH_API_KEY` (or `users.yaml`/`apikeys.yaml`), every request is rejected — the server is never open by default.
- **Login throttling:** Failed password logins are limited per account and per client address, logged, and counted; an unknown username costs the same work and gets the same answer as a wrong password.
- **Bounded password hashing:** The number of bcrypt comparisons running at once is limited for the whole process. API keys are found by lookup and an access token never costs a comparison. Only API key entries that are configured as a bcrypt hash and have not been used since startup are still compared, one request at a time; configuring them with `key_sha256` removes that.
- **Unauthenticated requests are answered `401`** with a `WWW-Authenticate` challenge on `/mcp`, logged, and counted.
- **Safe defaults:** Logging defaults to `info` (no request payloads); the unauthenticated metrics port is bound to loopback by the Compose file; caller-supplied `file_url` fetches fail closed against private/internal addresses.
- **Composite children checked:** Nested `api.*` calls inside a composite go through authorization and the pre-execution gate; a REST adapter without that guard refuses them, also after a reload of `backends.yaml`.
- **Credentials stay with their backend:** A redirect to another origin never carries injected credentials or the `Referer`, and is never followed from `https` to `http`; token and login requests follow no redirects and use the backend's connection rules; tool paths and the session login URL cannot leave the host and path of `base_url`.
- **No secrets in error texts:** Transport errors name only scheme and host of a request, so a query-injected credential reaches neither the audit log nor a tool result.
- **Typed arguments before the gate:** Parameters of REST tools are checked against their declared DADL types before any policy sees them.
- **Explicit OAuth consent:** The login page names the host that receives the authorization and requires a confirmation; `TOOLMESH_OAUTH_REDIRECT_HOSTS` can restrict redirect hosts. Token refresh and every access token are resolved against the current user configuration, and `/revoke` revokes tokens (RFC 7009).
- **Client address from trusted proxies only:** `X-Forwarded-For` is honored only from `TOOLMESH_TRUSTED_PROXIES`; failed API keys and client registrations are limited per address, also without Redis.
- **Bounded code execution:** `execute_code` runs are limited in time, tool calls, stack depth and number in progress (`TOOLMESH_CODE_MAX_CONCURRENT`, at most half of it per user). Known limit: the JavaScript runtime has no memory limit of its own, so a single run can use as much memory as the process may; run ToolMesh with a container memory limit.

### Startup security posture

No default silently relaxes a control. At boot ToolMesh logs a single
**security-posture summary** listing every control still in a relaxed state
(missing auth credential, authorization disabled or open to everyone, open CORS, debug tools, login limits
switched off) with a remediation hint. These are logged at `WARN` in the default production posture;
set `TOOLMESH_DEV=true` on a development machine to report the same facts once at
`INFO`. `TOOLMESH_DEV` changes only the log level of this summary — it never
relaxes a setting.

For details, see [docs/architecture.md](docs/architecture.md).
