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
- **Authorization:** Fine-grained access control via OpenFGA (plan -> tool mapping)
- **Authentication required:** With no `TOOLMESH_AUTH_PASSWORD`/`TOOLMESH_API_KEY` (or `users.yaml`/`apikeys.yaml`), every request is rejected — the server is never open by default.
- **Safe defaults:** Logging defaults to `info` (no request payloads); the unauthenticated metrics port is bound to loopback by the Compose file; caller-supplied `file_url` fetches fail closed against private/internal addresses.

### Startup security posture

No default silently relaxes a control. At boot ToolMesh logs a single
**security-posture summary** listing every control still in a relaxed state
(missing auth credential, authz bypass, open CORS, debug tools) with a
remediation hint. These are logged at `WARN` in the default production posture;
set `TOOLMESH_DEV=true` on a development machine to report the same facts once at
`INFO`. `TOOLMESH_DEV` changes only the log level of this summary — it never
relaxes a setting.

For details, see [docs/architecture.md](docs/architecture.md).
