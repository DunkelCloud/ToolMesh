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

For details, see [docs/architecture.md](docs/architecture.md).
