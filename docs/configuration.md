# ToolMesh Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and adjust values as needed.

## MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_PORT` | `8123` | Host-side port for Docker port mapping. The Go binary always listens on 8080 inside the container; this variable controls the `host:container` mapping in `docker-compose.yml`. |
| `TOOLMESH_TRANSPORT` | `http` | Transport mode: `http` or `stdio` |
| `TOOLMESH_CORS_ORIGINS` | *(empty)* | Comma-separated list of allowed CORS origins (e.g. `https://claude.ai,https://app.example.com`). If unset, any origin is reflected — fine for localhost, not for production. |
| `TOOLMESH_AUTH_PASSWORD` | *(empty)* | Password for OAuth 2.1 single-user authentication |
| `TOOLMESH_API_KEY` | *(empty)* | Static API key (bypasses OAuth when set) |
| `TOOLMESH_AUTH_USER` | `owner` | User identity in simple auth mode (password/single API key) |
| `TOOLMESH_AUTH_PLAN` | `pro` | Plan in simple auth mode |
| `TOOLMESH_AUTH_ROLES` | `admin` | Comma-separated roles in simple auth mode |
| `TOOLMESH_ISSUER` | `https://toolmesh.io/` | OAuth issuer URL (must end with `/`) |
| `TOOLMESH_ROOT_REDIRECT` | *(empty)* | Absolute `http(s)` URL that `GET /` redirects to (302). Unset, the site root serves the built-in page explaining that this host is an MCP endpoint. Only `/` is redirected — `/mcp` always serves the page, since a visitor there needs the URL to copy. An invalid value fails startup. |
| `TOOLMESH_DEV` | `false` | Local-development posture. Reports the startup security-posture summary at `INFO` instead of `WARN`. Relaxes no setting on its own — it only changes the log level of that summary. |

## Login Throttling

The password login at `/authorize` limits failed attempts. Each limit counts failures within `TOOLMESH_LOGIN_FAILURE_WINDOW`. Once a limit is reached, further attempts it covers are answered with `429` and a `Retry-After` header, without the password being checked, until the window that began with the first counted failure has passed. Later attempts do not extend it.

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_LOGIN_MAX_FAILURES_PER_USER_IP` | `5` | Failed logins for one account from one client address. This is the limit that stops a single source from guessing at an account; it locks that source out, not the account. |
| `TOOLMESH_LOGIN_MAX_FAILURES_PER_USER` | `20` | Failed logins for one account from all addresses together. Bounds guessing that is spread over many addresses. When it is reached, the account cannot log in from anywhere until the window ends. |
| `TOOLMESH_LOGIN_MAX_FAILURES_PER_IP` | `50` | Failed logins from one client address across all accounts. Bounds one source trying many usernames. |
| `TOOLMESH_LOGIN_FAILURE_WINDOW` | `900` | Length of the counting window in seconds (1 to 2592000, i.e. 30 days). |

Set a limit to `0` to switch it off; the startup security-posture summary reports every limit that is off. Unlike most numeric settings, these four are parsed strictly: a value that is not an integer or is out of range stops the server at startup instead of falling back to the default.

- **What counts.** A wrong password, for a known and an unknown username alike. An unknown name is counted and locked out exactly like a real one, and costs the same password-hash comparison, so neither the lockout nor the response time shows which accounts exist. (The timing guarantee assumes all hashes in `users.yaml` use the same bcrypt cost; ToolMesh logs a warning at startup if they do not.) Requests that are turned away before the password is looked at — unknown client, unregistered `redirect_uri` — are logged but do not count.
- **Success.** A successful login clears the account-wide counter and the counter for that account from that address, and gives the address back the one slot the attempt had taken. It does not erase failures the same address ran up before, and a lockout of the same account from a different address runs until its window ends.
- **Single-password mode.** With `TOOLMESH_AUTH_PASSWORD` there is one account, and the username typed into the form is not part of the credential. Every attempt counts against that account, whatever name was entered.
- **Scope of a lockout.** Only new password logins are refused. Access and refresh tokens that were already issued keep working, and so do API keys.
- **Shared passwords.** If one password is deliberately given to many people — a public demo login, say — the per-account ceiling lets anyone lock all of them out: 20 failed attempts spread over a few addresses refuse every new login for that account until the window ends. For such a deployment set `TOOLMESH_LOGIN_MAX_FAILURES_PER_USER=0` and keep the two per-address limits. The startup security-posture summary then lists that limit as switched off, which is expected here.
- **Where the counters live.** In Redis when it is connected, so the limits hold across replicas and survive a restart. Otherwise in process memory: per process, and reset by a restart. The startup log line `login throttling configured` shows which applies. If Redis fails while ToolMesh is running, a login that cannot reach it logs the warning `login throttle: Redis unavailable, falling back to process-local counters` and is counted in process memory rather than let through unlimited. A counter that was charged there stays there until its window ends, also after Redis is back, so what was counted during the outage keeps counting. The process-local table holds at most 50,000 counters. When it is full it drops expired counters first, then counters that have not reached their limit, and only if that is not enough, others; it logs `login throttle: process-local counter table is full, dropped live counters` at most once a minute.
- **Lifting a lockout early.** Delete the counters, e.g. `redis-cli --scan --pattern 'auth:{login}:failures:*' | xargs redis-cli del` (with the shipped Compose file, run `keydb-cli` inside the `keydb` service). Restart ToolMesh instead if it counts in process memory, or if the failures were counted there during a Redis outage.
- **Client address.** The per-address limits depend on the client address ToolMesh sees: the right-most public address in `X-Forwarded-For`, otherwise the peer address of the connection. Private, loopback and link-local entries in the header are skipped. IPv6 addresses are counted per `/64`. The `remote` field of the request log shows the address ToolMesh uses. For the per-address limits to mean what they say:
  - The proxy closest to ToolMesh must put the real client address last in `X-Forwarded-For`, and the ToolMesh port must not be reachable around the proxy — a client that connects directly can set the header itself.
  - If clients reach the proxy from private addresses (a LAN or VPN), the proxy must replace `X-Forwarded-For` with the peer address instead of appending to what the client sent. With an appending proxy such a client can choose the address it is counted under, because its own private address is skipped and the entry before it is used. With a replacing proxy those clients are all counted under the proxy's address.
  - Where the client address is not available — every request appears to come from the same address — all clients share the per-address counters. Raise or switch off the two per-address limits there and rely on the per-account ceiling. This does not combine with a shared password (above), which needs the per-address limits instead.

### Failed logins in the log

Every failed password login is logged at `WARN` with the message `login failed` and three fields: `username` (as submitted, truncated to 128 bytes), `remote` (the client address) and `reason`. The password is never logged. The username is logged as typed, so a password entered into the username field by mistake will appear there.

| `reason` | Meaning |
|----------|---------|
| `invalid_credentials` | Wrong password or unknown username. |
| `throttled_user_ip`, `throttled_user`, `throttled_ip` | Refused by the limit named above; the password was not checked. |
| `unknown_client`, `invalid_redirect_uri` | The OAuth client or its redirect URI is not registered; the password was not checked. |
| `password_login_disabled` | Neither `TOOLMESH_AUTH_PASSWORD` nor `users.yaml` is configured, so there is no password to log in with. Token requests at `/token` are refused for the same reason and logged as `token grant refused`; access tokens issued earlier are not honored. |

A bearer credential that is rejected on an authenticated endpoint (`/mcp`, `/files/upload`, `DELETE /blobs/…`) is logged as `bearer authentication failed` with `method`, `remote` and `reason`; the credential itself is never logged. `unknown_credential` is logged at `WARN`. `expired_token` and `unknown_token` — a value that has the form of an access token issued by this server, which is what an expired token looks like once it has been removed from the store — are the routine case and logged at `INFO`.

Failed logins are also counted in `toolmesh_logins_total{result="failure"}`; see [metrics.md](metrics.md).

## Audit

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_STORE` | `log` | Audit store: `log` (structured slog output, write-only) or `sqlite` (append-only SQLite database, queryable) |
| `AUDIT_RETENTION_DAYS` | `90` | Retention period in days for the sqlite store — entries older than this are automatically deleted |

## OpenFGA

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_API_URL` | `http://localhost:8080` | OpenFGA API endpoint. In Docker Compose use `http://openfga:8080` (set in `.env`). |
| `OPENFGA_STORE_ID` | *(empty)* | OpenFGA store ID (set by `./config/openfga/setup.sh`) |

## Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://keydb:6379/0` | KeyDB/Redis connection URL (Docker Compose service name: `keydb`) |

## Credential Store

Credentials are stored as environment variables with the `CREDENTIAL_` prefix.

| Variable | Description |
|----------|-------------|
| `CREDENTIAL_<LOGICAL_NAME>` | Credential value for the given logical name |

Example:
```bash
CREDENTIAL_MEMORIZER_API_KEY=sk-mem-xxxxx
CREDENTIAL_BRAVE_API_KEY=BSA-xxxxx
```

## Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_MCP_TIMEOUT` | `120` | HTTP client timeout in seconds for calls to downstream MCP servers |
| `TOOLMESH_EXEC_TIMEOUT` | `120` | Tool execution timeout in seconds — context deadline for a single backend call. Falls back to `TOOLMESH_ACTIVITY_TIMEOUT` if set (backwards compat). |
| `TOOLMESH_CODE_TIMEOUT` | `120` | Wall-clock budget in seconds for one `execute_code` run. Bounds a whole orchestration of `toolmesh.*` calls, so set it at least as high as the slowest backend timeout times the number of calls chained in one run (e.g. a committee of slow models). |

Increase these for backends that need more time, e.g. browser-based web fetchers processing heavy pages, or `execute_code` runs that fan out across several slow models:

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_EXEC_TIMEOUT=180
TOOLMESH_CODE_TIMEOUT=600
```

> Long tool calls no longer trip a "connector isn't responding" error: ToolMesh streams the `tools/call` response over SSE and emits keepalives while the backend works, so the MCP client's idle timer never fires mid-call. The per-request write deadline is also lifted for tool calls, so these timeouts — not the HTTP server's `WriteTimeout` — are the real bound.

## Backend Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_BACKENDS_CONFIG` | `/app/config/backends.yaml` | Path to backend configuration YAML |
| `TOOLMESH_POLICIES_DIR` | `/app/policies` | Path to output gate policy directory |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | Output format: `json` or `text` |
| `DEBUG_BACKENDS` | *(empty)* | Comma-separated backend names for per-backend debug file logging |
| `DEBUG_FILE` | *(empty)* | Path to the debug log file (e.g. `debug.log`). Both `DEBUG_BACKENDS` and `DEBUG_FILE` must be set to activate. |

**Secure default.** The default level is `info`, which does not log request payloads. Raise it to `debug` only while diagnosing an MCP communication issue: at `debug` level ToolMesh logs complete request URLs and request/response payloads, which for query-string API keys means the credential is written to the log. **Do not run `debug` in production.** Prefer the per-backend debug file (below) to scope tracing to a single backend without turning on global debug.

At `debug` level, ToolMesh logs the complete request/response flow between clients and backends:
- Incoming JSON-RPC method, params, and request ID
- Outgoing JSON-RPC results and errors
- Backend connection lifecycle (connect, discover, disconnect)
- Tool call parameters sent to MCP backends and their responses
- Executor pipeline steps (authz, credential injection, gate pre, execution, gate post)

### Per-backend debug file

When troubleshooting a specific backend, set `DEBUG_BACKENDS` and `DEBUG_FILE` to write debug-level output for only the named backends to a separate file. The file also includes the ToolMesh startup banner (version, commit, build date) so recipients have full context. Normal stdout logging continues at the global `LOG_LEVEL` unchanged.

```bash
DEBUG_BACKENDS=github
DEBUG_FILE=debug.log
LOG_LEVEL=error          # keep stdout quiet, debug goes to the file
```

The `./data` directory is typically volume-mounted to the host, so the debug file is directly accessible without `docker cp`.

## Docker Compose Databases

These variables are used by `docker-compose.yml` and do not affect the ToolMesh binary itself.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_DB_USER` | `openfga` | OpenFGA MySQL user |
| `OPENFGA_DB_PASSWORD` | `openfga` | OpenFGA MySQL password |
| `OPENFGA_DB_NAME` | `openfga` | OpenFGA MySQL database name |
| `MYSQL_ROOT_PASSWORD` | `rootpassword` | MySQL root password |
