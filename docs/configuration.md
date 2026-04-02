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

## Audit

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_STORE` | `log` | Audit store: `log` (structured slog output, write-only) or `sqlite` (append-only SQLite database, queryable) |
| `AUDIT_RETENTION_DAYS` | `90` | Retention period in days for the sqlite store — entries older than this are automatically deleted |

## OpenFGA

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_API_URL` | `http://localhost:8080` | OpenFGA API endpoint. In Docker Compose use `http://openfga:8080` (set in `.env`). |
| `OPENFGA_STORE_ID` | *(empty)* | OpenFGA store ID (set by `tm-bootstrap`) |

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
| `TOOLMESH_EXEC_TIMEOUT` | `120` | Tool execution timeout in seconds — context deadline for backend calls. Falls back to `TOOLMESH_ACTIVITY_TIMEOUT` if set (backwards compat). |

Increase these for backends that need more time, e.g. browser-based web fetchers processing heavy pages:

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_EXEC_TIMEOUT=180
```

## Backend Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_BACKENDS_CONFIG` | `/app/config/backends.yaml` | Path to backend configuration YAML |
| `TOOLMESH_POLICIES_DIR` | `/app/policies` | Path to output gate policy directory |

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `DEBUG_BACKENDS` | *(empty)* | Comma-separated backend names for per-backend debug file logging |
| `DEBUG_FILE` | *(empty)* | Path to the debug log file (e.g. `debug.log`). Both `DEBUG_BACKENDS` and `DEBUG_FILE` must be set to activate. |

## Docker Compose Databases

These variables are used by `docker-compose.yml` and do not affect the ToolMesh binary itself.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_DB_USER` | `openfga` | OpenFGA MySQL user |
| `OPENFGA_DB_PASSWORD` | `openfga` | OpenFGA MySQL password |
| `OPENFGA_DB_NAME` | `openfga` | OpenFGA MySQL database name |
| `MYSQL_ROOT_PASSWORD` | `rootpassword` | MySQL root password |
