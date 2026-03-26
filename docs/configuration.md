# ToolMesh Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and adjust values as needed.

## MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_PORT` | `8080` | HTTP port for the MCP server |
| `TOOLMESH_TRANSPORT` | `http` | Transport mode: `http` or `stdio` |
| `TOOLMESH_AUTH_PASSWORD` | *(empty)* | Password for OAuth 2.1 single-user authentication |
| `TOOLMESH_API_KEY` | *(empty)* | Static API key (bypasses OAuth when set) |
| `TOOLMESH_AUTH_USER` | `owner` | User identity in simple auth mode (password/single API key) |
| `TOOLMESH_AUTH_PLAN` | `pro` | Plan in simple auth mode |
| `TOOLMESH_AUTH_ROLES` | `admin` | Comma-separated roles in simple auth mode |
| `TOOLMESH_ISSUER` | `https://toolmesh.io/` | OAuth issuer URL (must end with `/`) |

## Temporal

| Variable | Default | Description |
|----------|---------|-------------|
| `TEMPORAL_ADDRESS` | `localhost:7233` | Temporal server address |
| `TEMPORAL_NAMESPACE` | `default` | Temporal namespace |
| `TEMPORAL_TASK_QUEUE` | `toolmesh` | Temporal task queue name |

## OpenFGA

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_API_URL` | `http://localhost:8080` | OpenFGA API endpoint |
| `OPENFGA_STORE_ID` | *(empty)* | OpenFGA store ID (set by `tm-bootstrap`) |

## Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |

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
| `TOOLMESH_ACTIVITY_TIMEOUT` | `120` | Temporal activity StartToClose timeout in seconds for tool execution |

Increase these for backends that need more time, e.g. browser-based web fetchers processing heavy pages:

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_ACTIVITY_TIMEOUT=180
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

## Docker Compose Databases

These variables are used by `docker-compose.yml` and do not affect the ToolMesh binary itself.

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_USER` | `postgres` | PostgreSQL superuser (used by Temporal) |
| `POSTGRES_PASSWORD` | `postgres` | PostgreSQL superuser password |
| `TEMPORAL_DB_USER` | `temporal` | Temporal database user |
| `TEMPORAL_DB_PASSWORD` | `temporal` | Temporal database password |
| `OPENFGA_DB_USER` | `openfga` | OpenFGA MySQL user |
| `OPENFGA_DB_PASSWORD` | `openfga` | OpenFGA MySQL password |
| `OPENFGA_DB_NAME` | `openfga` | OpenFGA MySQL database name |
| `MYSQL_ROOT_PASSWORD` | `rootpassword` | MySQL root password |
