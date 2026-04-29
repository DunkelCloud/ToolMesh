# Prometheus Metrics

ToolMesh exposes runtime metrics in Prometheus text format. The endpoint runs
on a **separate listener** so a Prometheus scraper does not need to traverse
the public, auth-protected MCP port.

## Endpoint

| Default                  | Path       | Notes                                  |
| ------------------------ | ---------- | -------------------------------------- |
| `:9090`                  | `/metrics` | Override with `TOOLMESH_METRICS_BIND`. |

The endpoint is unauthenticated by design (Prometheus scrapers typically can
not present bearer tokens). Bind it to a private interface or an internal
network when running in production.

## Configuration

| Env var                       | Default | Purpose                                                      |
| ----------------------------- | ------- | ------------------------------------------------------------ |
| `TOOLMESH_METRICS_ENABLED`    | `true`  | Disable the listener entirely.                               |
| `TOOLMESH_METRICS_BIND`       | `:9090` | `host:port` for the metrics listener.                        |
| `TOOLMESH_METRICS_LABEL_TOOL` | `true`  | When `false`, replaces the `tool` label with `*` to bound cardinality on deployments with many tools. |

## Metrics

### `toolmesh_logins_total` (counter)

Authentication / token-issuance events.

| Label    | Values                                                            |
| -------- | ----------------------------------------------------------------- |
| `method` | `oauth_code`, `oauth_refresh`, `oauth_bearer`, `api_key`          |
| `result` | `success`, `failure`                                              |

- `oauth_code` — Authorization-code-to-token exchange at `/token`.
- `oauth_refresh` — Refresh-token grant at `/token`.
- `oauth_bearer` — Validation of a bearer access token on each MCP request.
- `api_key` — API-key match (per-request, both file-based and legacy env-var auth).

`oauth_bearer` and `api_key` are recorded **per request**, so they double as
authenticated-request-rate metrics. Server-internal errors (failure to persist
a token, etc.) are logged but not counted as login failures — only failures
that originate from the credential are counted.

### `toolmesh_tool_calls_total` (counter)

Tool invocations recorded by the executor, so individual backend calls made
from inside `execute_code`'s JS body are counted with their real backend/tool
labels rather than collapsed under `execute_code`. The two MCP meta-tools
(`list_tools`, `execute_code`) are recorded at the handler under the synthetic
`builtin` backend so they remain visible in their own right.

| Label     | Values                                                              |
| --------- | ------------------------------------------------------------------- |
| `backend` | Backend name (e.g., `hetzner`, `deepl`), `builtin` for `list_tools`/`execute_code`, or `unknown` for tools without a backend prefix. |
| `tool`    | Tool name without the backend prefix, or `*` if `TOOLMESH_METRICS_LABEL_TOOL=false`. |
| `result`  | `success`, `error`, `denied`                                        |

- `success` — completed without error.
- `error` — transport failure or `IsError=true` result from the backend.
- `denied` — blocked by the OpenFGA authorizer or by a pre/post output-gate policy.

### `toolmesh_tool_call_duration_seconds` (histogram)

End-to-end pipeline latency, from executor entry to result return (covers
AuthZ → credential injection → pre-gate → backend → post-gate). The
`list_tools` and `execute_code` meta-tools are timed at the MCP handler level.

Buckets are tuned to typical REST-backend latencies:
`10ms, 50ms, 100ms, 500ms, 1s, 5s, 30s` plus `+Inf`.

| Label     | Values                                                              |
| --------- | ------------------------------------------------------------------- |
| `backend` | See above.                                                          |
| `tool`    | See above.                                                          |

## Example queries

```promql
# Login attempts per second by method, last 5 minutes
sum by (method) (rate(toolmesh_logins_total[5m]))

# Failed login ratio
sum(rate(toolmesh_logins_total{result="failure"}[5m]))
  / sum(rate(toolmesh_logins_total[5m]))

# Tool-call error+denied rate per backend
sum by (backend) (rate(toolmesh_tool_calls_total{result=~"error|denied"}[5m]))
  / sum by (backend) (rate(toolmesh_tool_calls_total[5m]))

# Authorization-denied calls per backend, last hour
sum by (backend) (increase(toolmesh_tool_calls_total{result="denied"}[1h]))

# p95 tool-call latency per backend
histogram_quantile(0.95,
  sum by (backend, le) (rate(toolmesh_tool_call_duration_seconds_bucket[5m])))
```

## Scrape configuration

```yaml
scrape_configs:
  - job_name: toolmesh
    scrape_interval: 30s
    static_configs:
      - targets: ['toolmesh.internal:9090']
```
