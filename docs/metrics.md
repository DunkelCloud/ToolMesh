# Prometheus Metrics

ToolMesh exposes runtime metrics in Prometheus text format. The endpoint runs
on a **separate listener** so a Prometheus scraper does not need to traverse
the public, auth-protected MCP port.

## Endpoint

| Default                  | Path       | Notes                                  |
| ------------------------ | ---------- | -------------------------------------- |
| `:9090`                  | `/metrics` | Override with `TOOLMESH_METRICS_BIND`. |

The endpoint is unauthenticated by design (Prometheus scrapers typically can
not present bearer tokens). The shipped `docker-compose.yml` therefore binds the
**host** port to `127.0.0.1` by default, so it is never exposed on a public
interface. A Prometheus instance on the same Docker network still scrapes the
container directly by service name (it does not go through the host mapping). If
you scrape from another host, set `TOOLMESH_METRICS_HOST=0.0.0.0` to publish the
host port and firewall it yourself.

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
| `method` | `password`, `oauth_code`, `oauth_refresh`, `oauth_bearer`, `api_key`, `anonymous` |
| `result` | `success`, `failure`                                              |

- `password` — Password login at `/authorize` (username and password, or the
  single password).
- `oauth_code` — Authorization-code-to-token exchange at `/token`.
- `oauth_refresh` — Refresh-token grant at `/token`. Both grants also fail,
  and are counted, when the server has no password login configured.
- `oauth_bearer` — Validation of a bearer access token on each MCP request.
- `api_key` — API-key match (per-request, both file-based and legacy env-var auth).
- `anonymous` — A request without a bearer credential on an endpoint that
  authenticates (`/mcp`, `/files/upload`, `DELETE /blobs/…`). It is not a login
  of any method, so it has a label of its own.

`oauth_bearer` and `api_key` are recorded **per request**, so they double as
authenticated-request-rate metrics. Server-internal errors (failure to persist
a token, etc.) are logged but not counted as login failures.

What counts as a `failure`:

- `password` — every login attempt that was refused: a wrong password or
  unknown username, and an attempt turned away by the
  [failed-login limits](configuration.md#login-throttling) without the password
  being checked. Requests rejected before the login is attempted (unknown OAuth
  client, unregistered redirect URI) are logged but not counted.
- `oauth_bearer` and `api_key` — a request that presented a bearer credential
  which nothing accepted. Each such request is counted **once**. A rejected
  credential does not say which method the caller meant, so it is attributed by
  its form: an expired token, or a value that has the form of an access token
  issued by this server, counts as `oauth_bearer`; anything else counts as
  `api_key`. If only one of the two methods comes into question, every
  rejected bearer counts for that one: `oauth_bearer` when no API key is
  configured, `api_key` when there is no password login and therefore no
  access tokens are honored. A request without a bearer credential is not
  counted here, but as `anonymous`.

  Access tokens are 64 lowercase hex characters. An API key generated in the
  same form (`openssl rand -hex 32`, for example) cannot be told from one when
  it is rejected, so on a deployment that offers both password login and API
  keys a wrong key of that form is counted as `oauth_bearer`.

- `anonymous` — a request without a bearer credential that was turned away
  with `401`. This is what an MCP client sends before it has a token, so a
  small number accompanies every new connection; it is also what a scanner
  sends. This method is recorded with `result="failure"` only.

A request whose credential could not be checked — the token store failed, or
no [password hash comparison](configuration.md#password-hash-comparisons)
could be started — is answered `503` and counted nowhere: it is neither a
success nor a failure.

Access tokens expire after an hour, so a deployment with OAuth clients has a
small steady rate of `oauth_bearer` failures from clients presenting a token
that has just expired. Alert on a rate well above that baseline rather than on
any non-zero value.

### `toolmesh_tool_calls_total` (counter)

Tool invocations recorded by the executor, so individual backend calls made
from inside `execute_code`'s JS body are counted with their real backend/tool
labels rather than collapsed under `execute_code`. The MCP meta-tools
(`discover_tools`, `execute_code`, `tell_me_my_rights`, `request_grant`) are recorded at the
handler under the synthetic `builtin` backend so they remain visible in their
own right.

| Label     | Values                                                              |
| --------- | ------------------------------------------------------------------- |
| `backend` | Backend name (e.g., `hetzner`, `deepl`), `builtin` for `discover_tools`/`execute_code`/`tell_me_my_rights`/`request_grant`, or `unknown` for tools without a backend prefix. |
| `tool`    | Tool name without the backend prefix, or `*` if `TOOLMESH_METRICS_LABEL_TOOL=false`. |
| `result`  | `success`, `error`, `denied`                                        |

- `success` — completed without error.
- `error` — transport failure or `IsError=true` result from the backend.
- `denied` — blocked by the OpenFGA authorizer or by a pre/post output-gate policy.

### `toolmesh_tool_call_duration_seconds` (histogram)

End-to-end pipeline latency, from executor entry to result return (covers
AuthZ → credential injection → pre-gate → backend → post-gate). The
`discover_tools`, `execute_code`, `tell_me_my_rights` and `request_grant` meta-tools are timed
at the MCP handler level.

Buckets are tuned to typical REST-backend latencies:
`10ms, 50ms, 100ms, 500ms, 1s, 5s, 30s` plus `+Inf`.

| Label     | Values                                                              |
| --------- | ------------------------------------------------------------------- |
| `backend` | See above.                                                          |
| `tool`    | See above.                                                          |

### `toolmesh_codemode_scripts_total` (counter)

`execute_code` scripts by how they ended. All three series exist from the
start, at zero.

| Label     | Values                     |
| --------- | -------------------------- |
| `outcome` | `ok`, `error`, `timeout`   |

- `ok` — the script ran to completion without throwing.
- `error` — the script did not run to completion: the static analysis
  rejected it, it threw an exception it did not catch, it went over the budget
  of 50 tool calls, or the client canceled the request.
- `timeout` — the script ran out of its wall-clock budget
  (`TOOLMESH_CODE_TIMEOUT`).

### `toolmesh_codemode_swallowed_errors_total` (counter)

Scripts that ran to completion although a tool call in them failed. Inside
`execute_code` a failed tool call does not throw: the script gets the failure
as the call's value and runs on. This counter shows how often a script
finished regardless, possibly without the data it asked for. ToolMesh cannot
tell a script that checked the value from one that went on without it, so
both count. Scripts that end in `error` or `timeout` are not counted.

A script counts once per backend and reason, however many of its calls failed
that way; a script with failures from two backends counts once for each.

| Label     | Values                                                              |
| --------- | ------------------------------------------------------------------- |
| `backend` | The backend's configured name, `builtin` for `tell_me_my_rights` and `request_grant`, or `unknown` for a tool no backend claims. |
| `reason`  | `dispatch`, `coercion`, `tool_error`                                |

- `dispatch` — the call produced no result at all, for example a backend
  request that failed on the network or timed out. The script got
  `{error, tool}`.
- `coercion` — the arguments could not be converted to the types the tool
  declares. The call did not run; the script got `undefined`. Only the tools
  defined in the TypeScript files of the tools directory (`tools/`,
  `TOOLMESH_TOOLS_DIR`) are coerced. Tools of DADL and MCP backends pass their
  arguments on unchanged, so a wrong argument there comes back as an error
  result and counts as `tool_error`.
- `tool_error` — the call returned an error result: the backend reported an
  error (such as an HTTP error status), or authorization or a gate policy
  refused the call. The script got the error text or the parsed error body.

The series of every configured backend exist from the start, at zero. The
`backend` label is the name the backend is configured under, also when it
contains an underscore; `toolmesh_tool_calls_total` takes the backend from the
tool name up to the first underscore, so for such a backend the two labels
differ.

## Example queries

```promql
# Login attempts per second by method, last 5 minutes
sum by (method) (rate(toolmesh_logins_total[5m]))

# Failed login ratio (requests without any credential are left out)
sum(rate(toolmesh_logins_total{result="failure",method!="anonymous"}[5m]))
  / sum(rate(toolmesh_logins_total{method!="anonymous"}[5m]))

# Failed password logins in the last 15 minutes (guessing, or the limits engaging)
increase(toolmesh_logins_total{method="password",result="failure"}[15m])

# Rejected API keys in the last 15 minutes
increase(toolmesh_logins_total{method="api_key",result="failure"}[15m])

# Requests without any credential that were turned away, last 15 minutes
increase(toolmesh_logins_total{method="anonymous",result="failure"}[15m])

# Tool-call error+denied rate per backend
sum by (backend) (rate(toolmesh_tool_calls_total{result=~"error|denied"}[5m]))
  / sum by (backend) (rate(toolmesh_tool_calls_total[5m]))

# Authorization-denied calls per backend, last hour
sum by (backend) (increase(toolmesh_tool_calls_total{result="denied"}[1h]))

# p95 tool-call latency per backend
histogram_quantile(0.95,
  sum by (backend, le) (rate(toolmesh_tool_call_duration_seconds_bucket[5m])))

# execute_code scripts that finished despite a failed tool call, last 14 days,
# by backend and reason
sum by (backend, reason) (increase(toolmesh_codemode_swallowed_errors_total[14d]))

# Scripts by outcome over the same range, the base for the counts above
sum by (outcome) (increase(toolmesh_codemode_scripts_total[14d]))
```

## Scrape configuration

```yaml
scrape_configs:
  - job_name: toolmesh
    scrape_interval: 30s
    static_configs:
      - targets: ['toolmesh.internal:9090']
```
