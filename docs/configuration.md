# ToolMesh Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and adjust values as needed.

## MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_PORT` | `8123` | Host-side port for Docker port mapping. The Go binary always listens on 8080 inside the container; this variable controls the `host:container` mapping in `docker-compose.yml`. |
| `TOOLMESH_TRANSPORT` | `http` | Transport mode: `http` or `stdio` |
| `TOOLMESH_CORS_ORIGINS` | *(empty)* | Comma-separated list of allowed CORS origins (e.g. `https://claude.ai,https://app.example.com`). If unset, any origin is reflected — fine for localhost, not for production. |
| `TOOLMESH_AUTH_PASSWORD` | *(empty)* | Password for OAuth 2.1 single-user authentication |
| `TOOLMESH_API_KEY` | *(empty)* | Static API key (bypasses OAuth when set). Used only when there is no `apikeys.yaml`; see [API Keys](#api-keys). |
| `TOOLMESH_AUTH_USER` | `owner` | User identity in simple auth mode (password/single API key) |
| `TOOLMESH_AUTH_PLAN` | `pro` | Plan in simple auth mode |
| `TOOLMESH_AUTH_ROLES` | `admin` | Comma-separated roles in simple auth mode |
| `TOOLMESH_ISSUER` | `https://toolmesh.io/` | OAuth issuer URL (must end with `/`). The default is a placeholder: set it to the public URL clients use, or the OAuth metadata and the [`401` challenge of `/mcp`](#unauthenticated-requests) name the wrong host. ToolMesh logs a warning at startup while it is unchanged. |
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
- **A login that could not be checked.** If the password comparison cannot be started because the server is at its [limit for password hash comparisons](#password-hash-comparisons), the login is answered `503` with `Retry-After` and the form is shown again. No password was looked at, so this is not a failed login: it is not counted and does not use up any of the limits.
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

## API Keys

`config/apikeys.yaml` (path: `TOOLMESH_APIKEYS_CONFIG`) gives every API key an identity of its own. An entry names its key in one of two ways:

| Field | Value | How a presented key is found |
|-------|-------|------------------------------|
| `key_sha256` | SHA-256 of the key, 64 hex characters | Table lookup. No bcrypt comparison, from the first request on. |
| `key_hash` | bcrypt hash of the key | By bcrypt comparison the first time the key is presented after startup, table lookup from then on. |

```yaml
keys:
  - key_sha256: "<SHA-256 of the key, 64 hex characters>"
    user_id: my-agent
    company_id: my-company
    plan: pro
    roles: [tool-executor]
    caller_id: my-agent
```

Generate a key and the value for `key_sha256`:

```bash
KEY="tm_$(openssl rand -hex 32)"
printf '%s' "$KEY" | sha256sum | cut -d' ' -f1
```

The prefix is not required. It keeps a key from looking like an access token, which is 64 hex characters: a wrong key that has that form is logged and counted as an unknown token instead of as a rejected API key (see [metrics.md](metrics.md)).

- **Existing files keep working unchanged.** A file that has only `key_hash` entries needs no migration, and the keys themselves stay the same in either form.
- **Use `key_sha256` for randomly generated keys only.** SHA-256 is fast, which is what makes the lookup cheap. For a random key of 128 bits or more that costs nothing: it cannot be guessed, however fast the hash. A key that a person chose, or a short one, could be guessed from a leaked `apikeys.yaml` far faster than through bcrypt. Keep such a key as `key_hash`, or better, replace it with a random one.
- **What a `key_hash`-only entry still costs.** A bcrypt hash cannot be put into the lookup table when the file is loaded, because it does not reveal the key. Until the key of such an entry has been used once since startup, the entry is *unseen*: a bearer credential that nothing else recognizes is compared against every unseen entry, in file order, one bcrypt comparison each. That applies to the first use of the key itself and to any value that is no credential at all. Entries whose key has been used, and entries with a `key_sha256`, are never compared again. An entry stays unseen for as long as its key is not presented: a key nobody uses, or a second entry for a key that an earlier entry already matches.
- **How that cost is bounded.** Requests that need these comparisons are admitted one at a time and wait in a queue of their own, so they occupy at most one of the [comparison slots](#password-hash-comparisons) and cannot keep password logins from theirs. A request waits up to 5 seconds for its turn and, once admitted, up to 5 seconds in total for the slots of its comparisons. When more than 64 such requests are waiting, or the wait runs out, the request is answered `503` with `Retry-After`. Under a flood of made-up bearer credentials this is what the first use of a `key_hash`-only key can run into; keys that were used before, keys with a `key_sha256`, access tokens and password logins are not affected.
- **Removing it.** Add `key_sha256` to the entry. `key_hash` may stay next to it; it is then not used, and the file still works with a version that does not know `key_sha256`. At startup ToolMesh logs how many entries are in which form, with a warning if any have only a `key_hash`.
- **Validation at startup.** A `key_sha256` that is not 64 hex characters, or that two entries share, stops the server. An entry with neither a `key_sha256` nor a `key_hash` that bcrypt can work on matches no key; it is reported in a warning with its `user_id`.
- **Keys of 72 bytes or more with `key_hash`.** bcrypt reads only the first 72 bytes of a key, so different values that agree in those bytes match the same hash. Such an entry accepts the first of them that is presented after startup and only that one from then on. Keys shorter than 72 bytes are not affected. `key_sha256` covers the whole key.

Without an `apikeys.yaml`, the single key in `TOOLMESH_API_KEY` applies. It is compared in constant time, independent of its length.

A bearer credential is checked in this order: the lookup table of the API keys (or the single `TOOLMESH_API_KEY`), then the access tokens in the token store, and only then, by bcrypt comparison, the `key_hash`-only entries that have not been seen yet. A valid access token therefore never costs a bcrypt comparison, and an API key does not depend on the token store being reachable.

## Unauthenticated Requests

A request to `/mcp` without a valid credential is answered `401 Unauthorized` with a challenge that points to the OAuth protected resource metadata of the endpoint ([RFC 9728](https://www.rfc-editor.org/rfc/rfc9728), as the [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) asks of a server):

```
WWW-Authenticate: Bearer realm="toolmesh", resource_metadata="https://toolmesh.example.com/.well-known/oauth-protected-resource/mcp"
```

If the request carried a bearer credential that was rejected, for example an expired access token, the challenge also contains `error="invalid_token"`. The body is the JSON-RPC error `-32001` (`Unauthorized`). MCP clients act on the status: they start the OAuth flow, or refresh an expired token and retry.

- **Metadata.** `/.well-known/oauth-protected-resource/mcp` describes the MCP endpoint; its `resource` is `TOOLMESH_ISSUER` followed by `mcp`. Clients compare that value with the URL they connect to, so `TOOLMESH_ISSUER` has to be the public URL clients use. `/.well-known/oauth-protected-resource` is served as before.
- **Reverse proxies** must pass the `401` status and the `WWW-Authenticate` header through unchanged.
- **Browsers.** For origins in `TOOLMESH_CORS_ORIGINS` the `WWW-Authenticate` header is exposed (`Access-Control-Expose-Headers`), so that an MCP client running in a browser can read the challenge.
- **`503` is not `401`.** A request whose credential could not be checked right now, because the token store failed or because no [password hash comparison](#password-hash-comparisons) could be started, is answered `503 Service Unavailable` with `Retry-After`. That says nothing about the credential; answering `401` would make a client discard a token that is still good.
- **In the log.** Every request that `/mcp` turns away is logged at `INFO` as `mcp request rejected: unauthorized`, with `remote` (the client address) and `credential`: `none` for a request without a bearer credential, `rejected` for one whose credential was not accepted. The latter also has its `bearer authentication failed` line (see [above](#failed-logins-in-the-log)).
- **In the metrics.** A request without a bearer credential is counted in `toolmesh_logins_total{method="anonymous"}`; see [metrics.md](metrics.md).

`/files/upload` and `DELETE /blobs/…` answer `401` with `WWW-Authenticate: Bearer realm="toolmesh"` as before, and `503` in the same cases.

## Password Hash Comparisons

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_BCRYPT_MAX_CONCURRENT` | half of the CPUs available to the process, at least `1` | How many bcrypt comparisons may run at the same time, across the whole process. Must be a positive integer; anything else stops the server at startup. |

bcrypt is slow on purpose: one comparison keeps one CPU core busy for tens of milliseconds, and longer at a higher cost. Two kinds of request ask for one:

- a password login with `users.yaml`, for an unknown username as well, which is compared against a dummy hash so that it takes as long as a wrong password;
- a bearer credential that has to be compared against `key_hash`-only API key entries (see [API Keys](#api-keys)).

Access tokens, API keys with a `key_sha256`, `TOOLMESH_API_KEY` and `TOOLMESH_AUTH_PASSWORD` never need one. The limit keeps the first group from taking the CPU away from the second: however many logins or unknown credentials arrive at once, no more than this many cores are busy hashing.

The two kinds do not compete on equal terms. A bearer credential costs nothing to send, so the requests that need a comparison for one are admitted one at a time and wait in a queue of their own (see [API Keys](#api-keys)): together they use at most one slot, and they cannot fill the queue a password login waits in. With a limit of `1`, a login waits for at most the one comparison that is running.

A comparison that finds every slot taken waits up to 5 seconds for a free one. If none becomes free in that time, or 64 comparisons per slot are already waiting, the request is answered `503` with `Retry-After: 1` — on the login form with a note that the server is busy, on `/mcp` as a JSON-RPC error — and logged at `WARN` as `authentication deferred: no password hash comparison could be started`, with `method` and `remote`. The credential was not checked, so the request is not a failed login: it is not counted in `toolmesh_logins_total` and does not use up the [failed-login limits](#login-throttling).

The default is half of the CPUs the process may use (in a container with a CPU limit, half of that limit), and at least one. Raise it on a deployment where many people log in with passwords at the same moment; lower it to reserve more of the machine for tool calls. There is no value that switches the limit off. The startup log line `bcrypt comparisons bounded` shows the value in effect.

## Audit

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_STORE` | `log` | Audit store: `log` (structured slog output, write-only) or `sqlite` (append-only SQLite database, queryable) |
| `AUDIT_RETENTION_DAYS` | `90` | Retention period in days for the sqlite store — entries older than this are automatically deleted |

Both stores keep an entry's metadata; the `log` store writes it as a
`metadata` object in the `audit` line. It carries what the fixed fields
cannot: for kit grants the approver, the grant id and the kit, and for a
request the reason and the duration asked for (`ttl_requested`); for a call
the kits the caller held (`held_kits`), and for a denial the kits that would
have allowed it (`remedy_kits`).

## Authorization

Every tool call is checked before it runs: a direct call, each `api.*` call
inside a composite, and every tool listing (`tools/list`, `discover_tools`,
`toolmesh.discover` in Code Mode), which shows only the tools the caller may
execute, and in discovery also those a [kit](#kits) covers. A denied call
returns an error result and is audited with status `denied`. Callers can ask
what they may do with the meta-tool
[`tell_me_my_rights`](#asking-what-a-caller-may-do-tell_me_my_rights), and ask
for a kit with [`request_grant`](#granting-kits).

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_AUTHZ_MODE` | `embedded` | `embedded`: ToolMesh runs the checks itself, on a database in the data directory. `external`: checks go to an OpenFGA server you operate. `disabled`: no checks (see [below](#disabling-authorization)). |
| `TOOLMESH_AUTHZ_PRESET` | *(chosen at startup)* | Embedded mode: preset grants, `single-user`, `team` or `open` (see [Presets](#presets)). Ignored while the grants file exists. |
| `TOOLMESH_AUTHZ_CONFIG` | `/app/config/authz.yaml` | Embedded mode: the grants file. When it exists, its grants replace the preset. |
| `OPENFGA_API_URL` | `http://localhost:8080` | External mode: OpenFGA API endpoint. In Docker Compose use `http://openfga:8080`. |
| `OPENFGA_STORE_ID` | *(empty)* | External mode: store ID, required. |
| `OPENFGA_MODE` | *(empty)* | Deprecated. Read only while `TOOLMESH_AUTHZ_MODE` is not set: `restrict` selects `external`, `bypass` selects `embedded` and counts as an [upgrade](#upgrading-an-installation-that-ran-without-authorization). ToolMesh logs a warning while it is set. |

### Embedded mode

Nothing needs to be installed or set up. ToolMesh runs
[OpenFGA](https://openfga.dev) inside its own process and keeps its data in
`authz.db` in the data directory (`TOOLMESH_DATA_DIR`, default `/app/data`), next to a small
marker file, `.authz-bootstrap`. On the first start it creates the store and
the authorization model; a later version that changes the model writes the new
one on its first start. The data directory must be writable and should be
persistent, as it is in the shipped `docker-compose.yml`.

Who may call which tool is decided by **grants**. A grant names a subject and
what it may call. Subjects are the users, roles, plans and companies that
ToolMesh already knows from authentication: `username`, `roles`, `plan` and
`company` in `users.yaml`, `user_id`, `roles`, `plan` and `company_id` in
`apikeys.yaml`, and `TOOLMESH_AUTH_USER`, `TOOLMESH_AUTH_ROLES` and
`TOOLMESH_AUTH_PLAN` for the single password or API key. There is nothing to
keep in sync: a user who is moved to another plan in `users.yaml` is checked
against the grants of that plan with the next call.

The grants come from the first of these that applies:

1. the grants file (`TOOLMESH_AUTHZ_CONFIG`), when it exists;
2. the preset named in `TOOLMESH_AUTHZ_PRESET`;
3. the preset `open`, for an [upgraded installation](#upgrading-an-installation-that-ran-without-authorization);
4. the preset `team` when `users.yaml` or `apikeys.yaml` exists, otherwise
   `single-user`.

The log line `authorization policy applied` shows the preset, where the grants
came from (`file`, `env`, `upgrade`, `default`) and how many there are.

#### Presets

| Preset | Who may call what |
|--------|-------------------|
| `single-user` | The owner (`TOOLMESH_AUTH_USER`, default `owner`) and every caller with the role `admin`: every tool. Nobody else: nothing. |
| `team` | As `single-user`, and plan `pro`: every tool; plan `free`: every tool whose DADL access classification is `read`. |
| `open` | Every authenticated caller: every tool. Reported as a relaxed control in the security-posture summary. |

With the defaults of the single password or API key (user `owner`, plan `pro`,
role `admin`), every preset lets that caller use every tool, as before.

#### Grants file

Copy `config/authz.yaml.example` to `config/authz.yaml`:

```yaml
preset: single-user        # optional: start from a preset

grants:
  - plan: pro
    backends: [github, deepl]
  - plan: free
    access: [read]
  - role: support
    tools: [zammad_list_tickets, zammad_get_ticket]
  - company: acme
    backends: [netbox]
  - user: alice
    all_tools: true

denies:                    # optional: blocks that win over every grant
  - user: alice
    tools: [stripe_create_refund]
  - role: contractor
    backends: [stripe]
```

Each grant names exactly one subject (`user`, `role`, `plan`, `company`, or
`everyone: true` for every authenticated caller) and at least one target:

- `all_tools: true`: every tool, including tools of backends added later.
- `backends`: every tool of these backends, by their name in `backends.yaml`
  (`echo` for the built-in tools). A grant covers the backend a call is
  actually routed to: with the backends `web` and `web_search`, a grant on
  `web` does not cover `web_search_query`.
- `tools`: single tools by their full name, `<backend>_<tool>`.
- `access`: every tool whose DADL access classification is one of these
  (`read`, `write`, `admin`, `dangerous`, or a custom value). Tools without a
  classification, which includes most tools of MCP backends, are not covered.

A **deny** has the same form as a grant and blocks what it names for its
subject, whatever any grant or the preset allows: a deny always wins. Use it to
take single tools or backends away from a subject that otherwise has all of
them, for example `alice` above, who keeps every tool except
`stripe_create_refund`. A denied tool is refused with an error, audited as
`denied`, and no longer listed for that caller. Only the grants file has
denies; presets have none.

ToolMesh reads the file at startup and again within a few seconds of every
change, including when it is created or removed. A file that does not parse,
or a grant or deny that names no subject or no target, stops the server at
startup; on a later change it is reported in the log and the rules stay as
they were. Calls that start after a change has been applied are checked
against the new rules. While a change is applied, no call is allowed that
neither the old nor the new rules allow.

#### Kits

A **kit** is a named bundle of tools that a caller is granted as a whole and
for a limited time, instead of tool by tool: for example everything a network
diagnosis needs to read. Kits are defined in the grants file:

```yaml
kits:
  net-diag-read:
    description: "Network diagnosis (read-only)"
    warning: "Production systems."
    grants: [graylog:read, unifi:read, netbox:read, checkmk:read]
    tools: [netbox_get_device]
    ttl_default: 4h
    ttl_max: 24h
```

- `description` (required): what the kit is for, in plain language. It is
  what callers see, and what a person granting the kit reads.
- `warning`: shown with the description.
- `grants`: what the kit covers, as scopes. `"*"`: every tool. `<backend>`:
  every tool of a backend. `<backend>:<access>`: the tools of a backend with
  this DADL access classification. `"*:<access>"`: the tools with this
  classification on any backend. Quote scopes that start with `*`.
- `tools`: single tools by their full name, `<backend>_<tool>`.
- `ttl_default`, `ttl_max`: how long a grant of the kit lasts by default and
  at most (`10m`, `4h`). Shown to callers. A kit without `ttl_max` is granted
  for at most 24 hours, so its `ttl_default` must not exceed that.

Kit names are slugs: letters, digits, `.`, `_` and `-`, at most 64
characters. In the authorization model a kit is a role. Its holders may
execute what it covers, and holding it is passed with each check, so a kit
ends without anything to clean up. A deny wins over a kit as over every grant.
`<backend>:<access>` covers exactly the tools of that backend with that
classification: holding a kit for `graylog:read` and one for `unifi:write`
does not add up to `graylog:write`.

A kit allows nothing by itself: a caller holds it once an approver has
approved its request, until the grant ends (see [Granting kits](#granting-kits)).
The definitions also shape what callers are told:

- Discovery (`discover_tools`, `toolmesh.discover`, `toolmesh.describe`) lists
  the tools a kit covers along with those the caller may call, marked
  `grant_required: kit <name>`. Kits therefore also decide which tools a
  caller sees without being allowed to call them; a tool that no kit covers
  stays hidden from a caller who may not call it.
- A denied call names the kits that would allow it, and the audit entry of the
  denial records them (`remedy_kits`).
- [`tell_me_my_rights`](#asking-what-a-caller-may-do-tell_me_my_rights) gives
  the kits per tool and the smallest set that covers a task.

Kits apply in embedded mode only. An invalid kit is reported like an invalid
grant.

#### Granting kits

A caller asks for a kit with the meta-tool `request_grant`, a person approves
the request, and the caller holds the kit until the grant ends. The
authorization engine stays the only place that decides: at every check, the
kits the caller holds are passed with the check, like its roles. A grant
therefore ends by itself, and revoking it takes effect with the next call.

**Approvers** are listed in the grants file. Each has a name and a key of its
own: the SHA-256 of a bearer key for the [approver API](#approver-api), a
signing address for the [approval page](#approval-page), or both:

```yaml
approvers:
  - name: alice@example.com
    key_sha256: "<SHA-256 of the key, 64 hex characters>"
  - name: bob@example.com
    address: bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw
```

```bash
key=$(openssl rand -hex 32)   # the approver's key; hand it over securely
printf %s "$key" | sha256sum  # the key_sha256 for the grants file
```

The `address` is a native segwit P2WPKH address (`bc1q…`; `tb1q…` and
`bcrt1q…` work as well). The approver signs with its private key; ToolMesh
stores only the address and never sees the key. No coins and no blockchain are
involved: the key only signs statements (BIP-322). Make one on the approval
page under "Set up a signing key" (`https://<toolmesh>/approve/`), or use the
address of a native segwit account of a wallet that signs BIP-322 messages.
Taproot (`bc1p…`) and script addresses are refused.

An approver key works only on the approver API below, and the credentials MCP
callers connect with do not work there, so an agent cannot approve its own
request. Do not give an agent an approver key or signing key. An approver whose key is also
an MCP credential is refused: `TOOLMESH_API_KEY`, `TOOLMESH_AUTH_PASSWORD` or
an entry of `apikeys.yaml` with a `key_sha256`. An `apikeys.yaml` entry with
only a `key_hash` cannot be compared, so never reuse such a key either. Names
are slugs or e-mail addresses; neither names, keys nor addresses may repeat.
Without approvers, `request_grant` tells callers that no kit can be granted,
and ToolMesh logs a warning when the file defines kits.

Changes to `approvers:` apply within seconds, like the rest of the file. An
edit that cannot be applied, because the file does not parse, an approver is
refused or writing the rules fails, stops the server at startup; later, it is
logged and the previous approvers stay in force, as grants and denies do.
ToolMesh tries again only when the file changes again. After removing an
approver key that may have leaked, check that the log shows the line
`authorization policy applied` for that edit, with the new number of
`approvers`; until then the old key still approves.

**Asking.** `request_grant({kit, reason, ttl})`. ToolMesh lists it as an MCP
tool only while kits are defined, and many clients keep the tool list they got
when they connected. Inside `execute_code` the same calls are always there:
`toolmesh.request_grant({...})` and `toolmesh.tell_me_my_rights({...})`.

- `kit`: the kit's name, as `tell_me_my_rights` names it.
- `reason` (required, at most 500 characters): the task and, if there is one,
  the ticket. Approvers see it marked as the requester's own statement. Line
  breaks become spaces; control and format characters (such as bidirectional
  overrides and zero-width characters) are removed.
- `ttl` (optional, such as `30m` or `4h`): how long the caller needs the kit.
  Without it the kit's `ttl_default` applies, or one hour; no more than its
  `ttl_max` is granted, or 24 hours when it sets none. The maximum counts as
  it is when the request is approved.

The answer is a request id of ten characters and a fingerprint such as
`0873-D5E5-9D1B-2DB7`, which the caller hands to the person it works for.
When an approver has a signing address and `TOOLMESH_ISSUER` is set to the
address ToolMesh is reached at, the answer also carries `approval_url`, the
link to the [approval page](#approval-page). A request waits 30 minutes for a
decision, then lapses. Asking again for a kit that is still pending returns
the pending request; a caller may have at most five requests pending at a
time. With the request, ToolMesh records for each entry of the kit how many
tools it covers and how many of them the caller cannot call yet; approvers
see these counts.

**Who holds a grant.** The requesting user, as the caller it connected as:
the `caller_id` of an API key, or the OAuth client. An API key without
`caller_id` binds the grant to that key itself (shown as `grant_key`), so two
such keys of one user do not share grants. The grant survives a token
refresh; other connections of the same user do not hold it. A grant of the
whole kit with an approver key gives the kit as it is defined at the time of
each call: a kit removed from the file allows nothing any more, and a changed
kit applies with its new content. A grant of **part of a kit** (some of its
`grants` scopes and `tools`) and every grant approved on the approval page
cover the entries the approval named and no others: entries removed from the
kit later allow nothing, entries added later are not part of it. A deny wins
over a part as over a kit.

**Where grants live.** In Redis when ToolMesh is connected to one
([`REDIS_URL`](#redis)): requests and grants survive a restart and are shared
between instances. Otherwise in process memory: a restart ends all requests
and grants, and every caller is back to its steady-state rights. A store that
fails is logged and contributes no kits.

**Audit.** Every request, approval, denial and revocation is recorded, with
backend `toolmesh` and the tool `request_grant`, `grant_approve`,
`grant_deny` or `grant_revoke`. The entry carries the user and caller the
grant is for, and in its metadata the grant id, kit, duration, expiry and, for
the approver actions, the approver. An approval records how it was given
(`approved_with`: `key` or `signature`) and, for part of a kit, the entries
granted (`part_grants`, `part_tools`). An approval on the approval page also
records the address, the signature, the statement and its SHA-256
(`statement_sha256`), so that it can be verified later; a refused signature is
recorded as an error. A call made while the caller holds kits records them in
its metadata (`held_kits`, a kit held in part marked `(part)`).

#### Approver API

On the ToolMesh port, with the approver key as bearer credential:

| Request | Effect |
|---------|--------|
| `GET /grants` | Pending requests and active grants |
| `GET /grants/<id>` | One request or grant |
| `POST /grants/<id>/approve` | Grant the kit. Optional body: `{"ttl": "1h"}` to grant it for less than requested, never for more; `{"grants": ["graylog:read"], "tools": [...]}` to grant only these entries of the kit, exactly as the kit lists them |
| `POST /grants/<id>/deny` | Reject a pending request |
| `POST /grants/<id>/revoke` | End an active grant now |

```bash
curl -s -H "Authorization: Bearer $APPROVER_KEY" https://toolmesh.example.com/grants/k3m9x2p7qa
curl -s -X POST -H "Authorization: Bearer $APPROVER_KEY" https://toolmesh.example.com/grants/k3m9x2p7qa/approve
```

Each request and grant shows the kit's description, warning and scope from
the grants file next to who asked, why, and for how long, and a pending
request its fingerprint, tool counts and approval link. Like the reason,
`caller_name` is the requester's own statement: an OAuth client chooses its
name itself. It is cleaned like the reason and cut to 128 characters. Approving a kit the
caller already holds replaces that grant. A grant keeps its request id, so
the same id revokes it, whether it was approved here or on the approval page.

#### Approval page

`https://<toolmesh>/approve/<id>` shows a pending request to whoever has the
link and lets an approver with a signing address approve it. The page needs
no login: approving takes a signature by the key of an approver's address.

- **What it shows** comes from ToolMesh: the kit's description and warning,
  its entries grouped by what they allow (every access class first, then
  dangerous, admin, other, write, read), and per entry the tools it covers and
  how many of them are new to the caller. The reason and the client name are
  shown as the requester's own statements. Whom the grant is for (user and
  connection), the duration asked for and the fingerprint are shown
  prominently. Compare the fingerprint with the one the agent reported, over
  the channel you work with it in, to know that the link shows its request.
- **Narrowing.** Untick entries the task does not need and pick a shorter
  duration. The grant then covers only the ticked entries.
- **The statement.** For these choices ToolMesh writes a statement, plain
  text that names this ToolMesh, the request and its nonce, the approver and
  address, the kit, the entries granted and left out, the duration, whom the
  grant is for and the reason. The page shows it as it is, and it is what is
  signed. ToolMesh writes it again from the stored request to verify the
  signature, so nothing the page or the requester adds can change it.
- **Signing.** Paste the private key (WIF or 64 hex characters) to sign in
  the page; the key stays in the browser and only the signature is sent.
  Or copy the statement into a wallet that signs BIP-322 messages and paste
  the signature (with or without the `smp` prefix). On a page served over
  plain HTTP (other than localhost) the key field is disabled: use HTTPS.
- **Once.** A signature approves its request once: approving takes the
  request from the store, and a statement names one request and its nonce.
- **Limits.** Refused approvals (a signature that does not verify, or
  choices that do not fit the request) are limited within 15 minutes to 5 per
  request and source address, 10 per request and 20 per source address;
  beyond that the page answers `429` with `Retry-After`. A successful
  approval clears the request's counters. The counters work like those of
  [login throttling](#login-throttling), with the same source address
  (right-most public address in `X-Forwarded-For`) and in Redis when it is
  connected, but apart from them: refused signatures never use up the login
  limits.

The page loads only its own style sheet and scripts, which are part of the
ToolMesh binary (Content Security Policy `default-src 'none'`, no other
origin, no framing). Messengers that show link previews get a summary from
ToolMesh (kit, user, duration, tool counts, fingerprint), never the reason.
`/approve/` without an id offers the key setup only.

Set `TOOLMESH_ISSUER` to the address approvers reach ToolMesh at; it is the
base of the links in `request_grant` and the ToolMesh a statement names.
Without it, `request_grant` gives no link, and statements name the address
the page was loaded from.

#### Upgrading an installation that ran without authorization

Up to version 0.4, authorization was off unless `OPENFGA_MODE=restrict` was
set. So that an upgrade does not lock anybody out, ToolMesh treats the first
start of the embedded engine as an upgrade when `TOOLMESH_AUTHZ_MODE` is not
set and either `OPENFGA_MODE=bypass` is set or the data directory already holds
state from an earlier run. It then records the preset `open`, logs a warning,
and reports it in the security-posture summary on every start: every
authenticated caller may still call every tool. The record stays until you set
`TOOLMESH_AUTHZ_PRESET` or write a grants file.

To have an upgraded installation start with the restrictive defaults instead,
set `TOOLMESH_AUTHZ_MODE=embedded` before the first start of the new version,
or set `TOOLMESH_AUTHZ_PRESET`.

#### Operations

- **Back up** `authz.db` and `.authz-bootstrap` with the rest of the data
  directory. The grants are written from configuration at every start, so a
  lost `authz.db` is created again without losing anything; the marker file
  keeps the upgrade decision of the first start, so an existing data directory
  is not taken for an upgrade a second time.
- **One process per data directory.** Two ToolMesh instances must not share
  one `authz.db`.
- **Cost.** A check takes about 0.5 to 0.6 ms. A tool listing does not check
  every tool on its own: tools without grants or denies of their own that
  share a backend and access classification are decided once, so filtering a
  listing of 3,000 tools takes about 115 ms.

### External mode

`TOOLMESH_AUTHZ_MODE=external` sends every check to an OpenFGA server you
operate (`OPENFGA_API_URL`, `OPENFGA_STORE_ID`), for example one that several
applications share. ToolMesh only reads from it: it writes neither a model
nor a tuple, and presets and the grants file do not apply. Each check asks
whether `user:<user ID>` has the relation `can_execute` on
`tool:<backend>_<tool>`; the model and tuples are yours.
`config/openfga/` holds an example model, tuples and a setup script.

### Disabling authorization

`TOOLMESH_AUTHZ_MODE=disabled` is the only way to switch the checks off.
Every authenticated caller may then call every tool. Authentication still
applies. ToolMesh reports it in the security-posture summary on every start
and records an audit entry with the status `authz_disabled` (tool
`toolmesh_authz`), so the audit trail shows from when on calls went
unchecked.

### Asking what a caller may do: `tell_me_my_rights`

Next to `discover_tools` and `execute_code`, ToolMesh lists the meta-tool
`tell_me_my_rights`. It tells the caller what it may do and decides nothing:
every call is checked again when it runs.

- Without arguments: per backend, how many tools the caller may call, how
  many a kit would add, and which kits.
- `backend: "<name>"`: the verdict for each tool of that backend.
- `tools: [...]`, the preflight (at most 500 tools): one verdict per tool,
  `allowed`, `escalatable` with the kits that would allow it, or `denied`,
  and the smallest set of kits found that covers every escalatable tool. An
  agent that checks all tools of a task first can then ask once for what it
  lacks, instead of collecting denials call by call.

Every answer also lists the kits the caller holds (`grants`, with id, expiry
and time remaining) and its pending requests (`requests`), and describes these
kits with their warnings.

The answer shows only the tools the caller may call or get through a kit.
For any other tool it says `denied`, without telling whether the tool exists.
Every call is recorded in the audit trail (tool `tell_me_my_rights`, backend
`toolmesh`): the answer is the first thing an agent that was taken over would
look up. In external mode there are no kits, so the verdicts are `allowed` and
`denied`; with authorization disabled, every tool is `allowed`.

## Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://keydb:6379/0` | KeyDB/Redis connection URL (Docker Compose service name: `keydb`). Also holds kit requests and grants (see [Granting kits](#granting-kits)) |

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

These variables are used by `docker-compose.yml` and do not affect the ToolMesh binary itself. The `OPENFGA_DB_*` and `MYSQL_*` variables matter only for the optional OpenFGA services of [external mode](#external-mode).

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENFGA_DB_USER` | `openfga` | OpenFGA MySQL user |
| `OPENFGA_DB_PASSWORD` | `openfga` | OpenFGA MySQL password |
| `OPENFGA_DB_NAME` | `openfga` | OpenFGA MySQL database name |
| `MYSQL_ROOT_PASSWORD` | `rootpassword` | MySQL root password |
