# ToolMesh Configuration

All configuration is done via environment variables. Copy `.env.example` to `.env` and adjust values as needed.

## MCP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_PORT` | `8123` | Host-side port for Docker port mapping. The Go binary always listens on 8080 inside the container; this variable controls the `host:container` mapping in `docker-compose.yml`. With [built-in TLS](#tls) set it to `443`. |
| `TOOLMESH_TRANSPORT` | `http` | Transport mode: `http` or `stdio` |
| `TOOLMESH_CORS_ORIGINS` | *(empty)* | Comma-separated list of allowed CORS origins (e.g. `https://claude.ai,https://app.example.com`). If unset, any origin is reflected — fine for localhost, not for production. |
| `TOOLMESH_AUTH_PASSWORD` | *(empty)* | Password for OAuth 2.1 single-user authentication |
| `TOOLMESH_API_KEY` | *(empty)* | Static API key (bypasses OAuth when set). Used only when there is no `apikeys.yaml`; see [API Keys](#api-keys). |
| `TOOLMESH_AUTH_USER` | `owner` | User identity in simple auth mode (password/single API key) |
| `TOOLMESH_AUTH_PLAN` | `pro` | Plan in simple auth mode |
| `TOOLMESH_AUTH_ROLES` | `admin` | Comma-separated roles in simple auth mode |
| `TOOLMESH_ISSUER` | `https://toolmesh.invalid/` | OAuth issuer URL (must end with `/`). The default is a placeholder on a top-level domain that never resolves: set it to the public URL clients use, or the OAuth metadata and the [`401` challenge of `/mcp`](#unauthenticated-requests) name the wrong host. ToolMesh logs a warning at startup while it is unchanged, and also for `https://toolmesh.io/`, the placeholder earlier versions shipped. |
| `TOOLMESH_ROOT_REDIRECT` | *(empty)* | Absolute `http(s)` URL that `GET /` redirects to (302). Unset, the site root serves the built-in page explaining that this host is an MCP endpoint. Only `/` is redirected — `/mcp` always serves the page, since a visitor there needs the URL to copy. An invalid value fails startup. |
| `TOOLMESH_TRUSTED_PROXIES` | *(empty: loopback only)* | Addresses of the reverse proxies whose `X-Forwarded-For` header is honored, as comma-separated addresses or CIDRs, or `none`. List proxies, not client networks. A request from any other address is identified by its connection address. See [Client address](#client-address). An invalid entry fails startup. |
| `TOOLMESH_DEV` | `false` | Local-development posture. Reports the startup security-posture summary at `INFO` instead of `WARN`. Relaxes no setting on its own — it only changes the log level of that summary. |

## TLS

By default ToolMesh serves plain http and expects a reverse proxy in front of it that ends TLS. It can also serve https itself, so that an instance needs no proxy. The certificate then comes from two files, or from an ACME certificate authority such as [Let's Encrypt](https://letsencrypt.org), which issues it for the host name of `TOOLMESH_ISSUER` and renews it. All of this is optional: an instance behind a proxy sets none of these variables and runs as before.

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_TLS_CERT` | *(empty)* | PEM file with the certificate, followed by its intermediate certificates. With it and the key the main listener serves https |
| `TOOLMESH_TLS_KEY` | *(empty)* | PEM file with the key of that certificate |
| `TOOLMESH_TLS_ACME` | `false` | `true` obtains the certificate from an ACME certificate authority, for the host name of `TOOLMESH_ISSUER`, and renews it. Setting it accepts the authority's terms of service |
| `TOOLMESH_TLS_ACME_EMAIL` | *(empty)* | Contact address of the ACME account. Optional |
| `TOOLMESH_TLS_ACME_DIRECTORY` | Let's Encrypt | Directory URL of another ACME certificate authority, for example Let's Encrypt's staging environment `https://acme-staging-v02.api.letsencrypt.org/directory`, or an authority of your own |
| `TOOLMESH_HTTP_REDIRECT_BIND` | *(empty)* | Address of a plain http listener next to the https one, such as `:8081`. It redirects to the https address and, with ACME, answers the authority's HTTP-01 challenges. Empty: no such listener |

### Quick start with TLS

You need a host name that resolves to the machine, here `toolmesh.example.com`, and port 443 of that address free for ToolMesh.

1. Set three lines in `.env`:

   ```bash
   TOOLMESH_ISSUER=https://toolmesh.example.com/
   TOOLMESH_TLS_ACME=true
   TOOLMESH_PORT=443
   ```

   `TOOLMESH_PORT` is the host port Compose publishes. Inside the container ToolMesh listens on 8080 as before.

2. Start ToolMesh and wait for the certificate, which takes a few seconds:

   ```bash
   docker compose up -d
   docker compose logs -f toolmesh | grep "TLS certificate"
   ```

   The line `TLS certificate ready` names the host and the day the certificate ends.

3. Check that it answers, and connect clients to `https://toolmesh.example.com/mcp`:

   ```bash
   curl https://toolmesh.example.com/health
   ```

With a certificate of your own, set `TOOLMESH_TLS_CERT` and `TOOLMESH_TLS_KEY` instead of `TOOLMESH_TLS_ACME` and mount the two files into the container; `docker-compose.override.yml.example` has the lines.

### What changes with TLS on

- The main listener speaks https only, TLS 1.2 or later, with HTTP/2 and HTTP/1.1. A plain http request to it is answered `400`. Health checks and scripts that call `/health` or `/mcp` need the https address.
- `TOOLMESH_ISSUER` has to be an https address. It is the address clients are given, in the OAuth metadata and in links.
- Nothing stands in front of ToolMesh any more, so no proxy is trusted for the client address: leave `TOOLMESH_TRUSTED_PROXIES` unset. See [Client address](#client-address).
- The metrics listener is a listener of its own and stays plain http. So does [the credentials page's own listener](#where-the-page-is-served), unless it has certificate files of its own.
- Failed TLS handshakes are logged at `DEBUG`. A listener on the internet sees them all day, from scanners and from clients that ask for another host name.

### Certificate files

ToolMesh looks at the two files once a minute and loads them again after a change, so a renewed certificate needs no restart. Files that do not load in the middle of a renewal leave the certificate in use and are tried again a minute later.

### Certificates from an ACME certificate authority

- **Terms of service.** `TOOLMESH_TLS_ACME=true` accepts the terms of the certificate authority on your behalf, for Let's Encrypt its subscriber agreement. Read them before you turn it on.
- **Host name.** The certificate is for the host name of `TOOLMESH_ISSUER` and for no other. A connection that asks for another name, or for none, as a client does that connects to the IP address, gets no certificate and fails. ACME needs a full host name; for an IP address or a name of one label use certificate files.
- **How the authority validates.** It connects to the host name on port 443 and asks the main listener for proof (TLS-ALPN-01). So port 443 of the host name has to reach the main listener: `TOOLMESH_PORT=443` with the shipped Compose file. If the instance is reached on another port, say `https://toolmesh.example.com:8443/`, set `TOOLMESH_HTTP_REDIRECT_BIND` and publish that listener on port 80; the authority then validates over port 80 (HTTP-01).
- **Where the certificate is kept.** The account key, the certificate and its key are files below `acme/` in `TOOLMESH_DATA_DIR`, which the shipped Compose file keeps in `./data`. Each certificate authority has a directory of its own there. A restart reads them and asks the authority for nothing. ToolMesh does not start when it cannot write there: without the files every start would request a new certificate, and authorities issue only a few per week for one name. Back the directory up like a key.
- **At the start.** ToolMesh obtains the certificate when it starts, not when the first client connects, and logs `TLS certificate ready`. When the authority issues none, it logs an error and tries again after 2, 5 and 15 minutes, then every hour. Until then https connections fail; a client that connects makes ToolMesh ask the authority as well, at most once a minute. The usual cause is that the authority does not reach the instance under the host name: check the DNS entry and the published ports.
- **Renewal.** The certificate is renewed 30 days before it ends, or in the last third of a shorter lifetime, without a restart. The log says `TLS certificate renewed`. A certificate that is halfway through that time without a renewal is logged as a warning twice a day.
- **Trying it out.** Let's Encrypt limits how many certificates it issues and how many validations may fail. Its staging environment has higher limits; its certificates are not trusted by clients. After a change of `TOOLMESH_TLS_ACME_DIRECTORY` ToolMesh requests a certificate from the new authority; the one of the old authority stays in its directory.
- **An authority of your own.** `TOOLMESH_TLS_ACME_DIRECTORY` takes the directory URL of another ACME certificate authority, for example one you run yourself, or [Pebble](https://github.com/letsencrypt/pebble) for tests. ToolMesh has to trust the certificate of that address. The image trusts the public authorities; for a private one, mount its root certificate into a directory and name the directory in `SSL_CERT_DIR`. Authorities that require an external account binding are not supported.

### The http redirect listener

`TOOLMESH_HTTP_REDIRECT_BIND` starts a plain http listener that serves nothing of ToolMesh. It answers `GET` and `HEAD` with a redirect (`308`) to the same path at the https address of `TOOLMESH_ISSUER`, so that a browser that was given the bare host name arrives. Other requests are answered `400`: a client that posts to the plain http address has sent its request in the clear and should be told. With ACME the listener also answers HTTP-01 challenges. Publish it on port 80, for example `"80:8081"` with `TOOLMESH_HTTP_REDIRECT_BIND=:8081`.

### Settings that stop the start

The settings go together, and one that would be ignored is an error: whoever sets it expects https. ToolMesh does not start with one of the two certificate files alone, with files that hold no certificate, with files and `TOOLMESH_TLS_ACME` together, with `TOOLMESH_TLS_ACME_EMAIL` or `TOOLMESH_TLS_ACME_DIRECTORY` but without `TOOLMESH_TLS_ACME=true`, with a redirect listener but no https, with an `http://` issuer while TLS is on, or with ACME while `TOOLMESH_ISSUER` is the placeholder, an IP address or a name of one label.

## Login Throttling

The password login at `/authorize` and on the page [`/credentials`](#the-page) limits failed attempts. Each limit counts failures within `TOOLMESH_LOGIN_FAILURE_WINDOW`. Once a limit is reached, further attempts it covers are answered with `429` and a `Retry-After` header, without the password being checked, until the window that began with the first counted failure has passed. Later attempts do not extend it.

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
- **Scope of a lockout.** Only new password logins are refused. Access and refresh tokens that were already issued keep working, and so do API keys, which have [a limit of their own](#failed-api-keys).
- **A login that could not be checked.** If the password comparison cannot be started because the server is at its [limit for password hash comparisons](#password-hash-comparisons), the login is answered `503` with `Retry-After` and the form is shown again. No password was looked at, so this is not a failed login: it is not counted and does not use up any of the limits.
- **Shared passwords.** If one password is deliberately given to many people — a public demo login, say — the per-account ceiling lets anyone lock all of them out: 20 failed attempts spread over a few addresses refuse every new login for that account until the window ends. For such a deployment set `TOOLMESH_LOGIN_MAX_FAILURES_PER_USER=0` and keep the two per-address limits. The startup security-posture summary then lists that limit as switched off, which is expected here.
- **Where the counters live.** In Redis when it is connected, so the limits hold across replicas and survive a restart. Otherwise in process memory: per process, and reset by a restart. The startup log line `login throttling configured` shows which applies. If Redis fails while ToolMesh is running, a login that cannot reach it logs the warning `login throttle: Redis unavailable, falling back to process-local counters` and is counted in process memory rather than let through unlimited. A counter that was charged there stays there until its window ends, also after Redis is back, so what was counted during the outage keeps counting. The process-local table holds at most 50,000 counters. When it is full it drops expired counters first, then counters that have not reached their limit, and only if that is not enough, others; it logs `login throttle: process-local counter table is full, dropped live counters` at most once a minute.
- **Lifting a lockout early.** Delete the counters, e.g. `redis-cli --scan --pattern 'auth:{login}:failures:*' | xargs redis-cli del` (with the shipped Compose file, run `keydb-cli` inside the `keydb` service). Restart ToolMesh instead if it counts in process memory, or if the failures were counted there during a Redis outage.
- **Client address.** The per-address limits depend on the client address ToolMesh sees; see [Client address](#client-address). IPv6 addresses are counted per `/64`. Where the client address is not available — every request appears to come from the same address — all clients share the per-address counters. Raise or switch off the two per-address limits there and rely on the per-account ceiling. This does not combine with a shared password (above), which needs the per-address limits instead.
- **Confirmation of the destination.** The login page names the host of the client's `redirect_uri`, the party that receives the authorization, and the client's self-declared name, marked as not verified. The user has to tick a confirmation for that host. A login without it is refused before the password is looked at and does not count.

### Client address

The client address is used for the login and API key limits, the registration limit and the `remote` field of the log. ToolMesh takes it from the connection, and from `X-Forwarded-For` only when the connection comes from a trusted proxy (`TOOLMESH_TRUSTED_PROXIES`, by default loopback only). The header is then read from the right: the first entry that is not a trusted proxy itself is the client. When every entry is a trusted proxy, the leftmost one is used. An entry with a port, as some load balancers append it (`203.0.113.7:51234`, `[2001:db8::7]:51234`), counts as its address; an entry that is no address (`unknown`, empty) ends the walk, and the last trusted proxy read so far, at first the connection's peer, is used. All `X-Forwarded-For` header lines count, not just the first.

`TOOLMESH_TRUSTED_PROXIES` lists the addresses your reverse proxies connect from, not the networks your clients are in: a client whose own address is listed can choose the address it is counted under.

- **Reverse proxy on the same host** (Caddy, nginx, Traefik as a host service): nothing to set.
- **Reverse proxy in a container** in the same Compose network: list the proxy container's address, or the Compose network if the address changes, for example `TOOLMESH_TRUSTED_PROXIES=172.18.0.0/16`. Only the proxy may share that network with ToolMesh then.
- **Proxy or CDN on other machines** (a load balancer, Cloudflare): list its addresses or published ranges.
- **No proxy, ports published directly** with rootful Docker on Linux: nothing to set; Docker keeps the client's source address. With Docker Desktop, rootless Docker or a userland proxy every connection comes from a gateway address instead, so all clients share one address's limits. That fails safe, but a lockout then hits everyone; put a reverse proxy in front, or raise the per-address limits.
- **Not configured but behind a proxy:** every client is counted under the proxy's address. ToolMesh logs `X-Forwarded-For from an address that is not a trusted proxy is ignored` at `WARN` (at most once an hour, with `remote`) when such a header arrives from an address that is not listed. The `remote` field of the request log shows which address ToolMesh uses.
- The proxy closest to ToolMesh must append the real client address to `X-Forwarded-For`, which common reverse proxies do. `none` honors no `X-Forwarded-For` at all.
- The startup log names the trusted addresses: `X-Forwarded-For honored from ...`.

### Failed API keys

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_APIKEY_MAX_FAILURES_PER_IP` | `50` | Failed bearer credentials from one client address within `TOOLMESH_LOGIN_FAILURE_WINDOW`. `0` switches the limit off, which the startup security-posture summary reports. Parsed strictly like the login limits. |

A bearer credential on `/mcp`, `/files/upload` or `DELETE /blobs/…` reserves a slot against its client address before it is checked, so concurrent guesses cannot all pass before the first failure is counted. A rejected credential keeps the slot, an accepted one hands it back, and one that could not be checked (`503`) is not counted. Once the limit is reached, every bearer credential from that address, the right one included, is answered `429` with `Retry-After` until the window ends, and logged at `INFO` as `bearer authentication throttled`. The counters live in Redis when it is connected, so each API key request then costs two short Redis operations; access tokens cost none.

Values that have the form of an access token issued by this server (64 lowercase hex characters) reserve no slot up front: they cannot be guessed, and expired ones arrive routinely, often from the shared addresses of hosted clients. Such a value takes a slot only when it would be compared with bcrypt against `key_hash`-only entries. When its address is throttled, the comparison is skipped and the value is answered `401` like any unknown credential, so a client with an expired token can still refresh it. An API key of that form (`openssl rand -hex 32` without the recommended `tm_` prefix) is therefore checked against the lookup table without throttling, which is safe only because such a key is random.

### Failed logins in the log

Every failed password login is logged at `WARN` with the message `login failed` and three fields: `username` (as submitted, truncated to 128 bytes), `remote` (the client address) and `reason`. The password is never logged. The username is logged as typed, so a password entered into the username field by mistake will appear there.

| `reason` | Meaning |
|----------|---------|
| `invalid_credentials` | Wrong password or unknown username. |
| `throttled_user_ip`, `throttled_user`, `throttled_ip` | Refused by the limit named above; the password was not checked. |
| `unknown_client`, `invalid_redirect_uri` | The OAuth client or its redirect URI is not registered; the password was not checked. |
| `redirect_host_not_allowed` | The host of the redirect URI is not in `TOOLMESH_OAUTH_REDIRECT_HOSTS`; the password was not checked. |
| `consent_not_confirmed` | The user did not confirm the destination of the authorization; the password was not checked. |
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

## Client Registration

MCP clients such as Claude register themselves at `/register` (OAuth 2.0 Dynamic Client Registration) before the user logs in. Registration takes no credential, so registered clients do not stay forever:

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_DCR_CLIENT_TTL` | `86400` (1 day) | Seconds a registered client is kept as long as it has not obtained a token. `0` keeps such clients forever; otherwise at least `600`, the time registration, login and code exchange need. |
| `TOOLMESH_DCR_CLIENT_IDLE_TTL` | `7776000` (90 days) | Seconds a client is kept after the last token issued to it. `0` keeps clients that obtained a token forever; otherwise at least `604800`, the lifetime of a refresh token. |
| `TOOLMESH_OAUTH_REDIRECT_HOSTS` | *(empty: any https host)* | Comma-separated hosts a client may use in `redirect_uri`: host names (`claude.ai`) or `*.example.com` for any subdomain. Applies at `/register` and again at `/authorize`, so it also covers clients registered before it was set. Loopback redirect URIs of native clients (`http://localhost`, `127.0.0.1`, `[::1]`) are always accepted. |

Both must be plain integers; anything else stops the server at startup.

- **Every token extends the client.** The code exchange after a login and every refresh set the client's expiry to `TOOLMESH_DCR_CLIENT_IDLE_TTL` from then on. A client in use refreshes its access token every hour and does not expire. A client that is idle for longer has to register again; until it does, the login answers `400` with `unknown client`.
- **Clients registered with an earlier version** carry no expiry. They get one with the next token issued to them; one that never obtains a token again stays.
- **Where it is kept.** In Redis the client's key expires with it; the file store (`oauth-state.json` in the data directory) drops it within 5 minutes of its expiry and does not restore an expired client after a restart.

- **Who gets the authorization.** Anyone can register a client with any https `redirect_uri`. The login page therefore names the `redirect_uri` host and requires the user to confirm it (see [Login Throttling](#login-throttling)). On a server that only serves known clients, such as Claude, set `TOOLMESH_OAUTH_REDIRECT_HOSTS` (for Claude: `claude.ai,claude.com`, plus loopback for Claude Code, which is always accepted).

### Tokens

An access token lives one hour, a refresh token seven days; every refresh issues a new pair.

- **Current identity.** Tokens are resolved against the configuration in force on every request and every refresh: `users.yaml` when it is loaded, the single-password owner otherwise. `users.yaml` and the `TOOLMESH_AUTH_*` variables are read at startup, so a change takes effect when ToolMesh restarts: from then on, a user that was removed from `users.yaml`, or whose `password_hash` is no longer usable (for example `"!"`), loses access with the next request, and no refresh succeeds for it; changed roles, plan and company apply to existing tokens. In single-password mode the same holds when `TOOLMESH_AUTH_USER` changes.
- **Changed passwords.** Tokens are bound to a fingerprint of the credential the user logged in with: a short hash of the `password_hash` for `users.yaml`, a value derived with scrypt from `TOOLMESH_AUTH_PASSWORD` in single-password mode, so the token store never holds a fast hash of a plain password. After a password change (and the restart that loads it), the sessions issued for the old password end with their next request or refresh. To end one user's sessions without a restart, revoke their tokens (below).
- **Tokens from before the upgrade.** Tokens issued by a version without this binding carry no fingerprint. They are accepted and get the fingerprint of the credential in force at their next refresh, so such a token survives a password change made after the upgrade: it is renewed and bound to the new password. A later release will close this. Until then, if you suspect misuse of a session that predates the upgrade, revoke its tokens with `POST /revoke` (this needs the token value), or end every session by clearing the stored tokens while ToolMesh is stopped:
  - **Without Redis:** delete `oauth-state.json` in the data directory (`TOOLMESH_DATA_DIR`). It also holds the registered OAuth clients, so clients register again and every user signs in again.
  - **With Redis:** delete both the Redis keys `oauth:token:*` and `oauth:refresh:*` (for example `redis-cli --scan --pattern 'oauth:token:*' | xargs -r redis-cli del`, and the same for `oauth:refresh:*`; with the shipped Compose file, run `keydb-cli` inside the `keydb` service) and `oauth-state.json` in the data directory. Clearing only one of them is not enough: at startup ToolMesh copies the tokens from `oauth-state.json` back into Redis, and while running it reads Redis first. The registered clients stay in Redis and are written back to the file.
- **Revocation.** `POST /revoke` ([RFC 7009](https://www.rfc-editor.org/rfc/rfc7009)) takes `token=<access or refresh token>` and revokes both tokens of the pair. It answers `200` also for an unknown token. Holding a token is enough to revoke it; the metadata advertises the endpoint as `revocation_endpoint`.

Registrations are limited to 5 per hour from one client address (an IPv6 address counts as its /64). The counters live in Redis, so the limit holds across replicas. Without Redis they live in process memory and the limit applies per process, which the startup log reports as `dynamic client registration (/register) is rate-limited per process`. When Redis cannot be reached for a check, the registration is allowed rather than refused (fail-open, so that an outage of Redis does not stop new connections) and logged at `WARN` as `dcr rate limit unavailable, registration allowed without limit (fail-open)` with `error` and `remote`.

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

**A kit replaces the pre-execution gate.** A call that a held kit covers
passes the [gate](#gate-policies) on the approver's word: every
pre-execution policy without the directive `// toolmesh: enforce-with-kit`
is skipped for it, and only policies with the directive, meant for parameter
filters, still run. A kit granted in part covers only its granted entries.
The audit entry of such a call carries `kit_applied` (the kit) and
`gate_skipped` (the policies), and the log shows `kit replaces the
pre-execution gate`. Denies decide before the kit is looked at, and the
post-execution gate (masking, field filters) runs for every call. A call
the gate refuses is answered, as an authorization denial is, with the kits
that would lift the refusal, and its audit entry carries `remedy_kits`;
where kits exist and none lifts it, the answer says so.

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
    kits: [net-diag-read]
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

`kits` limits an approver to the named kits, which must be kits the file
defines; without it an approver may approve every kit. An approval of
another kit is refused (`403` on the approver API, an error on the approval
page) and recorded in the audit trail as a failed `grant_approve`, and the
approval page offers only approvers who may approve the request's kit.
Denying and revoking are open to every approver, as they only take rights
away.

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
link to the [approval page](#approval-page). The answer's `note` repeats the
link and the fingerprint word for word, so that an agent which passes the note
on passes the link on. A request waits 30 minutes for a
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
its metadata (`held_kits`, a kit held in part marked `(part)`); when one of
them covers the tool, `kit_applied` names it and `gate_skipped` the
pre-execution policies it replaced (see [Gate policies](#gate-policies)).

#### Approver API

On the ToolMesh port, with the approver key as bearer credential:

| Request | Effect |
|---------|--------|
| `GET /grants` | Pending requests and active grants |
| `GET /grants/<id>` | One request or grant |
| `POST /grants/<id>/approve` | Grant the kit. Optional body: `{"ttl": "1h"}` to grant it for another duration than requested, up to the kit's `ttl_max` (24 hours without one); `{"grants": ["graylog:read"], "tools": [...]}` to grant only these entries of the kit, exactly as the kit lists them |
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

- **What it shows** comes from ToolMesh, the plain answers first: whom the
  grant is for (user and connection), the risk of what the kit allows (high,
  elevated, medium or low, after the most far-reaching access class among the
  entries kept), how many actions would be new to the caller, the duration
  and the fingerprint. Compare the fingerprint with the one the agent
  reported, over the channel you work with it in, to know that the link
  shows its request. Then come the kit's description and warning, and the
  reason and the client name, marked as the requester's own statements.
  Under "Technical details" are the request's id and times and the kit's
  entries, grouped by what they allow (every access class first, then
  dangerous, admin, other, write, read), with the tools each covers and how
  many of them are new to the caller.
- **Narrowing.** Keep the kit as requested, take it without its dangerous
  entries, or switch off single entries under "Technical details". The grant
  then covers only the entries that stay on.
- **Duration.** The page offers the duration requested and steps from 5
  minutes to 24 hours up to the kit's `ttl_max` (24 hours without one);
  "Other" takes whole minutes or hours up to that maximum. A grant may be
  shorter or longer than requested, never longer than the maximum.
- **The statement.** For these choices ToolMesh writes a statement, plain
  text that names this ToolMesh, the request and its nonce, the approver and
  address, the kit, the entries granted and left out, the duration, whom the
  grant is for and the reason. The page shows it as it is, under "Show the
  exact text you sign", and it is what is signed. ToolMesh writes it again from the stored request to verify the
  signature, so nothing the page or the requester adds can change it.
- **Signing.** Paste the private key (WIF or 64 hex characters) and press
  and hold the button to sign in the page; the key stays in the browser and
  only the signature is sent.
  Or copy the statement into a wallet that signs BIP-322 messages and paste
  the signature (with or without the `smp` prefix). On a page served over
  plain HTTP (other than localhost) the key field is disabled: use HTTPS.
- **Languages.** The page speaks English, German, French, Spanish and
  Japanese. It follows the browser's language; `?lang=de` picks one, and the
  language switch keeps the choice in the browser. The statement stays
  English: it is what ToolMesh verifies and records. In the other languages
  the page shows a reading aid beside it, line by line, which is not part of
  what is signed. The kit's description and warning appear as the grants
  file has them, and the requester's reason is never translated. The texts
  are in `internal/grants/web/i18n/<code>.json`; a file there adds a
  language, with the keys of `en.json`.
- **Once.** A signature approves its request once: approving takes the
  request from the store, and a statement names one request and its nonce.
- **Limits.** Refused approvals (a signature that does not verify, or
  choices that do not fit the request) are limited within 15 minutes to 5 per
  request and source address, 10 per request and 20 per source address;
  beyond that the page answers `429` with `Retry-After`. A successful
  approval clears the request's counters. The counters work like those of
  [login throttling](#login-throttling), with the same source address
  (see [Client address](#client-address)) and in Redis when it is
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

The verdicts take the [gate policies](#gate-policies) into account, as a
call meets them after the authorization step: the pre-execution policies are
asked about every tool the caller may call or get through a kit, with the
kits the caller holds, no parameters and `ctx.preflight` set. A tool a
policy refuses is `escalatable` through the kits that cover it and with
which the gate passes (a held kit replaces the gate, except for policies
with the directive `enforce-with-kit`), or `denied` when no kit does; the
reason names the policy and its message. Discovery (`discover_tools`,
`toolmesh.discover`) does not ask the policies: its `grant_required` marker
comes from the kit definitions alone.

Every answer also lists the kits the caller holds (`grants`, with id, expiry
and time remaining) and its pending requests (`requests`, each with its
approval link and fingerprint, so that the link can be handed over later), and
describes these kits with their warnings.

The built-in tools ToolMesh lists (`discover_tools`, `execute_code`,
`tell_me_my_rights`, and `request_grant` and `upload_file` where offered) are
`allowed` in a preflight: ToolMesh runs them itself, without the authorization
step and the gate policies, and checks every tool that `execute_code` calls
when it calls it. The answer shows only the tools the caller may call or get
through a kit. For any other name a preflight says `denied` with the reason
`unknown tool`, both when no tool has the name and when the caller may not see
the tool, so that it does not tell whether the tool exists.
Every call is recorded in the audit trail (tool `tell_me_my_rights`, backend
`toolmesh`): the answer is the first thing an agent that was taken over would
look up. In external mode there are no kits, so the verdicts are `allowed` and
`denied`; with authorization disabled, every tool is `allowed` unless a
policy refuses it.

## Gate Policies

The gate runs JavaScript policies (goja) on every tool call: in the
**pre-execution** phase with the tool name and parameters, before the
backend is called, and in the **post-execution** phase with the response.
Every `.js` file in the policies directory is a policy; policies run in file
name order, and a policy rejects a call by throwing. Nested `api.*` calls
inside a composite go through the pre-execution phase as well. For REST
backends the parameters a policy sees have passed the check against the
declared DADL types (see [Requests to REST backends](#requests-to-rest-backends)),
with declared defaults filled in, numeric strings converted to numbers and
numbers or booleans for string parameters converted to their text (`"42"`),
so a policy sees what the API receives. Write numeric comparisons with
`Number(ctx.params.x)` anyway: an integer beyond 2^53 stays a string to keep
it exact. Only top-level parameters are checked; values nested inside an
object or array parameter arrive as the caller sent them. Tools of MCP
backends and units are not checked against a declaration: their policies see
the caller's arguments, which are also what the MCP server receives.

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_POLICIES_DIR` | `/app/policies` | The policies directory. The shipped `docker-compose.yml` mounts `./config/policies` there; examples are in `config/policies/examples`. |
| `GATE_EVALUATORS` | `goja` | The evaluator chain, comma-separated. |

A policy sees one object, `ctx`:

| Field | Content |
|-------|---------|
| `ctx.phase` | `"pre"` or `"post"` |
| `ctx.tool` | The tool's full name, `<backend>_<tool>` |
| `ctx.toolAccess` | The tool's DADL `access` classification; `""` without one |
| `ctx.params` | The parameters. Changes made in the pre-execution phase reach the backend and are recorded in the audit entry |
| `ctx.user` | The caller: `userId`, `companyId`, `roles`, `plan`, `authenticated`, `callerId`, `callerName`, `callerClass` |
| `ctx.response` | The result, in the post-execution phase; changes to `content` reach the caller and are recorded. `null` in the pre-execution phase |
| `ctx.kits` | The kits the caller holds, whole or in part, by name; an empty array without any |
| `ctx.kitCovered` | `true` when one of them covers the tool |
| `ctx.preflight` | `true` when ToolMesh asks whether a call would pass without making it: for the verdicts of `tell_me_my_rights`, where `ctx.params` is empty, and to name the kits that would lift a refusal. Nothing runs or is recorded, and changes to `ctx.params` are discarded. A policy that requires a parameter should not refuse a preflight for its absence |
| `ctx.rateLimitExceeded(n)` | Whether the caller made more than `n` calls in the last hour |

Policies load at startup. The log shows one line `loaded policy` per file,
and a warning for every tool-name literal in a policy that matches no
registered tool, a branch that would never fire.

**Directives.** A policy declares how it relates to kits in its header
comment, the comment lines at the top of the file before the first line of
code, with a line of the form:

```javascript
// toolmesh: enforce-with-kit
```

- Without the directive a policy **yields to a kit**: when a kit the caller
  holds covers the tool, the policy is skipped in the pre-execution phase.
  This is the default, and the right choice for rules at tool granularity,
  such as a caller class that may not use write tools or a read-only
  posture: an approver has decided for this caller and this kit.
- With the directive a policy is **enforced with a kit**: it runs in the
  pre-execution phase whether or not a kit covers the tool. Use it for
  parameter filters and for conditions that narrow what a scope allows,
  such as refusing a force-push to `main` or turning a device off: a kit
  grants the tools, not every argument.

The post-execution phase runs every policy regardless, so masking and field
filters apply to kit holders too. The start log names the choice per policy
(`loaded policy name=readonly_gate.js pre_gate_with_kit=skipped`,
`loaded policy name=default.js pre_gate_with_kit=enforced`) and warns about
a directive it does not know. Among the shipped examples, `default.js`,
`github-branch-protection.js` and `shelly_write_protection.js` carry the
directive.

**When a kit replaces the gate.** After the authorization check, the
executor looks up whether a kit the caller holds covers the tool: a kit held
whole through its definition, a kit held in part through its granted entries
only. If so, the pre-execution gate runs only the policies with the
directive. The call is logged as `kit replaces the pre-execution gate` with
the kit and the skipped policies, and its audit entry carries `kit_applied`
(the kit) and `gate_skipped`, which names every other loaded policy,
post-execution-only policies included, as none of them ran in that phase.
A deny in the grants file still wins: it decides in the authorization step,
before the kit is looked at. Whether the steady-state grants would have
allowed the call as well does not matter: the kit applies whenever it
covers the tool. A preflight (`ctx.preflight`) skips the same policies for
a kit that covers the tool, which is how `tell_me_my_rights` tells
`escalatable` from `denied` and a refusal names the kits that lift it.

## Redis

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://keydb:6379/0` | KeyDB/Redis connection URL (Docker Compose service name: `keydb`). Also holds kit requests and grants (see [Granting kits](#granting-kits)) |

## Credential Store

`CREDENTIAL_STORE` selects where ToolMesh takes backend credentials from:

| Store | Values come from | Values are kept in |
|-------|------------------|--------------------|
| `embedded` (default) | `CREDENTIAL_*` environment variables | the process environment |
| `command` | the output of a command ToolMesh runs | ToolMesh's memory only |

### Embedded store

Credentials are stored as environment variables with the `CREDENTIAL_` prefix.

| Variable | Description |
|----------|-------------|
| `CREDENTIAL_<LOGICAL_NAME>` | Credential value for the given logical name |

Example:
```bash
CREDENTIAL_MEMORIZER_API_KEY=sk-mem-xxxxx
CREDENTIAL_BRAVE_API_KEY=BSA-xxxxx
```

### Why the environment is not the place for credentials

Under Docker the values reach the container through `env_file:` or
`environment:`. Docker writes a container's environment in plain text into
the container configuration on the host
(`/var/lib/docker/containers/<id>/config.v2.json`, also shown by
`docker inspect`). Every credential then sits on the host's disk and in every
backup or snapshot of it, even when the `.env` file itself is stored
encrypted and decrypted only to start the container. Stdio backends inherit
the whole environment as well, so each of them receives every credential.

The `command` store avoids both: ToolMesh fetches the values itself and keeps
them in memory.

### Command store

| Variable | Default | Description |
|----------|---------|-------------|
| `CREDENTIAL_STORE` | `embedded` | Set to `command` |
| `TOOLMESH_CREDENTIAL_COMMAND` | *(none)* | Command line that prints the values. Required |
| `TOOLMESH_CREDENTIAL_RELOAD_IN` | `0` | Seconds between runs. `0` runs the command only at startup |
| `TOOLMESH_CREDENTIAL_COMMAND_TIMEOUT` | `30` | Seconds a single run may take |
| `TOOLMESH_CREDENTIAL_FORMAT` | `dotenv` | Output format: `dotenv` or `json` |
| `TOOLMESH_CREDENTIAL_JSON_PATH` | *(top level)* | With `json`: dot-separated path to the object that holds the values, e.g. `data.data` |

The settings carry a `TOOLMESH_` prefix because `CREDENTIAL_<NAME>` is the
namespace of the credentials themselves. Invalid values stop the start.

**The command.** ToolMesh runs it without a shell, since the image has none.
The line is split into arguments the way a shell splits words: single quotes,
double quotes and backslash escapes work. Pipes, redirections, `;`, `&&`,
variables, command substitution and a leading `VAR=value` are refused at
startup; there is no globbing. Give the program as an absolute path and mount
it read-only into the container, together with whatever it reads. It has to
run without a libc, as statically linked binaries do. The command inherits
ToolMesh's environment, which with this store holds no credentials.

In `.env`, put the command line in double quotes. Docker Compose reads the
file itself (`env_file`), and some of its versions end an unquoted value at
the first space and then stop at the rest of the line with an error such as
`unexpected character "-" in variable name`. Compose removes the quotes
before ToolMesh sees the value. Quotes that the command line itself needs
go inside single quotes around the whole value:
`TOOLMESH_CREDENTIAL_COMMAND='/usr/local/bin/helper "a b"'`.

A run fails when the command exits with a code other than 0, exceeds the
timeout, writes more than 1 MiB to stdout, prints no value at all, or prints
something that does not parse.

**dotenv output** (the default). One `KEY=value` per line, as
`sops -d --output-type dotenv` writes it and as `.env.example` shows:

- `#` comment lines and blank lines are skipped, a leading `export ` is
  ignored.
- Unquoted values are trimmed, a `#` after a space or tab starts a comment,
  and `\n` stands for a line break (the way sops writes multi-line values).
- `'single quotes'` keep everything literal. `"double quotes"` know the
  escapes `\n`, `\r`, `\t`, `\"`, `\\` and `\$`. Quoted values may span lines.
- Variables are not expanded. A later line wins over an earlier one.

**JSON output.** With `TOOLMESH_CREDENTIAL_FORMAT=json` the command prints one
JSON value, as `vault kv get -format=json` and `bao kv get -format=json` do.
`TOOLMESH_CREDENTIAL_JSON_PATH` selects the object that holds the values:
`data.data` for a KV version 2 secret of Vault or OpenBao, `data` for version
1, empty for the top level. Everything outside that object, such as request
and lease metadata, is ignored.

- Nested objects below the path are flattened: every string, number and
  boolean becomes a key named after its own member name, however deep it
  sits. `{"github": {"CREDENTIAL_GITHUB_TOKEN": "..."}}` gives
  `CREDENTIAL_GITHUB_TOKEN`.
- Numbers keep their written form. `null` values and arrays are skipped.
- A member name that is not an environment variable name, or that occurs
  twice after flattening, fails the run.
- Vault's `lease_duration` is not used; a KV version 2 secret reports `0`
  there.

Keys are environment-style names: `CREDENTIAL_<NAME>` for backend credentials,
and any other name that an `env:` remapping, a `credential_env` entry or one of
ToolMesh's own secrets (below) refers to. `RELOAD_IN` is reserved in both
formats.

**Where the values stay.** In a map in ToolMesh's memory, never in its
environment and never in the log. stdout is not logged; stderr is logged at
`WARN`, cut off after 4 KiB, so the command must not write secrets there. When
a run adds or drops keys, the log names the keys, not the values.

**Refreshing.** After `TOOLMESH_CREDENTIAL_RELOAD_IN` seconds the command runs
again. A key `RELOAD_IN` in the output (a line `RELOAD_IN=<seconds>`, or a
JSON member of that name) sets the delay until the next run instead;
`RELOAD_IN=0` ends the refreshing. A successful run replaces
the whole set at once, and keys it no longer prints are gone. A failed run
keeps the previous set and is retried after 30 seconds, then with a doubling
delay up to the interval in force. If the first run at startup fails, ToolMesh
exits with a non-zero code and the container's restart policy tries again.

Refreshed values reach REST backends with their next call. MCP backends read
theirs (`api_key_env`, `credential_env`) when ToolMesh connects to them: at
startup and when `backends.yaml` changes.

**ToolMesh's own secrets.** With the command store, `TOOLMESH_AUTH_PASSWORD`,
`TOOLMESH_API_KEY`, `REDIS_URL`, `TOOLMESH_USER_CREDENTIALS_KEY` and
`TOOLMESH_USER_CREDENTIALS_KEY_NEXT` are taken
from the output when it contains them, ahead of the environment, once at startup. Remappings (`env:` in
`backends.yaml`) resolve their keys in the output too, not in the environment.

**Stdio backends.** A stdio MCP server inherits ToolMesh's environment, which
with this store contains no credentials. Pass it what it needs with
`credential_env` in its `backends.yaml` entry: variable name in the child,
key in the store.

```yaml
backends:
  - name: github
    transport: stdio
    command: /usr/local/bin/github-mcp-server
    args: ["stdio"]
    credential_env:
      GITHUB_PERSONAL_ACCESS_TOKEN: CREDENTIAL_GITHUB_TOKEN
```

The child receives nothing else from the store. A key the store does not hold
keeps the backend from connecting. With the embedded store `credential_env`
reads the key from the environment, so the same entry works with both stores.

**Monitoring.** Two metrics follow the runs:
`toolmesh_credential_store_runs_total{result="success|failure"}` and
`toolmesh_credential_store_last_success_timestamp_seconds`. Alert when the last
success lies more than two intervals back, for example with a one-hour
interval:

```promql
time() - toolmesh_credential_store_last_success_timestamp_seconds > 7200
```

#### Example: an encrypted file with sops

[sops](https://github.com/getsops/sops) encrypts the values of a dotenv,
YAML or JSON file and leaves the key names readable, so the file can live in
git and its diffs stay useful. It takes its keys from
[age](https://github.com/FiloSottile/age) (a small file-encryption tool), PGP
or a cloud KMS. With age:

```bash
sops --encrypt --age <recipient> --input-type dotenv --output-type dotenv \
  secrets.plain.env > secrets/toolmesh.env
```

Mount the encrypted file and a static `sops` binary read-only, for example in
`docker-compose.override.yml` (`docker-compose.override.yml.example` has a
section to start from, including the mount for an agent's socket):

```yaml
services:
  toolmesh:
    volumes:
      - /usr/local/bin/sops:/usr/local/bin/sops:ro
      - ./secrets/toolmesh.env:/run/secrets/toolmesh.env:ro
```

The `.env` then holds no credentials, only the store settings:

```bash
CREDENTIAL_STORE=command
TOOLMESH_CREDENTIAL_COMMAND="/usr/local/bin/sops -d --input-type dotenv --output-type dotenv /run/secrets/toolmesh.env"
```

How sops gets its age identity is the operator's decision: a key file mounted
read-only (`SOPS_AGE_KEY_FILE` is a path, not a secret) or a key command. A
key file on the host travels with every copy of its disk; the next example
avoids it. Do not put the key itself into `.env` or `environment:`; it would
end up in the container configuration like any other value there. Change
values with `sops secrets/toolmesh.env`; ToolMesh picks them up at its next
run or restart.

#### Example: credentials sealed to the machine with ergosum

The sops example still needs one secret on the host, its age key, and
whoever copies the disk, a backup or the VM image copies that key too.
[ergosum](https://github.com/DunkelCloud/ergosum) (v0.2.0 or later) ties
that step to the machine instead of to a file: its daemon `ergosumd` seals a
file so that it opens only after a separate ergosum authority has called the
machine back where it was registered (its tailnet name, a fixed address, an
address in a permitted network). Only the sealed file lies on disk, and it
may sit in backups; a copy running elsewhere opens nothing.

Seal the credentials themselves, in the dotenv format described above, and
delete the plain file afterwards (`-recovery` adds an age-encrypted way
back):

```bash
ergosumd secret create toolmesh -threshold 2 -file /etc/toolmesh/credentials.sealed < credentials.env
```

Mount `ergosumd` (a static binary), the sealed file and the daemon's secret
socket into the container; `docker-compose.override.yml.example` has the
section. Then:

```bash
CREDENTIAL_STORE=command
TOOLMESH_CREDENTIAL_COMMAND="/usr/bin/ergosumd secret get -socket /run/ergosum/secret.sock -file /etc/toolmesh/credentials.sealed"
```

`ergosumd secret get` prints the file as it was sealed, so ToolMesh needs no
support for ergosum. To change a value, seal a new file. ergosum offers no
rotation, revocation or audit of access; Vault does, and ergosum can log the
machine in to Vault as well (next example).

#### Example: Vault or OpenBao through their proxy

Vault Proxy (`vault proxy`, in OpenBao `bao proxy`) logs in with its
auto-auth method and adds its token to every request that carries none
(`use_auto_auth_token`). The command then needs no token of its own, and
nothing is written to disk:

```bash
CREDENTIAL_STORE=command
TOOLMESH_CREDENTIAL_FORMAT=json
TOOLMESH_CREDENTIAL_JSON_PATH=data.data
TOOLMESH_CREDENTIAL_COMMAND="/usr/local/bin/vault kv get -format=json -mount=secret toolmesh"
TOOLMESH_CREDENTIAL_RELOAD_IN=300
VAULT_ADDR=http://127.0.0.1:8100
```

The KV secret `secret/toolmesh` holds the keys as a dotenv file would
(`CREDENTIAL_GITHUB_TOKEN`, `TOOLMESH_API_KEY` and so on). Mount the static
`vault` binary (or `bao`, with `BAO_ADDR`) read-only; the address is not a
secret. Bind the proxy's listener so that only ToolMesh reaches it, for
example on loopback in a network namespace shared with the ToolMesh
container: whoever reaches it acts with the proxy's token.

The proxy's own login needs a credential too, usually an AppRole secret ID
on disk. With [ergosum](https://github.com/DunkelCloud/ergosum) it needs
none: the ergosum daemon keeps a JWT in `/run/ergosum/token`, valid for 30
minutes and renewed on its own, which it receives only after the machine was
called back where it was registered. Point the proxy's auto-auth method `jwt`
at that file with `remove_jwt_after_reading = false`, since the daemon
replaces it; Vault or OpenBao check the token with their JWT auth method.

#### Example: short-lived tokens

A small program that requests an access token and prints it together with its
lifetime minus a margin keeps the token fresh. For a token that is valid for
an hour:

```bash
CREDENTIAL_EXAMPLE_TOKEN=eyJhbGciOi...
RELOAD_IN=3300
```

ToolMesh runs the program again after 55 minutes. If that run fails, the old
token stays in use while the retries back off (30 s, 60 s, 120 s, ...), so
leave a margin for a few of them. The program can print static values too,
for example by decrypting a file first and adding the token to its output.

## Credentials of Users

Some APIs have an account per person: a mailbox, a calendar, a personal API
token. With one stored credential every caller would act as the same account.
For such a backend ToolMesh can use the credential of the calling user instead.
Each user stores their own on a page of ToolMesh; a credential never passes
through a tool call. The reasons are in
[ADR-0004](adr/0004-credentials-of-users.md).

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_USER_CREDENTIALS_KEY` | *(empty)* | Turns the store for credentials of users and the page `/credentials` on: 32 random bytes as base64 or as 64 hex digits, the key the stored values are encrypted with. Create one with `openssl rand -base64 32`. With `CREDENTIAL_STORE=command` it may come from the command's output |
| `TOOLMESH_USER_CREDENTIALS_KEY_NEXT` | *(empty)* | The key to change to, in the same form. Set next to the key in use, it makes a start seal every stored value again under it (see [Changing the key](#changing-the-key)) |

Without the key the store and the page do not exist, and a backend that
declares `user_credentials` is not loaded. Keep the key like any other secret
of the instance, and keep a copy: without it the stored values cannot be read.
With the [command store](#command-store), keep it in the command's output
rather than in `.env`: every value of `.env` ends up in the container
configuration, where `docker inspect` shows it.

A key of another form, or a `user-credentials.json` that cannot be read, stops
ToolMesh at startup. ToolMesh takes the keys out of its environment once they
are read, so child processes started later, such as stdio backends, do not
inherit them.

At every start ToolMesh logs the id of the key it runs on (`keyId`, the
`key_id` that entries in the file carry; it names a key without revealing it)
and warns when stored values do not open under that key, with their number and
the ids of the keys they were sealed under.

### Changing the key

The keys are read at startup only. To change the key without anybody storing
anything again:

1. Set the new key as `TOOLMESH_USER_CREDENTIALS_KEY_NEXT`, next to the key in
   use, and start ToolMesh anew so that the setting reaches it. With Docker
   Compose that is `docker compose up -d`; `docker compose restart` keeps the
   environment the container was created with. ToolMesh seals every stored
   value again under the new key and runs on it. The log line
   `user credential store: change of key` says how many values it sealed
   again (`resealed`). If values are stored and this first start reports
   `resealed=0`, the two settings are the wrong way round.
2. Make the new key `TOOLMESH_USER_CREDENTIALS_KEY`, remove
   `TOOLMESH_USER_CREDENTIALS_KEY_NEXT` and start anew. Do not leave this for
   long: until then every start works like the first, which also means that
   a value sealed under the old key is still taken and sealed again.
3. Keep the old key until that start has run without the warning
   `stored values do not open under TOOLMESH_USER_CREDENTIALS_KEY`, and for as
   long as you keep backups of `user-credentials.json` from before the change.
   A file restored from such a backup is brought to the new key the same way,
   with the old key as the key in use.

- The file is written once, after every value is sealed again. If that fails,
  ToolMesh does not start and nothing has changed.
- A value that neither key opens stays unreadable, and a warning says how many
  there are.
- Both keys come from the same place: if the key in use is in the output of the
  command store, a key in `.env` does not replace it.
- `TOOLMESH_USER_CREDENTIALS_KEY_NEXT` without `TOOLMESH_USER_CREDENTIALS_KEY`,
  or with the same key, stops ToolMesh at startup.
- Users sign in on the page again after the change: its sessions are derived
  from the key.
- A key replaced without these steps leaves the stored accounts in the file
  but unreadable; the page shows them as such and users store them again.
- A new key does not undo a leak. If a key and `user-credentials.json` may
  have been copied, every user changes the stored credentials at their API
  and stores them again.

### Declaring them

In `backends.yaml`, an entry lists under `user_credentials` the credential
names of its DADL that every user stores for themselves. An item is the name:

```yaml
  - name: tracker
    transport: rest
    dadl: tracker.dadl
    user_credentials:
      - tracker_token
```

or a mapping with the name and the texts the page shows (`label` up to 80
characters, `hint` up to 300):

```yaml
  - name: mail
    transport: rest
    dadl: mail.dadl
    user_credentials:
      - name: mail_login
        label: Mailbox login
        hint: Your mail address and an app password.
        format: basic
```

`format: secret` (the default) stores what the user enters. `format: basic`
asks for a username and a password and stores `Basic <base64(username:password)>`,
the value of an HTTP `Authorization` header. It is for a DADL that sends one
credential as that value, in a session login body or with `type: apikey`,
`header_name: Authorization` and no `prefix`. A DADL with `type: basic` reads
two credentials and encodes them itself: list its `username_credential` and
`password_credential` as two items of the default format. `format: acl` is for
a limit of the account and described under
[Limiting what an account reaches](#limiting-what-an-account-reaches).

- The DADL stays as it is. Which of its credentials are per user is the
  operator's decision; credentials not listed stay with the instance.
- A listed name is read from what the calling user has stored and from nowhere
  else: there is no fallback to `CREDENTIAL_<NAME>`.
- The names follow the [credential binding](#credential-and-host-binding) of the
  entry like any other: a name outside the entry's namespace also has to be in
  `credentials:`.
- Every listed name must be one the DADL's auth block reads, for `oauth2` one
  that its flow reads. A backend with a name it does not read is not loaded: a
  typo would otherwise leave the real one with the instance. The same goes for
  a name listed twice or also remapped with `env:`, an unknown `format`, a DADL
  that declares a parameter named `account` itself, and a store that is off.
  The `ERROR` line `backend refused` names the reason, and the startup
  security-posture summary lists the backend; the other backends keep running.
- A `user_credentials` key without a name under it (the key alone, an empty
  list, an empty item) is an error of the file, like a misspelled key.
- A backend with user credentials never sends a call without authentication.
  Where a missing credential of the instance otherwise means "send without a
  header", such a backend fails the call.
- With `flow: jwt_bearer`, the `token_uri` inside a service-account key that a
  user stored has to be a host of the backend (its `base_url` domain or
  `allowed_hosts`), unless the DADL declares `token_url`.
- `user_credentials` works for `transport: rest`. An MCP entry (`http`,
  `stdio`) that sets it is refused, and a unit with a backend that sets it is
  not loaded.
- Stored accounts belong to the entry's `name`. After a rename of the entry the
  page lists them under "No longer used" and users store them again.

### Accounts and the `account` parameter

A user can store several accounts for one backend, each under a label, for
example the mail address. A label has 1 to 100 characters: letters a to z,
digits and `@ . _ + -`, starting with a letter or digit, without spaces. Upper
and lower case are the same label. Every tool of such a backend takes a
parameter `account` besides its own:

- With one stored account, `account` may be left out.
- With several, a call has to name one. A call that names none fails and lists
  the labels, so an agent can pick.
- ToolMesh consumes the parameter; the API never receives it.
- Labels are names, not secrets. They appear in tool calls, in the log and in
  the audit trail. The audit entry of a call names the account it used in its
  metadata (`account`), also when the call left the parameter out.

**Whose accounts.** Accounts belong to a user id. A call uses what the user
with the caller's `user_id` stored: a key in `apikeys.yaml` calls with the
accounts of the `users.yaml` user of the same name, and a key whose `user_id`
has no password login can never have any. With `TOOLMESH_AUTH_PASSWORD` there
is one user (`TOOLMESH_AUTH_USER`), shared by everyone who knows the password
and by `TOOLMESH_API_KEY`.

**Policies.** A [gate policy](#gate-policies) sees the label as
`ctx.params.account`, trimmed and in lower case, so it can limit which account
a caller uses; the child calls of a composite are checked with the account the
composite was called with. Two things to mind: a call that leaves `account` out
uses the user's only stored account, which the policy does not see, so refuse
such calls where the account matters; and a policy yields to a kit unless it
carries the `enforce-with-kit` directive.

**Errors.** A call whose user has stored no account ends as an error result,
not as a request without authentication: the text says what is missing and
names the page (its full address when `TOOLMESH_ISSUER` is set or the page has
[an address of its own](#where-the-page-is-served)). Nothing is
sent to the API. The result carries the code `user_credential_missing`,
`user_credential_unknown_account`, `user_credential_ambiguous_account`,
`user_credential_incomplete` or `user_credential_unreadable`.

OAuth2 access tokens, session tokens and the cookies of a session login are
kept per user and account, never shared. Only the cookies of the login are
kept for such sessions; a cookie that a tool response sets is not.

### Limiting what an account reaches

Some APIs let a login say what the session may reach: which mailboxes, which
calendars, whether it may send. With such an API a user can store a limit next
to the credentials of an account, for the agents that call with it. ToolMesh
keeps the limit with the account and hands it to the API at login. The API
enforces it. ToolMesh does not read it.

The DADL carries the limit as a field of its session login and says that the
login may go without it:

```yaml
  auth:
    type: session
    login:
      method: POST
      path: /session
      body:
        login: "credential:mail_login"
        scope: "credential:mail_scope"
      optional: [scope]
```

`optional` lists fields of the body's top level whose value is one credential
reference. Such a field is left out of the login when its credential has no
value. Any other failure to read the credential fails the login: a limit that
is stored and cannot be read is never taken for no limit. The key is a
ToolMesh extension that DADL spec v0.2 does not define.

In `backends.yaml` the limit is one more entry of `user_credentials`:

```yaml
  - name: mail
    transport: rest
    dadl: mail.dadl
    user_credentials:
      - name: mail_login
        label: Mailbox login
        format: basic
      - name: mail_scope
        label: ACL
        hint: 'Example: {"mailboxes":["INBOX","Projects/*"],"send":false}'
        format: acl
        optional: true
```

- `format: acl` takes one JSON object of up to 4096 bytes, in the form the API
  defines, and stores it compact. The login carries it as that object, not as
  a string. It is no secret: the page shows the stored value, and the audit
  entry of a change names it. It needs a DADL with `auth.type: session`.
- `optional: true` lets an account go without the value. Such an account
  reaches what its credentials reach. Without the key every account has to
  hold one, and a call of an account that does not fails with
  `user_credential_incomplete`: the operator decides whether a limit is the
  user's choice or a condition. `optional: true` is for a limit only
  (`format: acl`) and needs a DADL that can leave the value out: the
  credential is the value of a field that `auth.login.optional` lists, and of
  no other. At least one credential of an entry is not optional.
- A backend whose entry asks for what its DADL cannot do is not loaded, with
  the reason in the `backend refused` line.

What follows from this:

- An agent selects an account with `account` and gets what that account's
  limit allows. It can neither read nor set nor widen the limit: the limit is
  no tool parameter, and the page asks for the user's password.
- Two accounts can hold the same credentials and different limits, for example
  one that reaches every mailbox and one for the inbox.
- A changed limit applies from the account's next call: storing or removing it
  ends the session ToolMesh keeps for the account.
- The check after a save logs in with the limit. When the API answers that
  login with 400, 401 or 403, as an API does for a limit that is not
  well-formed or that is wider than it allows this ToolMesh, the page reports
  the refusal and the account is as it was before. An API that answers
  otherwise leaves the check undecided: the limit stays stored, and the calls
  of the account fail at the login until it is corrected. The check tells that
  the API took the login, not that it honors the limit; the DADL has to send
  it where the API reads it. The health check of the DADL has to be one a
  limited session can answer.
- What a limit can say is up to the API, and so is what happens to a name in it
  that matches nothing there.
- Removing or renaming the entry of a limit while the DADL keeps the optional
  field takes the limits away: the login then reads that name from the
  instance, which has none. What users stored stays in the store, unused.
  ToolMesh logs a `WARN` at startup and after every reload for a backend whose
  users hold values under names it does not ask them for.
- The limit binds agents that call through this entry. The credentials of the
  account open everything the account can reach; whoever holds them is not
  bound.

### The page

`/credentials` is where a user stores, replaces and removes accounts.

- **Sign-in.** With the user's ToolMesh password, the one of the login at
  `/authorize` (`users.yaml` or `TOOLMESH_AUTH_PASSWORD`), under the same
  [failed-login limits](#login-throttling) and counters. An installation
  without a password login cannot use the page. A session ends 15 minutes after
  sign-in, without renewal, and earlier when the user's password changes, the
  user is removed or the user signs out. A signed-out session is remembered by
  the process that signed it out: after a restart, or on another instance, its
  cookie would be accepted again for what is left of the 15 minutes.
- **What it shows.** The backends with user credentials of which the user may
  call a tool, by the same [authorization](#authorization) as a tool call. Per
  backend the stored accounts with the time they were stored, and a form.
  Never a stored secret. The limit of an account (`format: acl`) is no secret
  and is shown. A form is answered with a redirect to the page, so a reload
  never sends a credential a second time.
- **The check.** After storing, ToolMesh sends the
  [health check](#backend-health-checks) the DADL declares, with the new
  credentials. If the API answers 401 or 403, or refuses the login or token
  request, the page says so and the credentials are not kept: what the account
  held before is put back. If the check cannot tell, for example because the
  API does not answer, the account is stored and the page says that it is
  unchecked. A DADL without a health check is stored unchecked. The check
  runs to its end also when the browser goes away. A save is one write to the
  store, so an account never exists with a part of what was entered, and a
  refused save is taken back whole: every entry is again what it was, also
  one that can no longer be read.
- **Audit.** Every stored and removed account is recorded, with backend
  `toolmesh` and the tool `user_credential_store` or `user_credential_remove`.
  The entry carries the user and, in its metadata, `backend`, `account`,
  `credentials` (the names) and `check` (the outcome). A save the API refused
  is recorded as an error. The value of a secret is never recorded. The value
  of a limit is, as `value:<name>`, also for a save the API refused, and
  `removed` lists the optional credentials a save took away: the trail tells
  which limit applied from when on.
- **Limits.** 50 accounts per user and backend; 20 saves per user in ten
  minutes, of which the API may refuse 5; 16 KiB per value, 4096 bytes for a
  limit, no line breaks in a value. The counts are kept per process. They bound
  how often a user can make
  ToolMesh try credentials against an API.

- **Sessions at the API.** Storing or removing an account ends the token or
  session ToolMesh keeps for that account, so its next call authenticates with
  what is stored then. The user's other accounts keep theirs.

### Where the page is served

By default the page is at `/credentials` of the main listener, next to the MCP
endpoint. Put it behind TLS like the rest of ToolMesh, with [built-in TLS](#tls)
or a proxy. That is all an instance needs that is reached directly or through a
proxy you run yourself.

Whatever ends TLS in front of the page reads every form sent to it: the
ToolMesh password at sign-in and each credential a user stores. If that is a
proxy someone else runs, such as a CDN in front of a public MCP endpoint, a
third party is in that path. For this case the page can have a listener of its
own, on an address that does not pass that proxy, for example on a private
network or a VPN. This is optional:

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_CREDENTIALS_BIND` | *(empty)* | Address the page's own listener binds, such as `:8444` or `10.0.0.5:8444`. Empty leaves the page on the main listener |
| `TOOLMESH_CREDENTIALS_URL` | *(empty)* | The address users open that listener at, scheme and host, such as `https://toolmesh.internal.example:8444`. Required with `TOOLMESH_CREDENTIALS_BIND` |
| `TOOLMESH_CREDENTIALS_TLS_CERT` | *(empty)* | PEM file with the certificate of that listener. With it and the key the listener serves https itself |
| `TOOLMESH_CREDENTIALS_TLS_KEY` | *(empty)* | PEM file with the key of that certificate |

- With the listener, the main listener answers `/credentials` with 404. The
  listener serves the page and nothing else.
- Messages that send a user to the page name `TOOLMESH_CREDENTIALS_URL`. The
  page is at that address and nowhere else: a request that reaches the
  listener under another host name gets no page (status 421), and a form is
  accepted from that address only. A proxy of your own in front of the
  listener has to pass the `Host` header on.
- Give the page a host name of its own. Browsers do not keep cookies apart by
  port, so with the host name of the main listener and another port, what
  stands in front of the main listener is sent the page's session cookie.
  ToolMesh warns at startup about such an address.
- `TOOLMESH_CREDENTIALS_BIND` needs a port from 1 to 65535.
- Without certificate files the listener speaks plain http: put a TLS proxy of
  your own in front of it, or use it on a network that is encrypted already.
  With them, ToolMesh looks at the files once a minute and loads them again
  after a change, so a renewed certificate needs no restart.
- The settings go together. ToolMesh does not start with
  `TOOLMESH_CREDENTIALS_URL` or the certificate files but no
  `TOOLMESH_CREDENTIALS_BIND`, with a listener but no address, with one of the
  two files alone, with files that hold no certificate, or with an address it
  cannot bind.
- In Docker, publish the listener's port on the address users reach it at.
  `docker-compose.override.yml.example` has the lines.
- A credential passes the page once, when it is stored. Calls take it from the
  store and send it from ToolMesh to the backend's API; it does not travel
  through the MCP endpoint.

The session cookie is marked `Secure` when the page's address
(`TOOLMESH_CREDENTIALS_URL`, otherwise `TOOLMESH_ISSUER`) is an `https` address
or the request arrived over https, directly or as `X-Forwarded-Proto: https`
from a proxy.

The page puts the comments `<!--email_off-->` and `<!--/email_off-->` around
its content. A Cloudflare zone with Email Address Obfuscation otherwise
replaces the mail addresses on the page and shows them again with a script,
which the page's Content-Security-Policy does not run: account labels that are
mail addresses would be unreadable.

### What to know before turning it on

- The values are in `user-credentials.json` in `TOOLMESH_DATA_DIR`. Each value
  is sealed with AES-256-GCM; user, backend, account, name, time and a short id
  of the key are readable. A value is padded to a multiple of 256 bytes before
  it is sealed, so the file does not tell a short password from a long one;
  a larger value, such as a service-account key, shows its size in steps of
  256 bytes. An
  entry copied to another user or account in the file does not open. Back the
  file up with the data directory, the key apart from it.
- If a proxy that someone else runs ends TLS in front of ToolMesh, it reads
  what users type into the page. Give the page
  [a listener of its own](#where-the-page-is-served) then.
- The file belongs to one process. Several instances do not share it.
- Accounts belong to a user id and outlive the user. Removing a user from
  `users.yaml` leaves their accounts in the file, unused; whoever is given
  that id later would call with them. ToolMesh warns at startup about accounts
  of users who cannot sign in. Before reusing an id, stop ToolMesh and remove
  its entries from `user-credentials.json`.
- A backend with user credentials is not monitored in the background: a
  background check has no user. `/health` and the metrics do not list it, and
  `<backend>_health` checks the caller's own account.
- Whoever operates the instance and holds the key can read the stored values.

## Timeouts

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_MCP_TIMEOUT` | `120` | HTTP client timeout in seconds for calls to downstream MCP servers |
| `TOOLMESH_EXEC_TIMEOUT` | `120` | Tool execution timeout in seconds — context deadline for a single backend call. Falls back to `TOOLMESH_ACTIVITY_TIMEOUT` if set (backwards compat). |
| `TOOLMESH_CODE_TIMEOUT` | `120` | Wall-clock budget in seconds for one `execute_code` run. Bounds a whole orchestration of `toolmesh.*` calls, so set it at least as high as the slowest backend timeout times the number of calls chained in one run (e.g. a committee of slow models). |
| `TOOLMESH_CODE_MAX_CONCURRENT` | `16` | `execute_code` runs in progress at once; `0` for no limit. One user may hold at most half of them, rounded up (8 with the default), so a single caller cannot keep every other user waiting; a run beyond that share is refused at once. A run that finds every slot taken waits up to 10 seconds for one and is then refused with an error result. On a deployment with a single user, that user can run half the limit in parallel; raise the limit there if needed. Must be an integer of `0` or more; anything else stops the server at startup. |

Increase these for backends that need more time, e.g. browser-based web fetchers processing heavy pages, or `execute_code` runs that fan out across several slow models:

```bash
TOOLMESH_MCP_TIMEOUT=180
TOOLMESH_EXEC_TIMEOUT=180
TOOLMESH_CODE_TIMEOUT=600
```

Each `execute_code` run gets its own JavaScript runtime (goja), which has no memory limit of its own. What bounds a run is its wall-clock budget, the cap of 50 `toolmesh.*` calls, a call-stack depth cap and `TOOLMESH_CODE_MAX_CONCURRENT`. A script that builds very large values inside one run is limited only by the memory of the process, so run ToolMesh with a container memory limit.

> Long tool calls no longer trip a "connector isn't responding" error: ToolMesh streams the `tools/call` response over SSE and emits keepalives while the backend works, so the MCP client's idle timer never fires mid-call. The per-request write deadline is also lifted for tool calls, so these timeouts — not the HTTP server's `WriteTimeout` — are the real bound.

## File Broker

The file broker holds files that tool calls pass around without sending their content through the conversation: `upload_file` fetches a public URL into it, `POST /files/upload` takes a file directly (multipart field `file`, optional `ttl`), and tools with a binary response (audio, images, PDFs) return a download URL under `/blobs/<id>` instead of the bytes. Files are kept in `blobs/` in the data directory for their TTL: 1 hour by default, at most 24 hours for uploads, at most 100 MB each. Files left there by a previous run are removed at startup, since the index of files lives in memory.

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_FILE_BROKER_ENABLED` | `true` | `false` switches the file broker off: `upload_file` is not offered, `/files/upload` and `/blobs/` answer `404`, and a tool with a binary response returns an error instead of a download URL. Must be `true` or `false`; anything else stops the server at startup. |
| `TOOLMESH_FILE_BROKER_MAX_TOTAL_BYTES` | `0` (no limit) | Bytes all files together may take. |
| `TOOLMESH_FILE_BROKER_MAX_BYTES_PER_USER` | `0` (no limit) | Bytes the files of one user may take. |

The two limits must be plain integers of bytes, `0` or more; anything else stops the server at startup. While the broker is on without `TOOLMESH_FILE_BROKER_MAX_TOTAL_BYTES`, the startup security-posture summary lists it as a relaxed control. Switch the broker off on an instance where callers have no files to exchange, such as a public demo.

- **Deleting a file.** `DELETE /blobs/<id>` needs MCP authentication and succeeds only for the user the file was created for, the same user it counts against. For anyone else it answers `404`, as for an unknown ID. A file created without a user cannot be deleted this way and goes after its TTL.
- **What counts.** A file counts from the moment it is written until it is deleted (`DELETE /blobs/<id>`) or removed after its TTL, which happens within a minute of the TTL running out. Uploads through `/files/upload` and `upload_file` count against the user who made the call, and so do binary responses of that user's tool calls.
- **A file that does not fit is refused.** `/files/upload` answers `507 Insufficient Storage`; `upload_file` and a tool with a binary response return an error. The message names the limit, the bytes already in use, and how to make room. A file of unknown length stops as soon as it reaches the limit, and nothing of it stays on disk. Each refusal is logged at `WARN` as `blob refused: file broker quota exceeded` with the `owner`.
- **Lowering a limit** keeps the files already stored; it only keeps new ones out until enough of them are gone.

## Backend Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `TOOLMESH_BACKENDS_CONFIG` | `/app/config/backends.yaml` | Path to backend configuration YAML |
| `TOOLMESH_POLICIES_DIR` | `/app/policies` | Path to output gate policy directory |

### Credential and host binding

Every REST backend is bound to its `backends.yaml` entry. The binding comes from the operator's configuration, never from the DADL: a DADL cannot read the credentials of another backend, and the hosts its own credentials go to are limited as described below.

A DADL is code you install. It decides which requests its backend sends with that backend's credentials, so load DADLs only from sources you trust, as you would a program. ToolMesh keeps the credentials of different backends apart. The host binding narrows where a backend's own credentials can go, as a second line of defense; it cannot make a malicious DADL safe, any more than a configuration can make a malicious ToolMesh build safe.

- **Credentials.** Each configured entry has a namespace: its `name` upper-cased with `-` as `_`, followed by `_` (entry `shelly-cloud`: `CREDENTIAL_SHELLY_CLOUD_*`). A credential belongs to the entry whose namespace is the **longest** that starts its name, so `CREDENTIAL_GITHUB_ENTERPRISE_TOKEN` belongs to an entry `github-enterprise`, not to an entry `github`. Every named entry counts, whatever its transport: REST and MCP entries in `backends.yaml`, units and the sub-backends in `unit.yaml`. A backend reads a credential only if its entry owns it, or if the entry lists it in `credentials:` or maps it with `env:`. A credential in no namespace, or in one that two spellings of an entry name share (`my-api`, `my_api`), belongs to no entry and must be listed. The division follows the configuration on every reload: adding an entry `github-enterprise` takes its credentials away from `github` at once. REST entries need a `name`; an entry without one is refused.
- **Hosts.** Credentials, session cookies, OAuth2 token requests and session logins go only to the host of the effective `base_url` (the entry's `url`, or the DADL's `base_url`) on its port (for an `http` `base_url` on port 80 also its `https` form on 443), to the other hosts of its registrable domain by the public suffix list on the default port, and to the entries of the entry's `allowed_hosts:` list. An entry is a host (`api.example.com`), a wildcard for any depth below a domain (`"*.example.com"`, quoted in YAML) or an IP address (`10.0.0.5`, `"[2001:db8::1]"`), each on the default port, or with `:port` (`files.example.com:8443`) on that port only. An entry with a scheme, a path or other text is a configuration error and the backend is not loaded. With an `https` `base_url`, credentials go out over https only. The public suffix list includes shared hosting domains: `googleapis.com`, for example, is such a suffix, so each Google API host is a domain of its own and needs `allowed_hosts`. Many shared SaaS domains whose customers each get a subdomain, such as `atlassian.net`, `zendesk.com` or `service-now.com`, are not on that list: there, the tenants of other customers count as the same registrable domain, and only the DADL keeps the credentials on your tenant. Use a DADL you have checked for such a service, or one whose tools all stay on the `base_url` host.
- **Checked at load.** The credentials the DADL's auth type reads (including `credential:<name>` in a session login body) and the scheme, host and port of `token_url`, absolute tool paths, an absolute health check path and the session login URL are checked when the backend is loaded, at startup and on every reload of `backends.yaml`. With `include_tools`, tools outside it are not checked: no request for them can be sent, and with `allow_private_url` their hosts do not count as destinations the configuration names. The health check tool is checked in any case. A backend that breaks the binding is not loaded: an `ERROR` line `backend refused` names it, each violation (with the entry that owns a refused credential), and the exact lines to add to its entry (`add_to_backends_yaml_entry`). The other backends keep running and ToolMesh starts; the startup security-posture summary lists the refused backends at `ERROR`. There is no global switch, only these per-entry lines.
- **Checked again at run time.** The same binding is enforced where credentials are injected, where token and login requests go out, and where the cookie jar of a session backend adds cookies, for every request and every redirect hop. When an entry sets no `url` and the DADL's own `base_url` is `http`, ToolMesh warns at load that credentials go out unencrypted. A `token_uri` that a `jwt_bearer` service-account credential supplies itself is operator data and is not checked.
- **Names.** A DADL names credentials with letters, digits and `_` only; other names, and parameter defaults of the form `credential:<name>`, are refused when the DADL is parsed. In `credentials:` and `env:` the same applies; `env:` keys are read in upper case, so `credential_foo` and `CREDENTIAL_FOO` are the same key, and an entry with both is refused.
- **No secret.** `credential: none` in an auth block is the placeholder of DADLs for APIs without authentication. It is never looked up and needs no binding.
- **Units.** REST sub-backends of a unit are bound the same way through their `unit.yaml` entries.

Examples of entries that need a line, with the entry named like the DADL:

```yaml
  - name: shelly-cloud            # reads shelly_auth_key, outside CREDENTIAL_SHELLY_CLOUD_*
    transport: rest
    dadl: shelly-cloud.dadl
    credentials: [shelly_auth_key]

  - name: youtube                 # token_url on oauth2.googleapis.com
    transport: rest
    dadl: youtube.dadl
    allowed_hosts: [oauth2.googleapis.com]
```

**Upgrading.** After an upgrade, backends whose DADLs read credentials outside their entry's namespace, or use hosts outside the registrable domain of their `base_url`, are refused until these lines are added. Check the log for `backend refused` after the first start, add the lines it names, and the next reload of `backends.yaml` loads them. A DADL with a credential name other than letters, digits and `_`, or with a parameter default `credential:<name>`, is refused when it is parsed and needs a change to the DADL itself.

### Backend hints

A backend entry can carry a `hint:`: what an agent must know before it uses this backend in this deployment, such as a naming convention or a page to read first. Say what the caller must do, not what the backend is; the description from the API definition already says that.

```yaml
backends:
  - name: wiki
    transport: rest
    dadl: wiki.dadl
    hint: >-
      Page names start with a type prefix and use lowercase words joined by
      underscores. Read the page naming_rules before you create or rename a page.
    hint_required_for: [write, dangerous, admin]
```

Without `hint_required_for` the hint is advice. ToolMesh attaches it to the first tool call each user makes into the backend and forgets on restart whom it has told. It cannot tell one conversation from the next, because an MCP request carries no session, so a second conversation of the same user gets no hint.

With `hint_required_for` the hint is a precondition and reaches every conversation:

- **Which tools.** The list names the access classes whose tools need the hint: `read`, `write`, `admin`, `dangerous` or a class a DADL defines. `all` covers every tool of the backend, including tools without a class.
- **Refusal.** A call to such a tool without proof is refused before it reaches the backend. The refusal carries the hint and one line of JavaScript: `toolmesh.assert_proofs(["<backend>:<digest>"]);`.
- **Proof.** An `execute_code` script that starts with that line may call the tools. The line holds for that one script; the agent keeps it in its conversation and puts it at the top of each script that needs it. A new conversation does not have the line, is refused once, and has the hint before its first such call.
- **Stopped script.** A script that meets the refusal stops at that call. The error says how many calls ran before it, so that the next run does not repeat them. The result lists those calls: read calls by the size of their result only, since the script reads again anyway, and all others in full. A script that asserts a proof that is no longer valid stops at that line, before any call.
- **Expiry.** The proof is a digest of the backend name, the hint text and the date (UTC). It expires at the end of the day and when you change the hint; the caller is then refused once more and gets the hint again. It holds across restarts, and across instances with the same configuration.
- **Audit.** The refusal is an audit entry with status `denied` and `hint_required` in its metadata. It comes after authorization: a caller that may not call the tool gets the authorization denial and not the hint.

Limits:

- The proof shows that the hint was delivered to the conversation. It does not show that the agent followed it, and it is no access control: who may call a tool is decided by [authorization](#authorization).
- A direct MCP call to such a tool (a tool listed under `expose_tools`) cannot carry a proof and is refused with the same text. Agents reach these tools through `execute_code`.
- A fixed script without a model behind it cannot react to the refusal. Do not list access classes that such callers use.
- Calls a composite tool makes on its own are not checked; the access class of the composite decides.
- `hint_required_for` without a `hint` is a configuration error: ToolMesh does not start with such a `backends.yaml`, and a reload keeps the previous backends.

### Requests to REST backends

These rules apply to every REST backend, whatever its `backends.yaml` options:

- **Redirects.** A redirect to the origin of the request (same scheme, host and port), or from `http` to `https` on the same host, is followed unchanged. A redirect from `https` to `http` is refused. A redirect to any other origin is refused when it would send the request body again (`307`, `308`) and otherwise followed with only content negotiation headers (`Accept*`, `User-Agent`, `Range`, conditional headers): injected credentials, other custom headers and the `Referer` are dropped. Once a hop has left the origin, the rest of the chain is treated as foreign, also a hop back to the original host. An API that needs credentials on another host has to name that host in its DADL.
- **Token and login requests** (`auth.type: oauth2` and `session`) never follow redirects. They use the same connection rules as tool calls: `allow_private_url` and `tls_skip_verify` apply to them too.
- **Session login URL.** `login.path` is appended to `base_url` and must stay on the host of `base_url` (with the same userinfo, if `base_url` has any); it has to start with `/`.
- **Path parameters.** The values `.` and `..` are refused, and a joined URL that leaves the scheme, host or path prefix of `base_url` is refused before any request is sent, as is a tool path that does not parse. Only a DADL tool path that is itself an absolute `http(s)` URL with a host addresses another host; its scheme, host and port must not contain a `{placeholder}`, which `lint-dadl` and the loader refuse. A `/` in a value is sent encoded (`%2F`) and stays one path segment, as `group%2Fproject` needs. A proxy in front of the API that decodes `%2F` before it normalizes the path could still turn `a%2F..%2Fb` into a traversal; such a proxy should not decode it.
- **Parameter types.** Arguments are checked against the declared DADL types before the [pre-execution gate](#gate-policies) runs: `boolean` takes only `true` or `false`, `integer` a whole number or a string of decimal digits with an optional sign, `number` a number or a plain decimal string, `array` and `object` their JSON forms, `string` a string, number or boolean but no array or object. The file types are passed as given. A mismatch is answered with an `invalid_input` error and never reaches the gate or the API. Accepted numeric strings become numbers (an integer beyond 2^53 stays a string), a number or boolean for a `string` parameter becomes the text the request carries (`42` becomes `"42"`, also in a JSON body), and declared defaults are filled in before the gate, so the gate and the API see the same values.
- **Error texts.** A transport error names only scheme and host of the request URL, never its path or query, which can hold a query-injected credential; this includes OAuth2 token and session login requests. The text of an error result has userinfo, query and fragment removed from every URL in it. The audit log and the tool result see the same reduced form.
- **Private addresses.** With `allow_private_url: false` a backend may not resolve to loopback, private, link-local, carrier-grade NAT (`100.64.0.0/10`), documentation, benchmarking (`198.18.0.0/15`), multicast or reserved addresses, nor to a NAT64 (`64:ff9b::/96`), 6to4 or IPv4-compatible (`::/96`) address embedding one of them, nor to site-local `fec0::/10`. `allow_private_url` defaults to `true` for backends in `backends.yaml`, since the operator configures their URLs. It covers only the destinations the configuration names: the host and port of `base_url` (or the `backends.yaml` `url`), of `token_url` and of absolute tool paths. Any other destination, such as the target of a redirect, must resolve to a public address, checked when the connection is made. The redirect and credential rules above hold either way.

### Results that are not ready yet

Some APIs answer a read with a 2xx status other than `200` while they are still preparing the result, and expect the same request again a little later. GitHub's repository statistics, for example, send `202` with an empty body until their cache is filled. Left alone, such a response is a success, and the caller gets the empty body as the result.

A DADL tool names these statuses in `not_ready_on`:

```yaml
get_stats_contributors:
  method: GET
  path: /repos/{owner}/{repo}/stats/contributors
  not_ready_on: [202]
```

- **What happens.** A response with a listed status is not passed on. ToolMesh sends the same request again under the tool's effective `errors.retry_strategy` and waits before each retry; without a declared strategy it retries three times with exponential backoff, starting at one second. A status from `errors.retry_on` that turns up in between draws on the same `max_retries`.
- **When the result does not arrive.** The call fails with the error code `not_ready` and the last status, so the caller can tell "ask again later" from an empty result. The waits count toward `TOOLMESH_EXEC_TIMEOUT`.
- **Where it is allowed.** On `GET` and `HEAD` tools only, with 2xx statuses other than `200`; a DADL whose tool declares it with another method or status is refused when it is parsed, as is the combination with a streamed binary response. On a write, `202` usually says the operation was accepted, and a second request would start it again. The key belongs to one tool: under `defaults` it is an unknown key, reported and ignored. A non-2xx status to retry belongs in `errors.retry_on`.
- **What it does not do.** It repeats one request. It does not follow a `Location` header, call another endpoint or read a job state from the body; an API that hands out a job to poll is outside its scope.

`not_ready_on` is a ToolMesh extension: DADL spec v0.2 does not define the key. A ToolMesh version that does not know it warns and ignores it, and the tool then returns the not-ready response as its result; a validator that checks strictly against the v0.2 schema rejects the file.

### Backend health checks

A DADL can declare a health check ([DADL spec §4.6](dadl-spec-v0.2.md#46-health-check-since-v02)):
the cheapest request that shows the API is reachable and the configured
credential works. Auth is injected as for every other call, so an expired
token shows up here instead of as a surprise `401` on the next real call. For
such a backend ToolMesh

- runs the check in the background at startup, after every `backends.yaml`
  reload and every 15 minutes, so a revoked or expired credential is reported
  before an agent needs the backend;
- offers it as the tool `<backend>_health`. It returns a standardized result
  instead of the API response, `{ok, http_status?, error_code?, latency_ms,
  checked_at, auth_expires_at?, error?}`, and never fails: a failed check is a
  successful call with `ok: false`. Like every tool it passes authorization; it
  is classified `access: read`. `discover_tools` lists it for a pattern but
  does not rank it in query mode, and neither does `toolmesh.discover()`;
- reports backends whose check fails, or whose credential is about to expire,
  on `/health` and in the [metrics](metrics.md#toolmesh_backend_health_up-gauge).

The check never runs as part of a regular tool call. Backends without a
declared check are not affected.

A backend with [credentials of users](#credentials-of-users) is the exception:
it is not checked in the background and does not appear on `/health` or in the
metrics, the polling and threshold settings of its `health_check` block have no
effect, and `<backend>_health` checks the caller's own account without counting
toward a state.

`health_check` in `backends.yaml` tunes the monitoring per backend. Every key
is optional:

```yaml
backends:
  - name: tailscale
    transport: rest
    dadl: tailscale.dadl
    health_check:
      interval: 1h                 # poll hourly (default: 15m, minimum 30s, 0 turns polling off)
      degrade_after: 2             # consecutive failures before the backend counts as degraded (default: 1)
      warn_before: 7d              # warning window before a known credential expiry (default: 7d)
      auth_expires_at: 2026-10-16  # when the credential expires, if the API does not say (ISO 8601)
      # enabled: false             # no checks and no /health entry; tailscale_health stays callable
```

Choose the interval by how soon you want to hear about a broken credential
and by what the API allows: every check is a real, authenticated request.
With `interval: 0` the check runs only at startup, after a reload, and
whenever someone calls `<backend>_health`. Every result, polled or on
demand, counts toward the backend's state. `auth_expires_at` covers APIs whose check endpoint does not report when
the credential expires, such as an API key with a fixed lifetime: record the
date when you issue the key. When the DADL extracts an expiry from the check
response (`auth_expires_path`), that value wins. Durations take Go syntax
(`90s`, `15m`, `12h`) or days (`7d`). A malformed value costs only that
setting and is logged at startup; the backend loads regardless.

#### What `/health` reports

`/health` answers `{"status":"ok"}` while every monitored backend passes.
Otherwise it names the affected backends:

```json
{
  "status": "degraded",
  "backends": {
    "tailscale": {
      "status": "degraded",
      "reason": "health check failing since 2026-10-30T09:15:00Z (2 consecutive): unauthorized (HTTP 401)",
      "checked_at": "2026-10-30T09:30:00Z",
      "failing_since": "2026-10-30T09:15:00Z"
    },
    "gitlab": {
      "status": "warning",
      "reason": "credential expires at 2026-11-03T00:00:00Z",
      "checked_at": "2026-10-30T09:00:00Z",
      "auth_expires_at": "2026-11-03T00:00:00Z"
    }
  }
}
```

`status` is `degraded` when any backend is degraded, `warning` when any is
inside its expiry window, `ok` otherwise. The HTTP status stays `200` in every
case, so a container liveness probe does not restart ToolMesh over an upstream
credential; have an uptime monitor check the `status` field instead (for
example a keyword or JSON query monitor). `/health` needs no authentication, so
it carries backend names and short reasons only: the semantic error code, the
HTTP status or the transport error, never response content.

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
