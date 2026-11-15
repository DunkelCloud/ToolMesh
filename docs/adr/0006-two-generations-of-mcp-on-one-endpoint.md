---
status: accepted
date: 2026-11-15
---

# Two Generations of MCP on One Endpoint

## Context and Problem Statement

MCP revision 2026-07-28 changes how a client and a server open: there is no
`initialize` handshake and no session any more. Every request names its
revision and the client's capabilities in the `_meta` of its params, and
repeats the revision, the method and the tool name in HTTP headers
(`MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name`) so that a proxy can route
on them without reading the body. A request of the older revisions carries
none of that, and a client of the older revisions cannot open without
`initialize`. The two are incompatible on the wire in both directions.

ToolMesh sits in the middle twice. Clients connect to its MCP endpoint, and it
connects as a client to the MCP servers configured as backends. On both sides
it meets counterparts of both generations, for at least as long as the
revision's own deprecation window runs.

How does one instance serve clients of both generations, and reach backends of
both, without an operator having to know which is which?

## Decision Drivers

- An upgrade of ToolMesh breaks no client and no backend that worked before.
- An operator sets nothing per client or per backend.
- Nothing is kept between two requests, so that instances behind a load
  balancer need no session affinity. That was already so and stays so.
- What the headers of a request say is what gets executed. A proxy in front
  may admit, limit or route by the headers alone.
- A caller without a valid credential learns nothing from the protocol
  checks.

## Considered Options

1. **The new revision only.** Clients and backends of the older revisions stop
   working with the upgrade. The specification names no way for an older
   client to move forward on its own.
2. **A setting** that says which generation the endpoint, or a backend,
   speaks. One instance then serves one generation of clients, and the
   operator has to find out what each backend speaks and keep that current.
3. **Both generations at once, decided per request** from the request alone
   on the endpoint, and by asking the newer way first towards a backend.

## Decision Outcome

Chosen option: **3**.

**The endpoint.** A request that names a revision in the `_meta` of its
params is checked against its `MCP-Protocol-Version` header: both have to be
there and say the same. With revision 2026-07-28 the request is served
without a handshake; the client capabilities in `_meta`, the `Mcp-Method`
header and, on `tools/call`, the `Mcp-Name` header are required, and each
header has to say what the body says. A header that occurs twice is not read
at all, since a proxy and ToolMesh could each pick another of the two values.
A request that names no revision in its body, and none or one of the older
revisions in its header, is served exactly as before; `initialize` keeps
answering with 2025-11-25. Such a request has no routing headers and none is
asked of it, but one that carries them is held to them as well: otherwise a
request could get past a proxy on its headers and past this check by leaving
the revision out. Anything else is refused: `400` with
`HeaderMismatch`, with invalid params, or with the revisions ToolMesh speaks,
and `404` for a method the revision of the request does not have. Requests of
the older generation keep their answers, down to the status `200` for a
JSON-RPC error, so that nothing changes for clients that work today.

The checks run after authentication and before anything of the request is
executed.

**Results.** Results of revision 2026-07-28 carry `resultType` and the
server's name and version. The tool list and the discovery result carry
`ttlMs` and `cacheScope: "private"`. The tool list is filtered by what the
caller may use, so a cache that callers share must never hold it; the
discovery result is the same for everyone, but is only given to authenticated
callers and stays private for that reason. The tool list is built by walking
the backends in the order of their names, so that it is the same bytes on
every request.

**Change notifications.** ToolMesh sends none and says so in its
capabilities. `subscriptions/listen` is acknowledged with an empty set of
notifications and ended with the result the specification gives a server for
ending a subscription. Nothing is held open per caller.

**Backends.** The adapter asks `server/discover` first and falls back to
`initialize`. Over HTTP every request is a connection of its own, so the
fallback needs nothing more. A child process is one connection for its whole
life, and a server of the older generation may say nothing to a request
before `initialize` or end on it; a stdio backend whose first attempt fails
is started again and gets the handshake directly. That such a backend needs
the handshake is remembered until the handshake fails.

ToolMesh announces no client features to a backend. A backend that asks its
client for input anyway, by a request of its own or by answering a tool call
with `input_required`, gets none: the call fails with a message that names
what was asked for. A backend that is reached over the deprecated HTTP+SSE
transport, or that asks for roots or sampling, is reported in the log once,
which tells an operator which backends a later removal will concern. A
backend is not reported for announcing the logging capability: servers built
with an SDK announce it whether they log or not, and the first run against
real servers named every one of them.

The `x-mcp-header` keyword of a backend's tool schema is honored on the
request to that backend and removed from the schema ToolMesh lists. It
describes the hop between ToolMesh and the backend; passed on, it would make
callers of ToolMesh owe headers for a hop it was never about.

### Consequences

- Good: clients and backends of either generation work against one instance,
  and an operator configures nothing for it.
- Good: a request that says one thing in its headers and another in its body
  is never executed, whatever stands in front of ToolMesh.
- Good: the counter `toolmesh_mcp_requests_total` shows which revisions the
  clients of an instance speak, which is what tells an operator when the
  older generation can go.
- Bad: two code paths on the endpoint until the older generation is dropped.
  Dropping it is a decision of its own and needs that counter at zero.
- Bad: a stdio backend of the older generation that stays silent before
  `initialize` costs up to ten seconds at the first connect after a start.
- Limit: a request of the older generation is recognized by what it lacks.
  A client that sends `MCP-Protocol-Version: 2026-07-28` but no `_meta` is
  refused, not served as an older one.
- Limit: tools of a backend that need input from the client cannot be used
  through ToolMesh.
- Limit: the routing headers name what the client calls at the endpoint. A
  call of `execute_code` names `execute_code`; the tools its script calls
  appear in no header and are decided inside ToolMesh.

### Confirmation

- Tests drive the endpoint with the client of the official Go SDK in both
  generations, and with hand-written requests for every refusal; the refusals
  of a `tools/call` check that the tool was not called.
- Tests connect the adapter to a server that has no `initialize` at all, and
  to stdio servers of the older generation that stay silent or end before
  `initialize`.
- A test asks for the tool list of twelve backends fifty times and compares
  the bytes.
- A run of the built binary against clients built with the Go SDK before and
  after the revision, and against stdio and HTTP backends of both
  generations, before the change was merged.

## More Information

- MCP specification, revision 2026-07-28: versioning and compatibility,
  Streamable HTTP transport, caching, multi round-trip requests,
  subscriptions.
- [docs/configuration.md](../configuration.md#protocol-revisions) for what an
  operator sees.
