---
status: proposed
date: 2026-06-22
---

# Per-User Settings and Policy Resolution

## Context and Problem Statement

ToolMesh resolves per-user backend credentials through a `user → tenant → global`
fallback (see ADR-0001). Beyond credentials, two further kinds of per-user
configuration recur:

- **Values / preferences** that should *override* from most specific to least
  (e.g. connection settings, default targets, output preferences).
- **Security enforcements** that must only ever *narrow* (e.g. the set of mailbox
  folders a tool may touch, size/rate limits, the set of permitted tools).

Authorization is currently tool-granular (user → plan → tool); resource-level
scoping (such as folder restrictions) has no home yet. We need one predictable model
that covers both kinds of configuration without letting a user-editable value widen
a security boundary.

## Decision Drivers

- One mechanism for all declarative per-(user|tenant|global) configuration.
- A user must never be able to widen an administrator-defined boundary.
- Enforcements change over time; effective behavior must track those changes without
  rewriting stored user data.
- Secrets and non-secret policy have different confidentiality, ownership and audit
  needs.

## Considered Options

1. **Single resolution mode (most-specific-wins) for everything.** Simple, but a
   user-level value would *override* — i.e. widen — an enforcement: a privilege
   escalation foot-gun.
2. **Validate/clamp user input at write time** against the current ceiling. Destroys
   user intent when ceilings change and creates a second enforcement point that can
   drift from the runtime check.
3. **Two resolution modes, evaluated only at runtime** (chosen).

## Decision Outcome

Per-(user|tenant|global) configuration is resolved by a typed resolver with **two
modes**, selected per key by a declared `kind`:

- **Settings** — bottom-up `user → tenant → global`, most-specific-wins, with
  per-leaf deep-merge (a user value must not erase tenant defaults).
- **Enforcements** — top-down `global → tenant → user`, combined toward the most
  restrictive value per type: set → intersection, numeric ceiling → `min`, numeric
  floor → `max`, boolean permission → `AND`. The effective scope is the universe
  granted by the resource intersected with every layer.

**Enforcements bound settings:** enforcements are resolved first, then each setting
is clamped or rejected against them (e.g. a default-folder preference must lie within
the allowed-folder enforcement).

**Resolution happens only at runtime.** The write path is a dumb, per-level store of
raw intent: no write-time validation or clamping (syntactic checks only). All
intersection and clamping is performed at request time in the gate. Consequently an
over-broad user value is inert (it grants nothing), enforcements can change without
rewriting user data, and there is exactly one enforcement point. The only write-time
guard is a per-level ACL: a user may write user-level entries; tenant and global
entries are administrator-owned.

**Secrets and policy are stored separately.** Secrets remain in the encrypted
credential store; settings and enforcements live in a separate policy store. This
keeps the encryption boundary clean, allows per-file ACLs (user-writable secrets vs.
administrator-owned ceilings), uses the right combiner per store, and keeps policy
auditable in clear text.

Pattern syntax for path-like scopes (e.g. mailbox folders) is an anchored,
separator-aware glob (`exact`, `*` for one level, `**` for a subtree) — not raw
regular expressions, which are easy to mis-anchor and can cross the hierarchy
separator. Inputs are canonicalized before matching and rejected on ambiguity
(fail-closed). Operations that touch more than one resource (for example a *move*
with a source and a destination folder) check **every** resource argument
independently; the operation proceeds only if all arguments pass.

This decision extends ADR-0001: credential resolution is the `setting`-kind special
case of the same resolver.

### Consequences

- Good: one model covers both preferences and security boundaries; user
  self-restriction is safe by construction; effective policy tracks ceiling changes
  automatically.
- Good: the credential store becomes a client of the resolver rather than a bespoke
  mechanism.
- Scope: this covers **declarative** configuration only. Runtime/derived state (token
  refresh, rate counters, last-used timestamps) is explicitly out of scope and is not
  inherited.
- Cost: two combiners and a per-key schema (`kind`, `type`, `owner`, `sensitive`)
  must be specified and maintained; empty-vs-unset semantics and per-type neutral
  elements must be defined carefully and fail closed.

## More Information

Extends [ADR-0001](0001-credential-override-resolution-in-toolmesh.md)
(Credential-Override-Resolution).
