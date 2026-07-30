---
status: accepted
date: 2026-07-30
---

# DADL Spec Versioning & Forward Compatibility

## Context and Problem Statement

DADL files and DADL consumers evolve independently. The spec has a frozen v0.1
(cited externally and pinned by published files) and a growing v0.2 draft; consumers
range from the ToolMesh runtime to publish-time validators (registry CI, `dadl
validate`, linters). A file written against a newer spec revision will inevitably
meet an older consumer — and vice versa.

Two questions follow. First: what does a consumer do with a key it does not know —
reject the file, ignore the key silently, or something in between? Second: how does
a file express that it genuinely *needs* a capability, so that "something in
between" cannot silently produce wrong or unsafe behavior? A minimum-runtime-version
declaration has been requested for exactly this purpose.

The stakes are uneven across fields. Ignoring an unknown documentation-only field
(`returns`, `deprecated`) degrades nothing but comfort. Ignoring an unknown
`response.redact` would silently expose the secrets the author explicitly masked —
a security regression caused by *tolerance*.

## Decision Drivers

- v0.1 is frozen and citable; published files must keep validating unchanged.
- Spec evolution should be additive; a lockstep upgrade of every consumer for every
  spec release is not realistic.
- Silent degradation is unacceptable for load-bearing fields (redaction,
  idempotency) but harmless for advisory ones.
- Publish-time validation must be deterministic and strict — a typo
  (`idempotencv:`) must fail CI, not ship as a silently ignored key.
- Private/local DADL files that never pass through a registry must keep working.

## Considered Options

1. **Strict everywhere.** Every consumer rejects unknown keys. Safe against typos
   and silent degradation, but breaks forward compatibility completely: every
   additive spec release makes existing runtimes reject new files until upgraded.
2. **Lenient everywhere.** Every consumer silently ignores unknown keys (classic
   HTML/CSS model). Maximum compatibility, but typos ship to production and
   load-bearing fields degrade silently — the `redact` failure mode.
3. **Split by context, plus explicit requirements** (chosen). Strict at publish
   time, warn-and-ignore at runtime, and a `requires:` block through which a file
   opts specific capabilities into fail-closed handling.

## Decision Outcome

Option 3. The policy, normatively specified in spec v0.2 Section 15.3:

| Context | Unknown key handling |
|---------|---------------------|
| Publish-time validation (registry CI, `dadl validate`, linters) | reject (error) |
| Runtime consumers (ToolMesh) | warn and ignore |
| Underscore-prefixed keys (`_*`) | always silently ignored (YAML anchor workspace) |

Complemented by a top-level `requires:` block:

```yaml
requires:
  toolmesh: ">=0.9.0"          # semver range — minimum runtime version
  features: [redact, jwt_bearer]  # feature identifiers defined by spec releases
```

A runtime that cannot satisfy every entry MUST refuse to load the file
(fail-closed) with a message naming the missing capability. Each spec release
defines the feature identifiers it introduces (v0.2: `refresh_token`, `jwt_bearer`,
`authorization_code`, `refresh_token_rotation`, `health`, `returns`, `idempotency`,
`deprecation`, `semantic_errors`, `redact`, `composites`, `file_url`).

`requires.features` is preferred over `requires.toolmesh` for portability: it names
the capability rather than one implementation's version number, so non-ToolMesh
consumers can evaluate it too. The version range remains available for
implementation-specific needs (e.g. a known runtime bug fixed in a given release).

Authoring rule: files MUST declare `requires.features` for every feature whose
silent absence would change semantics dangerously (`redact`, `idempotency`,
`refresh_token_rotation`); documentation-only features need not be declared.

Spec versions themselves stay additive within the 0.x line: every valid v0.1 file
is a valid v0.2 file, and the `spec:` URL pins which schema a file validates
against. Capability changes always produce a new spec version — v0.1 stays frozen.

### Consequences

- Good: additive spec releases do not break deployed runtimes; new files run on old
  runtimes with visible warnings instead of hard failures.
- Good: typos and unspecified fields cannot enter the registry — one strict schema
  serves CI, linter, and CLI.
- Good: security-relevant fields cannot silently degrade; `requires` turns
  tolerance off exactly where tolerance is dangerous.
- Cost: the feature-identifier list becomes part of each spec release and must be
  maintained; runtimes must track which identifiers they implement.
- Cost: authors carry a duty (declare `requires` for load-bearing features) that
  validators can only partially enforce — a linter can warn when `redact` is used
  without being declared, but not for semantics it cannot see.
- Cost (bootstrap limitation): the fail-closed guarantee of `requires` binds only
  consumers that implement `requires` itself. A consumer predating spec v0.2 sees
  an unknown top-level key and ignores it under its own policy; the `spec:` URL is
  the only signal it can act on. Inherent to introducing the mechanism; spec
  Section 15.3 documents it, and consumers warn on newer-than-implemented spec
  URLs as the mitigation.

## More Information

Normative text: DADL spec v0.2, Sections 15.2–15.4. The canonical JSON Schema
(`docs/schema/dadl-v0.2.schema.json`, published at https://dadl.ai/schema/v0.2.json)
implements the strict publish-time profile. Related: ADR-0001/0002 establish the
same fail-closed posture for credential and policy resolution.
