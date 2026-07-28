---
status: proposed
date: 2026-06-11
---

# Credential-Override Resolution in ToolMesh

## Context and Problem Statement

ToolMesh injects backend credentials server-side at call time. A logical credential
(for example the token for a given backend) may exist at several levels: specific to
a user, shared within a tenant, or a global fallback. Something has to decide which
concrete credential applies for a given `(user, tenant)` request.

That precedence logic can live in two places: inside the secret store (relying on
each store's own hierarchy/override features), or inside ToolMesh (store-agnostic).
ToolMesh supports pluggable credential stores with very different capabilities — from
a built-in environment-variable store to external secrets managers — so where the
resolution lives determines how portable the feature is.

## Decision Drivers

- Pluggable credential stores: some have rich hierarchy/override features, some have
  none.
- Consistent precedence semantics regardless of the configured store.
- Keep the store's required capabilities minimal and portable.
- Least privilege: a store fetch should not depend on store-specific session features
  that a server-side (machine) identity cannot use.

## Considered Options

1. **Resolve in the secret store.** Use each store's native override mechanism.
   Behavior then varies per store, depends on features a machine identity may not be
   able to use, and is unavailable for simple stores.
2. **Resolve in ToolMesh (store-agnostic)** (chosen).

## Decision Outcome

The `user → tenant → global` fallback for backend credentials is resolved **inside
ToolMesh**, via resolution paths in the `CredentialStore` interface — not in the
secret store. The store only has to provide **hierarchical key/value lookup with
per-identity ACLs**; ToolMesh owns the precedence order.

This keeps the semantics identical across every store — from the built-in
environment-variable store to external secrets managers such as HashiCorp Vault or
OpenBao — needs no store-specific override features, and works with a server-side
machine identity.

### Consequences

- Good: any key/value-capable store works; precedence is uniform and testable in one
  place.
- Good: simple deployments (built-in store) get the same model as advanced ones.
- Cost: ToolMesh, not the store, owns the resolution logic and its correctness (path
  ordering, caching, invalidation).

## More Information

Extended by [ADR-0002](0002-per-user-settings-and-policy-resolution.md), which
generalizes this resolution to settings and enforcements (credential resolution is
the `setting`-kind special case of that resolver).
