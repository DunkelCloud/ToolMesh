# Unit-Backends

This directory holds **active** unit-backends. ToolMesh scans every
direct child here at startup and loads any directory that contains a
`unit.yaml`. The scan is **not** recursive — `examples/`, `tests/`,
notes, fixtures, anything one level deeper is ignored, so shipped
examples never auto-activate.

## Enabling an example

Examples live under `examples/<name>/`. To run one, copy or symlink it
into this directory:

```bash
# Copy
cp -r examples/dice ./dice

# Or symlink (so updates to the example flow through)
ln -s examples/dice ./dice
```

Then restart ToolMesh. The unit's tools appear on the MCP wire under
the `<unit>_<tool>` prefix (e.g. `dice_roll`).

## Writing your own

A unit is a directory with:

- `unit.yaml` — declares the unit's name, the path to its JavaScript
  implementation, the `expose` block (audit level, surfaced meta
  signals), and an optional `backends:` list of private sub-backends.
- `<name>.js` — JavaScript module that defines a top-level
  `describe()` function (returns the tool list) plus one exported
  function per tool.

See `examples/dice/` for the smallest possible version
(pure JavaScript, no sub-backends).

## Promoting unit tools to the MCP root

By default a unit's tools are reachable through `discover_tools` and
`execute_code`, like every other backend. To also advertise selected tools
directly at the MCP root — skipping the discovery round-trip for
high-frequency entry points — list them under `expose.tools`:

```yaml
unit: federated_internal
implementation: ./federated_internal.js
expose:
  audit: full
  tools:
    - search            # advertised at the root as federated_internal_search
```

Unlike the `expose_tools` field on `backends.yaml` entries, unit tools are
always promoted under their full `<unit>_<tool>` name, never a bare alias:
unit tool names are frequently generic (`search`, `roll`), so the prefixed
form is what keeps the root surface unambiguous. A listed name that matches
no `describe()` tool is logged at load time and skipped.
