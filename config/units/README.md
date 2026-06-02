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
