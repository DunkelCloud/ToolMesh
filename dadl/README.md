# Bundled DADLs

ToolMesh ships with a small set of DADL files that work out of the box —
public APIs that require **no credentials and no setup**. They exist so a
fresh `docker compose up` can demonstrate a working tool call immediately.

## Included

| File | API | Auth |
|---|---|---|
| `hackernews.dadl` | Hacker News (Firebase) — stories, comments, users, live feeds | none |
| `algolia-hn-search.dadl` | Algolia Hacker News Search — full-text search across HN | none |

To enable one of them, copy `config/backends.yaml.example` to
`config/backends.yaml` and add an entry:

```yaml
backends:
  - name: hackernews
    transport: rest
    dadl: hackernews.dadl
```

Restart ToolMesh, and tools like `hackernews_get_top_stories` are available
to your AI agent — no API key required.

## Adding more DADLs

ToolMesh does **not** bundle DADLs that require credentials. Instead, browse
the public registry and pick what you need:

**[dadl.ai/browse](https://dadl.ai/browse)**

Drop the `.dadl` file into this directory, register it in
`config/backends.yaml`, set the credential in `.env`, and restart. The DADL
file itself tells you which `CREDENTIAL_*` variable to use.

A `.gitignore` in this directory tracks **only** the bundled files
(`hackernews.dadl`, `algolia-hn-search.dadl`, this README, the `.gitignore`
itself). Anything else you place here stays untracked, so `git pull` and
branch switches won't touch your own DADLs.

## Why so few?

The registry is the source of truth for DADLs and evolves faster than
ToolMesh releases. Bundling many DADLs would create version drift between
what's shipped and what's current. Bundling only the no-auth ones gives a
useful demo without coupling ToolMesh releases to the registry's pace.
