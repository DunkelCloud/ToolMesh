# Releasing ToolMesh

The version is not stored in a file. `make build` derives it from
`git describe --tags` and injects it into `internal/version` via `-ldflags`;
the Docker workflow passes the tag name as `VERSION`. A release is therefore a
tag on `main` plus the artifacts that hang off it.

## Steps

1. Update `CHANGELOG.md`: rename `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`, add
   a fresh, empty `[Unreleased]` above it, and check `git log vPREV..main`
   against the section — every commit with user-visible effect needs an entry.
   A change that rejects something the previous release accepted gets a
   **Behavior change** note at the top of the section.
2. Open a pull request with the CHANGELOG change (`main` is protected; direct
   pushes are rejected) and squash-merge it once CI is green.
3. Tag the resulting commit on `main` and push the tag:
   `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
4. The tag push triggers two workflows:
   - `.github/workflows/docker.yml` publishes `ghcr.io/dunkelcloud/toolmesh`
     with the tags `X.Y.Z`, `X.Y`, and `latest` (no `v` prefix —
     `docker/metadata-action` strips it).
   - `.github/workflows/mcp-registry.yml` waits for that image and then
     publishes version `X.Y.Z` to the MCP registry (below).

   Check both runs under *Actions*, and verify the image with
   `docker pull ghcr.io/dunkelcloud/toolmesh:X.Y.Z` before announcing it.
5. Create the GitHub release for the tag: title `vX.Y.Z — <user-visible
   focus>`, body from the CHANGELOG section, behavior and breaking changes
   first, and the image tags that actually exist.

## MCP registry

ToolMesh is listed as `io.github.DunkelCloud/toolmesh` in the
[official MCP registry](https://registry.modelcontextprotocol.io). The listing
is [`server.json`](../server.json) in the repository root; its `version` must
equal the release version without the `v` prefix, and the entry with
`isLatest: true` is the one clients see. The file carries no secrets — the
registry publishes it verbatim. The committed `version` is only the last
published one; the workflow overwrites it from the tag.

### Automated publish on tag push

`.github/workflows/mcp-registry.yml` runs on every `v*` tag push and

1. derives the version from the tag (`v0.4.1` → `0.4.1`) and refuses anything
   that is not a release version;
2. polls the public manifest endpoint of `ghcr.io/dunkelcloud/toolmesh` until
   the image with that version exists (up to 15 minutes) — the Docker workflow
   runs in parallel on the same push, and the registry must never advertise a
   version whose image does not exist;
3. installs a pinned `mcp-publisher` (version and SHA-256 sit together at the
   top of the job), writes the version into `server.json`, validates it,
   authenticates with `mcp-publisher login github-oidc`, and publishes;
4. reads the entry back from the registry API and fails if the version is not
   listed (listed but not `isLatest` only warns).

Authentication is GitHub Actions OIDC: the registry grants publish rights for
`io.github.<repository_owner>/*` to any workflow of a repository under that
owner, so the job needs `id-token: write` and nothing else — no stored token
and no personal account. That matters: the registry maps a personal GitHub
login to an organization namespace only if the user is an org owner *and* the
org-membership lookup made with the registry's GitHub App returns the org. On
2026-09-24 that lookup did not return `DunkelCloud` for the owner account, so
a local publish under `io.github.DunkelCloud/*` was refused with 403.

If the tag-triggered run failed, or a version has to be published later, run
the same workflow by hand: *Actions* → *MCP Registry* → *Run workflow* on
`main`, with the version (without `v`) as input. The image for that version
must already exist on ghcr.io.

### Manual publish (fallback)

Only works for an account that the registry maps to the organization
namespace (see above). From the repository root:

```bash
mcp-publisher login github                # device flow; registry tokens are short-lived
jq --arg v X.Y.Z '.version = $v' server.json > server.json.tmp && mv server.json.tmp server.json
mcp-publisher validate
mcp-publisher publish
curl -s "https://registry.modelcontextprotocol.io/v0/servers/io.github.DunkelCloud%2Ftoolmesh/versions" \
  | jq '.servers[] | {version: .server.version, meta: ._meta["io.modelcontextprotocol.registry/official"]}'
```

The token files `mcp-publisher` leaves behind (`.mcpregistry_*`) are
git-ignored; do not commit them.
