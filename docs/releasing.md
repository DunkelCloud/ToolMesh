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
4. The tag push triggers `.github/workflows/docker.yml`, which publishes
   `ghcr.io/dunkelcloud/toolmesh` with the tags `X.Y.Z`, `X.Y`, and `latest`
   (no `v` prefix — `docker/metadata-action` strips it). Verify with
   `docker pull ghcr.io/dunkelcloud/toolmesh:X.Y.Z` before announcing it.
5. Create the GitHub release for the tag: title `vX.Y.Z — <user-visible
   focus>`, body from the CHANGELOG section, behavior and breaking changes
   first, and the image tags that actually exist.
6. Publish the new version to the MCP registry (below).

## MCP registry

ToolMesh is listed as `io.github.DunkelCloud/toolmesh` in the
[official MCP registry](https://registry.modelcontextprotocol.io). The listing
is a `server.json` whose `version` must equal the release version without the
`v` prefix; the entry with `isLatest: true` is the one clients see. The file
carries no secrets — the registry publishes it verbatim — so it can live in the
repository root.

Manual publish with [`mcp-publisher`](https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/cli/commands.md):

```bash
mcp-publisher login github                # device flow; registry tokens are short-lived
mcp-publisher validate server.json
mcp-publisher publish server.json
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=toolmesh" \
  | jq '.servers[] | {version: .server.version, meta: ._meta["io.modelcontextprotocol.registry/official"]}'
```

The `.mcpregistry_*` token files the tool leaves in the working directory are
git-ignored.

### Coupling the publish to the tag push (proposed)

The registry accepts GitHub Actions OIDC for `io.github.<owner>/*` namespaces,
so the publish can run from a workflow without any stored secret. Either a
separate workflow on `push: tags: ["v*"]`, or — preferably — a job in
`docker.yml` with `needs: build`, so the registry never advertises a version
whose image does not exist yet:

```yaml
  publish-mcp-registry:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: build
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # OIDC token for the registry
      contents: read
    steps:
      - uses: actions/checkout@v6
      - name: Install mcp-publisher
        env:
          # Pin; bump deliberately. Assets: mcp-publisher_<os>_<arch>.tar.gz
          MCP_PUBLISHER_VERSION: v1.8.1
        run: |
          curl -sSfL "https://github.com/modelcontextprotocol/registry/releases/download/${MCP_PUBLISHER_VERSION}/mcp-publisher_linux_amd64.tar.gz" \
            | tar -xz mcp-publisher
      - name: Set version from the tag
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          jq --arg v "$VERSION" '.version = $v' server.json > server.tmp && mv server.tmp server.json
      - name: Publish
        run: |
          ./mcp-publisher login github-oidc
          ./mcp-publisher publish server.json
      - name: Verify isLatest
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          curl -sSf "https://registry.modelcontextprotocol.io/v0/servers/io.github.DunkelCloud%2Ftoolmesh/versions" \
            | jq -e --arg v "$VERSION" \
                '.servers[] | select(.server.version == $v) | ._meta["io.modelcontextprotocol.registry/official"].isLatest'
```

With this in place the committed `server.json` only needs its `version` kept
as a placeholder; the job overwrites it from the tag, so a release cannot
drift from the registry again.
