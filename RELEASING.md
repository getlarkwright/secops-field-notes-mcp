# Releasing

Installs come straight from the tagged GitHub repo, so a release is a tag.

## 1. Tag

    npm test                       # 12 cases, all must pass
    git tag -a vX.Y.Z -m "vX.Y.Z"
    git push origin vX.Y.Z

The install line in the README pins that tag; bump it in the same commit.

## 2. Official MCP registry

`server.json` validates against the 2025-12-11 schema. Publishing authenticates against the GitHub
namespace that owns this repo:

    npx @modelcontextprotocol/publisher login github
    npx @modelcontextprotocol/publisher publish

## 3. The directories people browse

- **mcp.so** — submission form, points at this repo
- **Smithery** — connects to the repo and builds from `package.json`
- **PulseMCP** — submission form
- **Glama** — indexes public repos on its own; submitting speeds it up
- **awesome-mcp-servers** — a pull request adding one line under the right category

## Version bumps

`package.json`, `server.json` and the install snippets in `README.md` all carry the version. Bump the
three together, re-run the tests, tag, then update the registry entry.
