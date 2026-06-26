# Contributing to Hotwash

Hotwash is an incident-response runbook tool: a React web app, a FastAPI run engine, and the `hotwash-mcp` MCP server, in one repo. It is WIP, and patches are welcome. Before you start, please skim this file so we both spend our time on the right things.

## Repo layout

| Path | What it is | Toolchain |
|------|------------|-----------|
| `web/` | React 18 + TypeScript + Vite frontend | Node, npm, vitest |
| `api/` | FastAPI backend: run engine, REST API, ingest, integrations | Python 3.12, pytest |
| `mcp/` | `hotwash-mcp` npm package (MCP server) | Node >= 20, tsup, tsc |
| `docs/` | Architecture, configuration, integration, ingest notes | Markdown |

## What kinds of changes land easily

- **Bug fixes** in the run engine, the Markdown/Mermaid parsers, the ingest matcher, or the MCP tool wrappers.
- **Test coverage** for any of the above (pytest for the backend, vitest for the web parser).
- **Docs**: sharper integration notes, clearer setup, corrected examples.
- **New MCP tool wrappers** over existing REST endpoints, with the same error handling and confirmation gating as the current tools.
- **New SOAR action templates** or a new integration client that follows the SSRF-safe pattern in `api/integrations/`.

## What needs a conversation first

- **Breaking changes to the REST API shape** that the web app and `hotwash-mcp` both depend on. Open an issue describing the user story first.
- **Renaming or removing an MCP tool**, or changing a tool's confirmation semantics. Agents wire these by name.
- **Changes to the Wazuh ingest contract** (the HMAC scheme, mapping fields, or cooldown semantics).
- **New runtime dependencies**, especially in `mcp/` - the MCP server is intentionally small (just the MCP SDK and zod).

## What does not land

- Personal details, hostnames, real private IPs, account IDs, tokens, or live auth profiles in code, tests, docs, or fixtures. Use `192.0.2.0/24`, `198.51.100.0/24`, or `203.0.113.0/24` (RFC 5737) for example IPs. The `content-guard` check is run before publishing and will flag these.
- SSRF regressions in integration clients. Outbound fetches must resolve once, validate every resolved address, pin the IP, and refuse private, loopback, and link-local targets.
- Secrets written to logs at any level.
- AI-co-authorship trailers on commits (`Co-Authored-By: <model>`). Conventional commits only.

## Local dev

```bash
git clone https://github.com/solomonneas/hotwash.git
cd hotwash

# Backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn api.main:app --port 8000

# Frontend
cd web && npm install && npm run dev

# MCP server
cd mcp && npm install && npm run build
```

## Verifying your change

There is a single verification entrypoint that mirrors CI:

```bash
./scripts/verify
```

It runs the backend pytest suite, the web vitest suite, and the MCP typecheck/build. The GitHub Actions `CI` workflow runs the same gate on every push and pull request. Please make sure it passes locally before you open a PR.

If you touched only one component, you can run its checks directly:

```bash
.venv/bin/pytest api/tests          # backend
cd web && npm test                  # web parser tests
cd mcp && npm run typecheck && npm run build   # MCP server
```

## Filing issues

Please use the templates under `.github/ISSUE_TEMPLATE/`. Before posting output, remove tokens, private hostnames, real private repo names, and unredacted absolute paths.

## License

By contributing you agree that your contribution is licensed under the MIT License, same as the rest of the repo.
