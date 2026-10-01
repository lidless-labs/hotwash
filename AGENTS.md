# Repository Guidance

## Definition of Done
Before reporting any change complete, run the single verification entrypoint and report actual output:

```bash
./scripts/verify
```

It runs all component gates in order, so one green run covers any change (live tests stay auto-skipped).

Per-component mapping, for reference when narrowing a failure:
- Backend or shared change: `.venv/bin/python -m pytest api/tests/ -v` from the repo root (106 tests, live tests auto-skipped). Test dependencies are pinned in `requirements-test.txt`, which includes the API dependencies in `requirements.txt`, and installed in the repo venv (`python3 -m venv .venv && .venv/bin/pip install -r requirements-test.txt`). The system python has older versions and is not the supported test environment.
- Parser change: also `python3 api/tests/run_parser_tests.py` (or `make test`, which runs both).
- MCP change: `cd mcp && npm run typecheck`; packaging change: also `cd mcp && npm run build`.
- Frontend change: `cd web && npm test && npm run build` (vitest covers the client-side parsers).

Report actual results. If anything fails, report the failure verbatim and do not claim success.

## Project Shape
- Hotwash is an incident response runbook builder: Markdown and Mermaid playbooks become interactive flowcharts with a step-by-step execution engine and SOAR integrations.
- Three components in one repo:
  - `web/` - React 18 + TypeScript + Vite frontend (React Flow canvas, Zustand store). Works fully offline, backend optional. Dev server on port 5177.
  - `api/` - FastAPI backend on port 8000. Entry point `api/main.py`, routers in `api/routers/`, parsers in `api/parsers/`, integration clients in `api/integrations/clients/` (TheHive), SQLite via SQLAlchemy.
  - `mcp/` - `hotwash-mcp` npm package, an MCP server (Node >= 20) that drives playbook runs and the Wazuh ingest suggestion queue. Entry point `mcp/src/index.ts`, tools in `mcp/src/tools/`.
- Docs live in `docs/` (ARCHITECTURE, CONFIGURATION, THEHIVE-INTEGRATION, WAZUH-INGEST).
- Targeted backend tests: `python3 -m pytest api/tests/test_<area>.py -v`.

## Hard Prohibitions
- Pushing: never use `--no-verify`. `hooks/pre-push` runs content-guard against `policies/public-repo.json` from `~/repos/content-guard`. If it flags a leak, fix the content, then push.
- Failing test or gate: never weaken, skip, or delete it to get green. Fix the cause, or report the failure.
- Unsure about a command, endpoint, or API fact: do not invent it. Read the code (`Makefile`, `package.json` scripts, `api/routers/`) first; if still unverifiable, say so.
- Blocked by sandboxing, auth, or a missing tool: report the exact blocker and stop. Do not work around it.

## Live-Service Safety
- Touching TheHive integration: `api/tests/test_thehive_live.py` hits real infrastructure. It requires `HOTWASH_LIVE_THEHIVE_URL` and `HOTWASH_LIVE_THEHIVE_API_KEY` and runs only with explicit `-m live` (`api/tests/conftest.py` skips `live`-marked tests otherwise). Do not run against live unless the user explicitly asks in this session; otherwise rely on the auto-skipped suite.
- Touching outbound integration URLs: they are SSRF-guarded in `api/security.py` (RFC1918, loopback, and link-local blocked by default; `HOTWASH_PRIVATE_HOST_ALLOWLIST` CIDRs open private ranges for lab use, loopback and link-local never). Do not weaken the guard; add lab hosts via the allowlist env var instead.
- Touching credentials: integration secrets are encrypted at rest via `api/crypto.py`. Keep credential handling inside `api/security.py` and `api/crypto.py`, and never log or print raw API keys.

## Gotchas
- Writing a test that needs live infrastructure: mark it `live`, or it will run by default and fail.
- Looking for frontend lint: there is none; `web/package.json` has `dev`, `build`, `preview`, `test`. Do not invoke scripts that are not there.
- Setting env vars: frontend uses `VITE_*` in `web/.env`; backend vars go in `api/.env` (see `docs/CONFIGURATION.md`).
- Changing MCP code: the package publishes from `mcp/dist/` only, built with tsup. `npm run lint` and `npm run typecheck` are both `tsc --noEmit`, so running either is sufficient.

## Memory Handoff
At the end of any substantial task, write a handoff note to `.claude/memory-handoffs/` using that directory's `TEMPLATE.md`.
Record durable discoveries, gotchas, and decisions. Do not wait to be reminded.
