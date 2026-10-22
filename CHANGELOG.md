# Changelog

All notable changes to Hotwash. The `hotwash-mcp` npm package keeps its own
version line (`mcp-v*` tags); entries here cover the whole repo.

## [Unreleased]

### Changed
- Wazuh `run_active_response` is closed by default: it needs a nonempty
  `HOTWASH_WAZUH_AR_COMMANDS` allow-list (`403` otherwise), `"confirm": true`
  on every request, and supports `"dry_run": true`.
- The API enforces confirmation itself: accepting or dismissing a suggestion
  and deleting an execution need `confirm=true`, and abandoning an execution
  needs `"confirm": true` in the body. The web UI and MCP server send it.
- `HOTWASH_READ_ONLY_API_KEY` adds a read-scope key and `HOTWASH_READ_ONLY=true`
  limits every key to read scope. Scope is enforced for all key-gated routes.
- Live execution sockets authenticate with a short-lived ticket from
  `POST /api/executions/:id/live-ticket`. The `api_key` query parameter is no
  longer accepted (the `X-API-Key` header still works for non-browser clients).
- The web UI no longer reads `VITE_HOTWASH_API_KEY` in production builds. The
  key is entered in the settings panel and kept for the browser session.
- Upstream responses from TheHive, Wazuh, and webhook targets are read through
  a byte limit (`HOTWASH_MAX_UPSTREAM_BYTES`, default 5 MiB).
- `hotwash-mcp`: state-changing tools require `HOTWASH_MCP_ALLOW_MUTATIONS=true`
  (read-only by default); results include `structuredContent`, are bounded, and
  label upstream-written fields as untrusted; tools declare all four annotation
  hints; the backend client follows redirects only within its own origin and
  reads responses through a byte limit (`HOTWASH_MCP_MAX_RESPONSE_BYTES`).
  `hotwash_list_playbooks` now returns `{count, playbooks}` instead of a bare
  array, and `hotwash_list_suggestions` caps `limit` at 200.

### Added
- TheHive `run_analyzer` SOAR action: launches a Cortex analyzer on an
  observable through TheHive's Cortex link
  (`POST /integrations/thehive/actions/run_analyzer`), with strict id
  validation, a client method, connector dispatch, mock response, and docs.
  It launches only; no job polling or analyzer listing.
- "Suspicious Binary Triage" seed playbook: Wazuh rootcheck hit to evidence
  collection, TheHive case, Cortex hash analyzers, a manual package-verify
  evidence step, and SOC-owner-gated false-positive and close-out decisions.
  The approval gate is advisory in Hotwash until owner-identity approval
  exists: Hotwash does not authenticate approvers and callers share one API key.
- Maintainer-health docs: `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, GitHub issue templates (bug + feature), an issue
  config that disables blank issues and links the website and security
  policy, and a pull-request template with a no-PII / content-guard check.
- README rewritten lead-first around the incident-response + MCP
  differentiator, with a website link, a copyable MCP client config block,
  and the full verified `hotwash_*` tool list.
- Tag-triggered npm publish job for `hotwash-mcp` (tags `mcp-v*` / `v*`)
  with a skip-if-already-published guard and npm provenance.
- `HOTWASH_CORS_ORIGINS` env var: CORS origins are now configurable, with
  localhost-only defaults and narrowed methods/headers.
- TheHive integration: live `create_case`, `create_alert`, and
  `add_observable` SOAR actions with a structured client, Pydantic request
  schemas, and an opt-in live smoke test (`-m live`).
- Connector interface for live SOAR actions: registered connectors expose
  action schemas and dispatch through generic integration endpoints, with
  TheHive behind the contract, a new `http_webhook.post_json` connector, and
  optional action-result evidence attached to run steps.
- Wazuh connector: authenticated manager API client, agent query actions,
  active-response trigger action, mock payloads, and an opt-in live smoke
  test.
- Wazuh ingest hardening: route-aware forwarder template that serves
  multiple mappings from one integration script.
- GitHub Actions CI running the full `scripts/verify` gate.
- Web test suite: vitest coverage for the client-side markdown parser,
  wired into `scripts/verify`.
- `scripts/verify`: single verification entrypoint for all components.

### Changed
- Backend dependencies repinned (FastAPI 0.136, Pydantic 2.13, pytest 9)
  and installed via a repo venv; the verify gate prefers `.venv` python.
- Web bundle split into app + react + react-flow chunks (main chunk
  617 kB -> 321 kB).
- README quickstart, badges, roadmap prose, and Makefile targets brought
  back in line with the actual tree and ports.

### Fixed
- First-run playbook seeding no longer depends on a hardcoded OpenClaw
  workspace path; seeds ship under `api/seed_data/playbooks` and
  `HOTWASH_PLAYBOOK_SEED_DIR` overrides the source directory.
- Markdown link hrefs are sanitized before render: playbook content can no
  longer smuggle a `javascript:`/`vbscript:`/`data:` link (stored XSS), and
  inline rendering is length-capped against a quadratic-regex tab freeze.
- Wazuh active-response can be restricted with a `HOTWASH_WAZUH_AR_COMMANDS`
  allow-list, and a partial failure (`failed_items`) is surfaced instead of
  being recorded as a successful action.
- HTTP webhook connector rejects `..`/`%2e` path traversal and fails on a
  stored credential that cannot be decrypted instead of sending unauthenticated.
- A completed/abandoned run's step status and decisions are frozen (409);
  reopening a completed step clears its stale `completed_at` in both the router
  and the replay reducer.
- Mermaid parsing: a shaped re-mention upgrades a node's label/type (a decision
  no longer stays a step), subgraph steps survive round-trip export, and a
  duplicate node id no longer creates an unreachable step that blocks 100%.
- SSRF guard closes the DNS-rebinding TOCTOU: integration fetches now
  resolve once, validate every resolved address, and connect to the
  pinned IP with the original hostname kept for Host/SNI; redirects on
  outbound integration requests are disabled.
- Generated API key and Wazuh seed secret are no longer written to logs
  at debug level; deployment docs now require `HOTWASH_API_KEY`.
- SSRF guard now blocks IPv6 private, loopback, and link-local targets.
- `case_id` values are validated and URL-encoded to block path injection.
- TheHive `status` reads the top-level version field of TheHive 5.4.
- MCP server strips draft-07 `$schema` from `tools/list` for Anthropic
  client compatibility.

### Removed
- Unused `Markdown` pin (clears the PYSEC-2026-89 advisory; nothing
  imports the package).
- Tracked runtime SQLite database (`api/data/playbooks.db`) removed from
  the repo and scrubbed from history; the API seeds itself on startup.
- Stale `web/public/index.html` duplicate.

## v0.2.2 and earlier

Tagged before this changelog existed. See the git history of the tags
`v0.2.0` through `v0.2.2` and `mcp-v0.3.0`.
