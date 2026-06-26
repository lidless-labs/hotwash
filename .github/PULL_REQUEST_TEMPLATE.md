<!--
Thanks for sending a patch. Keep this short; delete sections that do not apply.
See CONTRIBUTING.md for what lands easily and what needs an issue first.
-->

## What and why

<!-- One or two sentences on the user-visible change and the problem it solves. -->

Closes #

## Component

- [ ] Web app (React frontend)
- [ ] Backend (run engine / REST API)
- [ ] hotwash-mcp (MCP server)
- [ ] Wazuh ingest
- [ ] Parsers (Markdown / Mermaid)
- [ ] SOAR actions / integrations
- [ ] Docs

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor with no API/tool surface change
- [ ] Surface change (REST API shape, MCP tool name/semantics, or ingest contract) — opened an issue first per CONTRIBUTING.md

## Checklist

- [ ] `./scripts/verify` passes locally (backend pytest, web vitest, MCP typecheck/build)
- [ ] Added or updated tests covering the change
- [ ] Updated the `Unreleased` section of `CHANGELOG.md` for any user-visible effect
- [ ] No personal details, hostnames, real private IPs, account names, tokens, or unredacted absolute paths in code, tests, fixtures, docs, or this PR. Example IPs use RFC 5737 (`192.0.2.0/24`).
- [ ] Integration changes keep the SSRF guard intact (resolve once, validate every address, pin the IP, refuse private/loopback/link-local)
- [ ] Conventional commit messages, no AI co-authorship trailers
