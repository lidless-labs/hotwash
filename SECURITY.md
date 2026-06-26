# Security Policy

## Supported versions

Hotwash is WIP. Only the latest commit on the `main` branch, and the latest
published `hotwash-mcp` release on npm, receive security fixes. Pin to a tagged
release if you need a known-good version.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems. Email
**me@solomonneas.dev** with: <!-- content-guard: allow pii/email -->

- A short description of the issue.
- Steps to reproduce (or a minimal proof of concept).
- The version, commit, or `hotwash-mcp` release you tested against.
- Whether you would like to be credited in the release notes.

You should get an acknowledgment within 72 hours. If you do not, please follow
up - the mail may have been filtered.

## In scope

- Authentication or authorization flaws in the FastAPI backend (`api/`),
  including the API-key check and the HMAC verification on `POST /api/ingest/wazuh`.
- Server-side request forgery (SSRF) in the SOAR integration clients
  (`api/integrations/`), including DNS-rebinding, redirect, and private-address
  bypasses.
- Path traversal or injection via `case_id` and other values forwarded to
  external platforms (for example TheHive).
- Secrets (API keys, HMAC seeds, integration tokens) leaking into logs,
  responses, or the repository.
- Confused-deputy or missing-confirmation flaws in the `hotwash-mcp` MCP server
  that let an agent take destructive actions (cancel a run, accept or dismiss a
  suggestion) without the documented `confirm: true` gate.
- CORS or origin-validation weaknesses that expose the backend to untrusted
  browser origins.

## MCP server drives a real backend

`hotwash-mcp` is a thin client over the Hotwash REST API. It is only as
trusted as the backend you point `HOTWASH_URL` at and the credentials in
`HOTWASH_API_KEY`. Treat the MCP server as something that can start, advance,
and abandon real incident-response runs:

- Destructive tools (`hotwash_cancel_run`, `hotwash_accept_suggestion`,
  `hotwash_dismiss_suggestion`) refuse to act unless the caller passes
  `confirm: true`. A report that bypasses this gate is in scope.
- Do not point the server at a backend you do not control, and do not put a
  privileged API key in an MCP config that an untrusted agent can read.

## Out of scope

- Bugs in third-party dependencies (FastAPI, React, React Flow, the MCP SDK).
  Report those upstream; we will bump the pin once a fix is released.
- Issues that require an attacker to already have write access to the host, the
  repo, or the deployment's environment variables.
- SOAR action *templates* that a team customizes incorrectly. The built-in
  actions are starting points, not hardened production integrations.
- Denial of service from sending the backend obviously malformed or oversized
  input, absent a concrete amplification or auth-bypass angle.

## Disclosure

We aim to ship a fix within 14 days of confirming a valid report. A coordinated
disclosure timeline can be negotiated for issues that need longer.
