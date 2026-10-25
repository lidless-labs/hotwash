# hotwash-mcp

Model Context Protocol server for [Hotwash](https://github.com/solomonneas/hotwash). Lets any MCP-capable LLM list playbooks, start runs against incidents, advance steps, attach evidence, query the timeline, and review the Wazuh ingest suggestion queue.

Version 0.3.0 adds `hotwash_dismiss_suggestion`, completing the suggestion queue triage surface (list / get / accept / dismiss). Dismiss anchors the cooldown for that fingerprint, suppressing immediate re-fires of the same alert.

## What it exposes

| Tool | Purpose |
|------|---------|
| `hotwash_list_playbooks` | Browse the library, filter by category, tag, or search |
| `hotwash_get_playbook` | Fetch the full graph (nodes + edges) for one playbook |
| `hotwash_start_run` | Begin an execution from a playbook + incident title (+ optional context payload) |
| `hotwash_query_run` | Get current run state, optionally including the timeline |
| `hotwash_list_runs` | Read bounded existing-run inventory with an overflow sentinel |
| `hotwash_get_run_report` | Read the existing JSON report for a known run |
| `hotwash_list_cases` | Read one finite TheHive case inventory page |
| `hotwash_get_case` | Read selected fields for a known TheHive case ID |
| `hotwash_list_case_observables` | Read case-scoped complete hashes and file paths |
| `hotwash_list_case_comments` | Read existing internal-comment evidence |
| `hotwash_get_analyzer_job` | Read known job status and selected report evidence without launching |
| `hotwash_advance_step` | Update one step: status, assignee, append a note, or record a decision |
| `hotwash_attach_artifact` | Upload text or base64 artifact to a step |
| `hotwash_cancel_run` | Mark a run abandoned (requires `confirm: true`) |
| `hotwash_list_suggestions` | List Wazuh ingest suggestions, filter by state or mapping_id (read-only) |
| `hotwash_accept_suggestion` | Accept a pending suggestion, creating an Execution (requires `confirm: true`) |
| `hotwash_dismiss_suggestion` | Dismiss a pending suggestion and anchor its cooldown (requires `confirm: true`) |

### Investigation read contracts

The seven inventory/report tools above are read-only and work while mutations
are disabled. They use only finite Hotwash GET routes. The backend owns all
TheHive queries. TheHive must already be enabled and outside mock mode. No tool
accepts a URL, action name, query DSL, run attachment context or extra argument.

TheHive IDs begin with `~`, contain only alphanumerics after it and are at most
128 characters. Case lists and relations accept `offset` (0 to 10000) and `limit`
(1 to 100, default 50). Each invocation fetches one source page plus a sentinel.
Run inventory accepts optional `status`, `playbook_id` and `limit` (1 to 100,
default 50). It uses the existing API inventory with one extra row. It does not
scan contexts or establish finding identity.

Results retain observation time, coverage and gaps. `has_more: false` means no
sentinel was observed, with query semantics and visibility still unverified.
`returned` counts projected rows. A relation can omit unsupported types or
non-internal comments and report the gap. MCP output cuts set
`coverage: "incomplete"`, add `mcp_output_truncated` and retain `_truncated`.
Oversized results that cannot fit the result bound return an error. The five
TheHive reads validate response identities, observation time, coverage, gaps,
page counters, requested bounds and selected facts before returning success.
Unapproved fields, including raw dictionaries and upstream links, are excluded.
Malformed envelopes return a sanitized read error.

All seven new reads put a warning before one named
`<untrusted_hotwash_read_data>` envelope. `structuredContent` contains only
`warning` and `untrusted_data`, with the latter holding the same envelope as
text output. Its JSON encodes angle brackets as `\u003c` and `\u003e`, so source
text cannot insert a closing delimiter. Consumers can recover source text with
JSON decoding and must retain the data boundary when forwarding it. Comments,
tags and report claims cannot authorize a tool call. This boundary does not
guarantee injection immunity. Other tools retain their existing result format.

Run reports retain selected IDs from recorded TheHive `create_case`,
`add_observable` and `run_analyzer` attachments under
`recorded_connector_evidence`, including job status. Each carries
`association: "unverified"` and a `connector_association_unverified` gap.
These records supply evidence for follow-up reads. They cannot establish a
dedup anchor or authoritative run-to-case linkage. Unsupported, malformed or
already-truncated connector results have explicit omission gaps. Raw result
dictionaries and their URLs are excluded.

Known analyzer jobs are read by ID through the configured TheHive connector.
CIRCLHashlookup_1_1 and MISP_2_1 reports retain bounded taxonomy claims and known
trust/event evidence. Missing or unsupported reports retain job ID/status with
gaps. Lookup misses and successful jobs keep an unknown verdict. This read path
does not launch, relaunch or poll an analyzer.

Authoritative legacy finding identity, run-to-case linkage and deployed query
coverage remain unverified. These tools support evidence reporting. This slice
adds no SOC create, append, comment, analyzer launch, closure or approval tools.
See [TheHive read contracts and primary sources](../docs/THEHIVE-INTEGRATION.md#bounded-investigation-reads).

## Install

```bash
npm install -g hotwash-mcp
```

Or run directly with `npx hotwash-mcp` once published.

## Configuration

Environment variables:

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `HOTWASH_URL` | no | `http://localhost:8000` | Base URL of the Hotwash API |
| `HOTWASH_API_KEY` | yes if API auth is on | - | Sent as `X-API-Key` |
| `HOTWASH_TIMEOUT` | no | `30` | Request timeout in seconds |
| `HOTWASH_MCP_ALLOW_MUTATIONS` | no | `false` | Operator switch for state-changing tools. While unset, the server is read-only: start, advance, cancel, attach, accept, and dismiss refuse to run. |
| `HOTWASH_MCP_MAX_RESPONSE_BYTES` | no | `5242880` | Largest backend response body the server will read |

### Safe defaults

- **Read-only until enabled.** The six state-changing tools refuse to run unless
  the operator sets `HOTWASH_MCP_ALLOW_MUTATIONS=true` in the server environment.
  Read tools always work. For a hard guarantee, also give the server a
  read-scope backend key (`HOTWASH_READ_ONLY_API_KEY` on the API side).
- **Typed, bounded results.** Every result carries `structuredContent` next to
  the text output. The seven investigation reads use the envelope above.
  Free-text fields are cut at 2000 characters and lists at 200
  items. `_truncated` reports what was dropped.
- **Untrusted content is labeled.** Other tools list values copied from alerts,
  playbooks, run notes and evidence under `_untrusted.fields`. Treat them as data,
  never as instructions or as approval for a tool call.
- **Annotations.** Each tool declares `readOnlyHint`, `destructiveHint`,
  `idempotentHint`, and `openWorldHint`.
- **Bounded backend calls.** Redirects are followed only within the configured
  backend origin (up to three hops), and response bodies are read through a byte
  limit.

## Client setup

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "hotwash": {
      "command": "npx",
      "args": ["-y", "hotwash-mcp"],
      "env": {
        "HOTWASH_URL": "http://localhost:8000",
        "HOTWASH_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add hotwash -e HOTWASH_URL=http://localhost:8000 -e HOTWASH_API_KEY=your-api-key -- npx -y hotwash-mcp
```

### OpenClaw

In `~/.openclaw/openclaw.json` under `mcpServers`:

```json
"hotwash": {
  "command": "npx",
  "args": ["-y", "hotwash-mcp"],
  "env": {
    "HOTWASH_URL": "http://localhost:8000",
    "HOTWASH_API_KEY": "your-api-key"
  }
}
```

### Hermes Agent

In `hermes.toml`:

```toml
[mcp.servers.hotwash]
command = "npx"
args = ["-y", "hotwash-mcp"]
env = { HOTWASH_URL = "http://localhost:8000", HOTWASH_API_KEY = "your-api-key" }
```

### Codex CLI

In `~/.codex/config.toml`:

```toml
[mcp_servers.hotwash]
command = "npx"
args = ["-y", "hotwash-mcp"]
env = { HOTWASH_URL = "http://localhost:8000", HOTWASH_API_KEY = "your-api-key" }
```

## Example session

```
You: List the incident response playbooks we have
LLM: (calls hotwash_list_playbooks)
LLM: We have 4 playbooks. Want me to start a run against one for an active incident?

You: Yes, the Wazuh SOC playbook for "Suspicious login from PROD-DB-01"
LLM: (calls hotwash_start_run with playbook_id and incident_title)
LLM: Started execution #12. The first phase is "Detection". The first step is "Identify
     affected systems" - want me to mark it in_progress and capture what you find?

You: Yes, mark it in progress. I just pulled the Wazuh agent inventory; here it is...
LLM: (calls hotwash_advance_step status=in_progress, then hotwash_attach_artifact
     filename=wazuh-inventory.json text=...)
```

## Running locally

```bash
git clone https://github.com/solomonneas/hotwash.git
cd hotwash/mcp
npm install
npm run build
HOTWASH_URL=http://localhost:8000 HOTWASH_API_KEY=dev-key node dist/index.js
```

The server speaks MCP over stdio. To smoke-test, point a compatible client at the built binary.

## License

MIT - see the root [LICENSE](../LICENSE).

## HTTP mode

Build with `npm run build` in `mcp/`, then run from the repository root:

```bash
node mcp/dist/index.js --http
```

Without `--http`, the existing stdio transport is unchanged. HTTP uses stateful
Streamable HTTP sessions at `/mcp`. `GET /healthz` returns only `{"status":"ok"}`
without authentication. All MCP requests require a bearer token.

| Variable | Default | Purpose |
|----------|---------|---------|
| `HOTWASH_MCP_HTTP_TOKEN` | required | Dedicated HTTP bearer token, at least 32 characters, distinct from the upstream API key and URL credentials |
| `HOTWASH_MCP_HTTP_HOST` | loopback | Specific listener bind address. Wildcard addresses are refused |
| `HOTWASH_MCP_HTTP_PORT` | `3118` | Listener port |

Keep the token in a secret store or a mode `0600` environment file. The HTTP
listener rejects untrusted Host and Origin headers before authentication, limits
bodies to 1 MiB and sessions to 128, and expires sessions after 30 idle minutes.
Request and header timeouts are 30 and 10 seconds. SIGTERM and SIGINT close
sessions and the listener. Binding beyond loopback requires a trusted deployment
with suitable network controls and TLS termination. Browser Origins are limited
to loopback origins.

### Claude Code over HTTP

```json
{
  "mcpServers": {
    "hotwash": {
      "type": "http",
      "url": "http://localhost:3118/mcp",
      "headersHelper": "/path/to/helper HOTWASH_MCP_HTTP_TOKEN"
    }
  }
}
```

The helper reads the named environment variable and prints a JSON object such as
`{"Authorization":"Bearer ..."}`. Keep the token out of checked-in client config.

### Codex over Streamable HTTP

```toml
[mcp_servers.hotwash]
url = "http://localhost:3118/mcp"
bearer_token_env_var = "HOTWASH_MCP_HTTP_TOKEN"
```

Export the token in the client environment. The server uses the same token from
its own environment.

### Shared incident state and artifact access

Runs, step state, artifacts, and suggestions belong to the Hotwash backend
and its database. They are intentionally shared between authorized agents
working on the same incident, as they already are across separate stdio
processes. Every mutation names an execution/node or suggestion explicitly.
There is no MCP-process current-run pointer, pending approval queue, deferred
tool set, shared mutable cache, or rate limiter. State-changing tools run only
when the operator sets `HOTWASH_MCP_ALLOW_MUTATIONS=true`. That switch is server
configuration, so no tool argument or upstream text can turn it on. Each HTTP
session gets a fresh MCP server and API client. Cancellation, suggestion
acceptance, and dismissal require `confirm: true` on every call. One client's
confirmation cannot authorize another call. HTTP sessions are protocol isolation,
not separate user accounts: token holders use the same upstream API identity
and may deliberately operate on the same backend records. Coordinate concurrent
edits to the same step using the backend's existing semantics.

`hotwash_attach_artifact` uploads only the text or base64 bytes supplied in the
call. `filename` is an upload label and `source_ref` is an opaque reference.
Neither causes local file reads or URL fetching, in either transport. No HTTP
local-file opt-in is needed because no local-path input exists.

### Example user service

See [hotwash-mcp-http.service](../docs/systemd/hotwash-mcp-http.service).
Place upstream configuration and the dedicated HTTP token in
`~/.config/hotwash-mcp/http.env`, with directory mode `0700` and file mode `0600`.
Adjust the example installation paths before using it. The service example
uses `NoNewPrivileges=true`, `PrivateTmp=true`, and `UMask=0077`.
