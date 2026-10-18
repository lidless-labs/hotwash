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
| `hotwash_advance_step` | Update one step: status, assignee, append a note, or record a decision |
| `hotwash_attach_artifact` | Upload text or base64 artifact to a step |
| `hotwash_cancel_run` | Mark a run abandoned (requires `confirm: true`) |
| `hotwash_list_suggestions` | List Wazuh ingest suggestions, filter by state or mapping_id (read-only) |
| `hotwash_accept_suggestion` | Accept a pending suggestion, creating an Execution (requires `confirm: true`) |
| `hotwash_dismiss_suggestion` | Dismiss a pending suggestion and anchor its cooldown (requires `confirm: true`) |

## Install

```bash
npm install -g hotwash-mcp
```

Or run directly with `npx hotwash-mcp` once published.

## Configuration

Two environment variables:

| Variable | Required | Default | Notes |
|----------|----------|---------|-------|
| `HOTWASH_URL` | no | `http://localhost:8000` | Base URL of the Hotwash API |
| `HOTWASH_API_KEY` | yes if API auth is on | - | Sent as `X-API-Key` |
| `HOTWASH_TIMEOUT` | no | `30` | Request timeout in seconds |

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
| `HOTWASH_MCP_HTTP_TOKEN` | required | Dedicated HTTP bearer token, distinct from the upstream API key and URL credentials |
| `HOTWASH_MCP_HTTP_HOST` | loopback | Listener bind address |
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
tool set, shared mutable cache, rate limiter, or write-enable flag. Each HTTP
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
