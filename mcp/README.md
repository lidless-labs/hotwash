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
