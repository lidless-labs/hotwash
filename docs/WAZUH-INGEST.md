# Wazuh Ingest

## Overview

Wazuh's integration block POSTs alerts to Hotwash. Hotwash matches each
alert against a mapping table and either auto-starts a run, queues a
suggestion for review, or logs the receipt only.

## Configuring Wazuh

Add an `<integration>` block to `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <integration>
    <name>hotwash</name>
    <hook_url>https://hotwash.example/api/ingest/wazuh</hook_url>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```

The integration script must send `X-Hotwash-Mapping-Id` and
`X-Hotwash-Signature` headers. Hotwash verifies the signature against the
claimed mapping's secret and re-matches the alert against that mapping
only, so a forwarder that serves several mappings has to route each alert
to the mapping that owns its rule id. Template for
`/var/ossec/integrations/custom-hotwash.py` (pair it with a copy of one of
the stock `/var/ossec/integrations/` shell wrappers named `custom-hotwash`,
both `root:wazuh` mode `750`):

```python
#!/usr/bin/env python3
import hashlib, hmac, json, sys, urllib.request

ALERT_FILE, _, HOOK_URL = sys.argv[1], sys.argv[2], sys.argv[3]
SECRET = "replace-with-mapping-secret"  # content-guard: allow api-key-assignment
ROUTES = {
    "23505": "1",  # rule_id -> mapping_id
    "5710": "2",
}

with open(ALERT_FILE, "rb") as f:
    body = f.read()

rule_id = str(json.loads(body).get("rule", {}).get("id", ""))
mapping_id = ROUTES.get(rule_id)
if mapping_id is None:
    sys.exit(0)  # not ours; keep ossec.conf <rule_id> as the noise filter

sig = hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
req = urllib.request.Request(HOOK_URL, data=body, method="POST", headers={
    "Content-Type": "application/json",
    "X-Hotwash-Mapping-Id": mapping_id,
    "X-Hotwash-Signature": "sha256=" + sig,
})
urllib.request.urlopen(req, timeout=10).read()
```

Keep the `<rule_id>` list in the `<integration>` block and the `ROUTES`
table in sync; the block decides which alerts reach the script, the table
decides which mapping signs and receives each one.

## Creating a mapping

```bash
curl -X POST https://hotwash.example/api/ingest/mappings \
  -H "X-API-Key: $HOTWASH_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Wazuh CVE level 10",
    "playbook_id": 1,
    "mode": "suggest",
    "rule_id_pattern": "23505",
    "rule_groups_pattern": "vulnerability-detector",
    "agent_name_pattern": null,
    "cooldown_seconds": 300,
    "hmac_secret": "replace-with-mapping-secret"
  }'
```

Patterns are CSV-of-exacts (case-insensitive). `null` or empty means wildcard.
Highest specificity wins, ties broken by oldest `created_at` then smallest `id`.

## Payload shape

Hotwash reads the nested `rule.{id, level, description, groups}` and
`agent.{id, name}` fields, which is what Wazuh's `<integration>` block
POSTs natively. Pattern matching is keyed on those nested values. The
Wazuh management API and tools like `wazuh-mcp` return a flattened
envelope (`rule_id`, `agent_id`, `rule_groups` at top level) for query
results; if you smoke-test from those, translate to the nested shape
first or no mapping will match.

## Trigger modes

- `auto`: starts an `Execution` immediately. Alert exposed at
  `context.wazuh_alert`. Returns `201` with `execution_id`.
- `suggest`: queues an `IngestSuggestion` for human review. Returns `200`
  with `suggestion_id`.

  **Listing pending suggestions:**

  ```bash
  # All pending (default)
  curl -H "X-API-Key: $HOTWASH_API_KEY" \
    https://hotwash.example/api/ingest/suggestions

  # Filter by state and mapping
  curl -H "X-API-Key: $HOTWASH_API_KEY" \
    "https://hotwash.example/api/ingest/suggestions?state=pending&mapping_id=3"

  # Full detail for one suggestion (includes parsed alert_payload, mapping ref, playbook_title)
  curl -H "X-API-Key: $HOTWASH_API_KEY" \
    https://hotwash.example/api/ingest/suggestions/42
  ```

  **Accepting a suggestion** (creates an Execution, idempotent):

  ```bash
  curl -X POST -H "X-API-Key: $HOTWASH_API_KEY" \
    https://hotwash.example/api/ingest/suggestions/42/accept
  # Returns: {"execution_id": 17, "already_accepted": false}
  # Re-accept returns the same execution_id with "already_accepted": true
  ```

  **Dismissing a suggestion** (anchors cooldown, optional reason):

  ```bash
  curl -X POST -H "X-API-Key: $HOTWASH_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"reason": "noise - known scanner activity"}' \
    https://hotwash.example/api/ingest/suggestions/42/dismiss
  ```

- `off`: logs the receipt only. Returns `200` with `status: ignored`.

## HMAC scheme

- Headers: `X-Hotwash-Mapping-Id: <int>`, `X-Hotwash-Signature: sha256=<64-hex>`.
- Signing input: raw request body bytes.
- Comparison: constant-time (`hmac.compare_digest`).
- Bare 64-hex without the `sha256=` prefix is accepted too.

```bash
printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}'
```

Body cap is 256 KB (`413` over). `X-Hotwash-Mapping-Id` is required (`400`
if missing). Bad signature, unknown mapping, or disabled mapping all
return `401` with the same opaque message.

## Cooldown

Fingerprint is `sha256(mapping_id:rule_id:agent_id)`. Default window is
`300s`, set per mapping via `cooldown_seconds`, rotatable via PATCH. The
suppression log doubles as the cooldown anchor: `dispatched_auto`,
`dispatched_suggest`, `cooldown`, and `suggestion_dismissed` rows count.
`no_match` and `mode_off` do not, so flipping a mapping on does not silently
swallow the next alert.

Dismissing a suggestion writes a `suggestion_dismissed` row to the suppression
log, anchoring the cooldown window for that fingerprint. This prevents the same
alert fingerprint from immediately re-queueing after a dismiss - useful for
confirmed noise where you want the cooldown clock to start from the review
decision rather than the original ingest time.

## Suggestion lifecycle

Suggestions move through three states:

- `pending` - created on ingest, awaiting a review decision.
- `accepted` - a human (or an authorized agent) called POST /accept. An
  Execution was created with the original alert in `context.wazuh_alert`,
  identical to what `mode=auto` would have produced. The suggestion's
  `accepted_execution_id` field links it to that run.
- `dismissed` - a human called POST /dismiss. No Execution is created.
  The cooldown is anchored via the suppression log so the fingerprint
  does not immediately re-queue.

**State transitions:**

```
pending --[POST /accept]--> accepted   (creates Execution)
pending --[POST /dismiss]--> dismissed (anchors cooldown)
```

Neither transition is reversible. There is no path from `accepted` or
`dismissed` back to `pending`.

**Idempotency:** POST /accept is safe to call more than once. If the
suggestion is already accepted, the response returns the existing
`execution_id` plus `"already_accepted": true` with a `200` status. No
duplicate Execution is created.

**Error responses (409):** The accept endpoint returns `409 Conflict` in
four situations:

| Scenario | Message |
|----------|---------|
| Already accepted | `suggestion already accepted` |
| Already dismissed | `suggestion already dismissed` |
| Concurrent modification during accept | `concurrent modification - retry` |
| Underlying playbook deleted after suggestion was queued | `inconsistent state - playbook unavailable` |

Dismiss does not produce 409; calling dismiss on an already-dismissed
suggestion is a no-op returning `200`.

## Reviewing via MCP

Two MCP tools are available for suggestion review when using hotwash-mcp
0.2.0 or later.

**`hotwash_list_suggestions`** - read-only. Mirrors the GET
`/api/ingest/suggestions` filters:

- `state` - `pending`, `accepted`, or `dismissed` (default: `pending`)
- `mapping_id` - restrict to one mapping
- `limit` - cap result count

Use case: an LLM agent scanning the pending queue to triage alerts before a
human review session. Because this tool is read-only it carries no confirm
gate.

**`hotwash_accept_suggestion`** - write. Requires `confirm: true` in the
call. Returns the resulting `execution_id` so the caller can immediately
chain to `hotwash_query_run` to inspect the started playbook run. Example
prompt to pass to a model with MCP support:

> Review the pending suggestion queue and accept the highest-priority CVE
> alert. Then query the resulting run and summarize which playbook step is
> first.

**Why dismiss is not exposed via MCP:** Dismissal permanently suppresses an
alert fingerprint for the cooldown window and anchors the suppression log.
A model acting on a queue could swallow legitimate noise without the context
a human reviewer brings. Accept is exposed because its worst outcome is a
playbook run that a human can cancel; dismiss has no safe undo within the
cooldown window. Dismiss remains a human-only action via the REST API.

## Reviewing the queue (web UI)

The route `/suggestions` is the analyst-facing queue. It lists pending
suggestions by default and links to a detail view for each one. Both the list
and detail pages are wrappers over the REST endpoints above; nothing the UI
does is unavailable to a `curl` user.

**Filters.** The list page exposes two filters that round-trip through the URL
hash so a view can be linked or bookmarked:

- `state`: one of `pending`, `accepted`, `dismissed`, or `all`. Defaults to
  `pending`.
- `mapping_id`: free-text integer. Restricts the queue to suggestions raised
  by one mapping. Empty means no restriction.

The page polls while `state=pending` is selected so newly arrived alerts
appear without a manual refresh; switching to any other filter pauses
polling.

**Accept flow.** From the list, click View on a row to open the detail page.
The detail page shows the parsed alert payload, the matched mapping, and the
playbook that will be started. Click Accept and confirm in the dialog. The UI
calls `POST /api/ingest/suggestions/:id/accept`, which creates an Execution
and returns its id, then navigates to the run view for that Execution. Accept
is idempotent end to end: re-accepting an already-accepted suggestion returns
the same `execution_id` (no duplicate run is created) and the UI navigates to
that existing run.

**Dismiss flow.** From the detail page, click Dismiss to open the dismiss
panel. The reason field is optional and capped at 500 characters; a counter
shows remaining length. Submitting calls `POST
/api/ingest/suggestions/:id/dismiss`, which writes a `suggestion_dismissed`
row to the suppression log and anchors the cooldown window for that
fingerprint. The same alert fingerprint will not immediately re-fire while
the cooldown is active, which is the intended outcome when a reviewer marks a
suggestion as noise.

**410 Gone.** If the underlying mapping was hard-deleted between suggestion
creation and the moment a reviewer opens the detail page, the API returns
`410 Gone`. The detail page surfaces this as a friendly "underlying mapping
was removed" state rather than a generic error, and Accept and Dismiss are
disabled because there is nothing to act on.

**Auth.** The web UI sends `X-API-Key` from the build-time env var
`VITE_HOTWASH_API_KEY` on every request to a key-gated endpoint (the entire
`/api/ingest/*` surface, including suggestions and mappings). Because Vite
inlines `import.meta.env` at build time, the key must be set when the
frontend bundle is built; a missing or wrong value at build time produces a
bundle that cannot authenticate at runtime, no matter what the deployment
config says. This is the smallest-blast-radius pick that lets the queue work
today, on the assumption that the bundle is served from the same trust
boundary as the API. A broader auth design (per-user sessions, browser-side
login, or a runtime-injected token) is a follow-up.

## Known limitations

The cooldown check is read-modify-write and not atomic across workers: two
requests with the same fingerprint that race `is_in_cooldown` can both
dispatch. Hotwash ships as single-process uvicorn, which keeps the race
window narrow. Multi-worker deployments need a unique constraint on the
suppression log keyed by fingerprint plus a time bucket; tracked as a
follow-up.
