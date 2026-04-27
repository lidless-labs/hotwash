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
`X-Hotwash-Signature` headers. Template for
`/var/ossec/integrations/custom-hotwash.py`:

```python
#!/usr/bin/env python3
import hashlib, hmac, json, sys, urllib.request

ALERT_FILE, _, HOOK_URL = sys.argv[1], sys.argv[2], sys.argv[3]
MAPPING_ID = "1"
SECRET = b"replace-with-mapping-secret"

with open(ALERT_FILE, "rb") as f:
    body = f.read()
sig = hmac.new(SECRET, body, hashlib.sha256).hexdigest()
req = urllib.request.Request(HOOK_URL, data=body, method="POST", headers={
    "Content-Type": "application/json",
    "X-Hotwash-Mapping-Id": MAPPING_ID,
    "X-Hotwash-Signature": "sha256=" + sig,
})
urllib.request.urlopen(req, timeout=10).read()
```

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
suppression log doubles as the cooldown anchor: only `dispatched_auto`,
`dispatched_suggest`, and `cooldown` rows count. `no_match` and `mode_off`
do not, so flipping a mapping on does not silently swallow the next alert.

## Known limitations

The cooldown check is read-modify-write and not atomic across workers: two
requests with the same fingerprint that race `is_in_cooldown` can both
dispatch. Hotwash ships as single-process uvicorn, which keeps the race
window narrow. Multi-worker deployments need a unique constraint on the
suppression log keyed by fingerprint plus a time bucket; tracked as a
follow-up.
