# TheHive Integration

<!-- Example IPs below are illustrative private-range placeholders. -->
<!-- content-guard: allow private-ipv4 file -->

Tested against TheHive **5.4**.

## What it does

Hotwash can:
- Probe a real TheHive instance from the IntegrationsPage "Test" button.
- Create cases, create alerts, and attach observables to existing cases from playbook SOAR Execute nodes (via the API).

All routes are gated by the standard `X-API-Key` header.

## One-time config

1. On the IntegrationsPage, expand the **TheHive** card.
2. Fill in:
   - **Base URL** (e.g., `http://192.168.1.50:9000`)
   - **API key** (TheHive admin -> Account Settings -> API key)
   - Uncheck **Mock mode**, check **Enabled**.
3. Hit **Save**, then **Test**. You should see `version` and `user` in the response.

If TheHive is on a private LAN, the API will refuse to talk to it unless you set:

```bash
export HOTWASH_PRIVATE_HOST_ALLOWLIST="192.168.1.0/24"
```

(Loopback `127.0.0.0/8` and link-local `169.254.0.0/16` stay blocked even if listed, defense in depth.)

## Action endpoints

All require `X-API-Key`. All return `502` with `{message, upstream_status, details}` if TheHive itself errors.

### `POST /api/integrations/thehive/actions/create_case`

Request:
```json
{
  "title": "Ransomware on host01",
  "description": "Wazuh rule 100100 fired",
  "severity": 3,
  "tlp": 2,
  "pap": 2,
  "tags": ["ransomware", "wazuh"]
}
```
Response:
```json
{"case_id": "~12345", "number": 42, "url": "http://192.168.1.50:9000/cases/42/details", "raw": {...}}
```

Severity: 1 (low) to 4 (critical). TLP/PAP: 0 to 3 (TheHive standard).

### `POST /api/integrations/thehive/actions/create_alert`

Request:
```json
{
  "type": "vulnerability",
  "source": "wazuh",
  "source_ref": "wazuh-23505-2026-05-22",
  "title": "CVE-2024-1234 on host01",
  "description": "Patch needed",
  "severity": 2,
  "observables": [
    {"dataType": "hostname", "data": "host01"},
    {"dataType": "ip", "data": "10.0.0.5"}
  ],
  "tags": ["cve"]
}
```

`source_ref` MUST be unique per `source`. TheHive returns 400 if a `(source, sourceRef)` already exists; the API surfaces that as `502` with `upstream_status: 400`.

### `POST /api/integrations/thehive/actions/add_observable`

Request:
```json
{
  "case_id": "~12345",
  "data_type": "ip",
  "data": "1.2.3.4",
  "message": "C2 server",
  "tlp": 3,
  "ioc": true,
  "sighted": true,
  "tags": ["c2"]
}
```

## Live smoke test

```bash
export HOTWASH_LIVE_THEHIVE_URL=http://192.168.1.50:9000
export HOTWASH_LIVE_THEHIVE_API_KEY=<admin-api-key>
export HOTWASH_PRIVATE_HOST_ALLOWLIST=192.168.1.0/24
pytest api/tests/test_thehive_live.py -m live -v -s
```

Cleanup: live tests tag cases/alerts with `hotwash-live-test`; sweep via TheHive's tag filter periodically.

## Not yet supported

- `update_case` / `close_case` (planned)
- Cortex analyzer invocation (separate integration)
- Webhook receivers from TheHive (Hotwash currently ingests from Wazuh; reverse direction is roadmap)
