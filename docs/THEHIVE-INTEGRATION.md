# TheHive Integration

<!-- Example IPs below are illustrative private-range placeholders. -->
<!-- content-guard: allow private-ipv4 file -->

The existing write integration was tested against TheHive **5.4**. The bounded
read routes below have mocked verification and upstream source contracts.
Deployed compatibility and visibility remain unverified.

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

`source_ref` MUST be unique per `source`. TheHive returns 400 if a `(source, sourceRef)` already exists. The API surfaces that as `502` with `upstream_status: 400`.

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

### `POST /api/integrations/thehive/actions/run_analyzer`

Launches a Cortex analyzer on an existing observable through TheHive's Cortex link.

Request:
```json
{
  "artifact_id": "~12304",
  "analyzer_id": "0123456789abcdef0123456789abcdef",
  "cortex_id": "cortex0"
}
```

`artifact_id` is the TheHive observable id (`~` followed by alphanumerics). `analyzer_id` is the Cortex worker id, not the analyzer name, and `cortex_id` defaults to `cortex0` and allows only letters, digits, `_` and `-`. All three are validated against strict patterns, so path segments, whitespace, and query strings are rejected with `422`.

Hotwash sends `POST /api/v1/connector/cortex/job` with `{"analyzerId", "cortexId", "artifactId"}`. That launch call was verified against TheHive 5.7.5 with Cortex 4.1.0. The response is `{"job_id", "status", "raw"}` taken from TheHive's launch reply. The separate known-job read below retrieves selected report evidence without launching or polling. Hotwash does not list analyzers, so look up the worker id for an analyzer such as `CIRCLHashlookup_1_1` in Cortex first.

The seeded "Suspicious Binary Triage" playbook uses this action to run `CIRCLHashlookup_1_1` and `MISP_2_1` on each file hash, with the package verification and every approval kept as manual steps. The approval gate is advisory in Hotwash until owner-identity approval exists, so marking it complete is not approval.

## Bounded investigation reads

These GET routes accept the existing read-scope API key. They require an enabled,
non-mock TheHive integration and reuse its decrypted credential, URL pinning,
TLS setting, timeout, response body limit and redirect refusal. No read attaches
evidence to a run, commits local state or launches an analyzer.

| Hotwash route under `/api/integrations/thehive` | Result |
| --- | --- |
| `GET /cases` | One finite case inventory page |
| `GET /cases/{case_id}` | Case ID, status, dates, bounded title/stage/tags and number |
| `GET /cases/{case_id}/observables` | Case-scoped complete hash and filename facts |
| `GET /cases/{case_id}/comments` | Existing internal-comment evidence |
| `GET /analyzer-jobs/{job_id}` | Known job ID/status, dates, analyzer identity and selected report facts |

IDs must match `~` followed by alphanumerics, at most 128 characters including
the prefix. Whitespace, URL fragments and path separators are refused. Lists
accept only `offset` (0 to 10000, default 0) and `limit` (1 to 100, default 50).
All other parameters, duplicate query parameters and generic-action extras are
rejected. The five corresponding connector action names are `list_cases`,
`get_case`, `list_case_observables`, `list_case_comments` and `get_analyzer_job`.
Generic POST dispatch retains write-scope authentication and rejects run/node
context before it can be removed or attached.

Case inventory uses a fixed `listCase` query. Related lists use `getCase` with
the validated `idOrName`, then `observables` or `comments`. The backend alone
builds the sort and page expressions. Each list fetches `limit + 1` rows in one
request. It never retries, polls or follows another page automatically. Sort is
ascending `_createdAt` then `_id` for all lists, including comments. Response
timestamp projection is independent: fields such as `_createdAt` and `createdAt`
are retained when present and valid. The corrected comment sort has local
regression coverage. Deployed compatibility remains unverified.

Every result includes `observed_at`, `coverage` and `gaps`. Pages include `items`,
`returned`, `scanned`, `offset`, `limit`, `has_more` and `overflow`. The latter two
describe an observed sentinel. Visibility remains unverified. `returned` counts
projected items and `scanned` counts source rows before filtering. Unsupported
observable types, external or unclassified comments, missing fields and text
cuts remain explicit gaps. Empty pages retain `coverage: "unverified"` and
`query_contract_unverified`. A server might silently cap a response. Malformed
pages, duplicate/conflicting IDs, mismatched detail IDs, ignored page bounds
and failed reads return `502` with only `{"message":"TheHive read failed"}`
inside `detail`. No raw upstream object, error detail or upstream link is returned.

Observable reads retain only complete MD5/SHA-1/SHA-256/SHA-512 hashes and bounded
`filename` data. Hashes are lowercase. Paths are never opened or fetched. Case
membership establishes neither a designated finding anchor nor source/asset/rule
identity. IDs retain explicit link gaps.

Known-job reads use TheHive's `GET /api/connector/cortex/job/{id}` while the
existing launch POST path stays unchanged. Only exact `analyzerDefinition`
values `CIRCLHashlookup_1_1` and `MISP_2_1` receive report projection. Their
`summary.taxonomies` claims are bounded and labeled as source evidence. Selected
`full` evidence retains CIRCL `hashlookup:trust` or MISP event UUIDs/counts.
Truncated or malformed MISP evidence has an unknown total count. Unsupported
analyzers or report shapes keep the known job ID/status and report a gap. Every
projected report has `verdict: "unknown"`: a lookup miss, taxonomy label or
successful job does not certify a file clean.

The corresponding MCP reads validate these API envelopes at runtime. Required
observation time, coverage, gaps, requested IDs, case association, page counters
and selected item facts must be valid. Unexpected fields are removed. A known
job with only an unsupported report retains its ID/status, an unknown verdict
and explicit report gaps.

The seven new MCP read tools return one `untrusted_hotwash_read_data` envelope
with a warning before it. Both text and `structuredContent.untrusted_data`
contain the same envelope. There is no parallel raw object. Angle brackets in
source JSON are encoded as `\u003c` and `\u003e` to prevent source text from
inserting a closing delimiter. JSON decoding recovers the source text.
Consumers must preserve the data boundary. It does not guarantee injection
immunity or authorize actions from source text.

MCP run reports select strict case/observable/job IDs and job status from
recorded TheHive connector attachments. These facts are labeled
`recorded_connector_evidence` with `association: "unverified"`. They are recorded
evidence, with no authoritative run-to-case binding or dedup anchor. Unsupported,
malformed and already-truncated connector results have explicit omission gaps.
Their raw result dictionaries and upstream URL fields are excluded.

The legacy finding-anchor/source namespace, authoritative run-to-case linkage,
deployed query semantics and principal visibility are unverified. These reads
cannot certify dedup or a complete case workflow. No new SOC create, append,
comment, launch, closure or approval tool is provided by this slice.

Primary contracts were retrieved on 2026-10-25, not publication dates:
[case reads and query traversal](https://raw.githubusercontent.com/TheHive-Project/thehive4py/main/thehive4py/endpoints/case.py),
[job reads](https://raw.githubusercontent.com/TheHive-Project/thehive4py/main/thehive4py/endpoints/cortex.py),
[job fields](https://raw.githubusercontent.com/TheHive-Project/thehive4py/main/thehive4py/types/cortex.py),
[report envelope](https://raw.githubusercontent.com/TheHive-Project/cortexutils/master/cortexutils/analyzer.py),
[CIRCL report](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/CIRCLHashlookup/circlhashlookup_analyzer.py)
and [MISP report](https://raw.githubusercontent.com/TheHive-Project/Cortex-Analyzers/master/analyzers/MISP/misp.py).
Upstream branch source establishes request syntax. Deployed compatibility remains unverified.

## Bounded finding candidates

`GET /api/integrations/thehive/finding-check` accepts a read-scope API key and
requires the configured, enabled, non-mock TheHive connector. Required query
fields are `source=wazuh`, `source_instance_ref`, `asset_id`, `rule_id`, and
`sha256`. The three logical IDs match `[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}`.
They are case-sensitive and retain their exact bytes. Whitespace, URLs, paths,
control characters, unknown fields and duplicate parameters are rejected.
`sha256` is exactly 64 hexadecimal characters and is normalized to lowercase.
An optional `run_id` is a canonical positive decimal integer, at most
9223372036854775807, identifying an existing run. It does not narrow the search.
Invalid parameters return a finite `422` error. A missing run returns `404`.
Upstream read failures return sanitized `502` errors without upstream bodies.

The server computes `fingerprint` as `v1:` followed by the lowercase SHA-256
hex digest of the UTF-8 compact JSON array below. The strings are the validated
query values. There are no spaces between array elements.

```text
["hotwash-finding",1,"wazuh",source_instance_ref,asset_id,rule_id,"sha256",lowercase_hash]
```

Run ID, observation time, title and mapping ID are excluded. The only supported
case association is the full tag `hotwash:finding:v1:<digest>`, where `<digest>`
is the 64 lowercase hexadecimal characters from that fingerprint. Matching is
exact over all raw tags in the bounded response. Titles, tag prefixes and
substrings do not match. Multiple distinct fingerprint tags or contradictory
status/stage values produce ambiguity. `New` and `InProgress` statuses map to
`open`, and `Resolved` and `Deleted` map to `closed`. If present, stage must agree
with that lifecycle. The supported stage values are those four status names,
`Open`, and `Closed`. An unknown status or stage produces an explicit gap.
Lifecycle gaps are evaluated per record, so separate conflicting and unknown
records retain both gaps regardless of their order.

For local runs, the candidate representation is a `context_json.soc_finding_v1`
object with exactly the five tuple fields, plus an optional validated `case_id`:

```json
{
  "soc_finding_v1": {
    "source": "wazuh",
    "source_instance_ref": "example-instance",
    "asset_id": "Asset01",
    "rule_id": "100100",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "case_id": "~C1"
  }
}
```

This context is caller-controlled. Copied records, provenance labels,
`started_by`, notes, generic Wazuh context and ingest cooldown fingerprints do
not authenticate it. Matching runs carry `identity_basis: "untrusted_context_v1"`
and `attempt_state: null`. A completed step or run does not prove an upstream
action occurred. Every matching run adds `run_attempt_state_unverified` and
blocks the disposition, including fully linked open or closed case candidates.
Missing or unseen case links also block the disposition. A different-fingerprint
run linked to a visible matching case adds `run_case_link_conflict` and blocks
the result. The case candidate remains visible, and the different-fingerprint
run is excluded from exact run matches. An unrelated run with an unrelated case
link contributes no conflict.

The check makes one fixed `listCase` request at offset 0 with limit 100 and a
101st overflow sentinel. It scans local runs in ascending ID order across all
statuses, also with a 101st sentinel. The optional run lookup and inventory
share one separately owned database read transaction. The snapshot is fully
materialized and its connection closes before the upstream request. This read
does not flush, commit or roll back caller-owned session work. Run context is
limited to 65536 UTF-8 bytes before loading or parsing it. Oversized, malformed
or duplicate-key JSON,
legacy records without the supported association, malformed identities and cap
hits contribute finite gaps. The operation performs no source fetch, paging,
local commit, evidence attachment, step transition or upstream mutation.

The response has `schema_version: 1`, the canonical `candidate` tuple and
`fingerprint`, safe `case_matches` and `run_matches`, `coverage`, `disposition`,
and finite `gaps`. Case matches expose only `case_id`, `lifecycle`, and
`identity_basis: "fingerprint_tag_v1"`. Run matches expose only `run_id`,
`case_id`, `identity_basis`, and `attempt_state`. Coverage contains `cases`,
`runs`, `visibility`, `observed_at`, and `contract_version: 1`. A complete local
scan describes the bounded stored representation only. Case coverage remains
`unverified` even when the page has no observed overflow.

Dispositions are `one_open_candidate`, `closed_only`, `ambiguous`, `blocked`,
and `no_match_visible`. Structural gaps take precedence over candidate
dispositions. Matches remain available when a gap blocks the result. An empty
bounded inventory can report `no_match_visible` while visibility remains
unverified. There is no creation permit or authoritative negative result.
`identity_binding` and `coverage.visibility` always remain `unverified`, with
`source_binding_unverified`, `visibility_unverified`, and
`query_contract_unverified` gaps on every successful response.

These representations define candidate matching only. Deployment evidence must
still establish the authenticated source namespace, stable asset/rule identity,
complete hash decoder and source-to-run relation, plus legacy case mapping,
all-state query/page semantics and the connector principal's full relevant
visibility. No source decoder, account visibility contract, backfill or write
admission is established by this endpoint. An absent tag or unavailable record
cannot certify that a finding has no case.

## Live smoke test

```bash
export HOTWASH_LIVE_THEHIVE_URL=http://192.168.1.50:9000
export HOTWASH_LIVE_THEHIVE_API_KEY=<admin-api-key>
export HOTWASH_PRIVATE_HOST_ALLOWLIST=192.168.1.0/24
pytest api/tests/test_thehive_live.py -m live -v -s
```

Cleanup: live tests tag cases/alerts with `hotwash-live-test`. Sweep via TheHive's tag filter periodically.

## Not yet supported

- `update_case` / `close_case` (planned)
- Cortex analyzer listing and automatic job result polling (known-job reads are available)
- Webhook receivers from TheHive (Hotwash currently ingests from Wazuh. The reverse direction is roadmap)
