# Evidence record v1

`evidence-record` is a JSON export envelope for incident evidence, annotations,
and closeout facts. Hotwash, Vervet, and Intel Workbench can use the same contract.
The authoritative [draft 2020-12 schema](schemas/evidence-record-v1.schema.json)
uses `format: "evidence-record"` and the string `format_version: "1"`.
Consumers must reject another format or version. Additive fields stay on v1.
Removing fields, changing their types or meanings, or changing vocabularies needs v2.
Consumers must accept and ignore unknown additive fields within the documented bounds.

## Fields and nullability

Every field below is required unless marked as an extension. Missing facts use
JSON `null`, never an invented timestamp, identity, empty string, or conclusion.
An empty `records` or `enrichment` array means there are no exported entries.

| Field | Meaning and allowed absence |
| --- | --- |
| `format`, `format_version` | Exact strings above, never null. |
| `generator.name` | Producer name, nonempty string. |
| `generator.version` | Producer software version, or null if unavailable. Separate from the envelope version. |
| `exported_at` | Time this export was generated, RFC3339 with an explicit offset, never null. |
| `subject.kind` | `case`, `run`, or `project`. |
| `subject.id`, `subject.title` | Nonempty producer-native identity and human title. IDs are scoped to the producer and subject kind. |
| `records[].id` | Nonempty identity within this subject. |
| `records[].source.tool` | Nonempty tool or connector name. This is an open vocabulary, such as `zeek`, `suricata`, `wazuh`, `hotwash`, or `manual`. |
| `records[].source.observed_at` | RFC3339 event or collection time, or null when unknown. |
| `records[].source.ref` | Opaque native identifier or `sha256:<64 lowercase hex digits>`, or null. It is data, never a fetch instruction. |
| `records[].source.raw` | Bounded JSON object of source facts, or null when absent or unsafe to export. File bytes and credentials do not belong here. |
| `records[].enrichment` | Array of annotations. |
| `enrichment[].kind` | `attack`, `ti`, or `score`. |
| `enrichment[].provider` | Nonempty producer of the annotation. |
| `enrichment[].value` | Bounded JSON value. Null means unavailable. |
| `enrichment[].value.technique_ids` | For `kind=attack`, producers that export ATT&CK IDs use this array of unique `T####` or `T####.###` strings. Validate ID syntax. Source-specific facts stay in `source.raw`. The schema does not assert membership in a particular ATT&CK release. |
| `enrichment[].at` | RFC3339 annotation time, or null. |
| `records[].decision` | Decision object, or null if no decision is recorded. |
| `decision.verdict` | `benign`, `suspicious`, `malicious`, `false-positive`, or `unknown`. |
| `decision.rationale` | Original decision text or explanation, or null. Empty text is allowed when the source explicitly stored it. |
| `decision.by`, `decision.at` | Recorded actor and RFC3339 decision time, each independently nullable. |
| `closeout.status` | `open` or `closed`. |
| `closeout.resolution` | `TruePositive`, `FalsePositive`, `Indeterminate`, `Duplicated`, `Other`, or null. |
| `closeout.impact` | `NoImpact`, `WithImpact`, `NotApplicable`, or null. |
| `closeout.summary` | Closeout summary, or null. |
| `closeout.closed_at`, `closeout.closed_by` | Recorded RFC3339 close time and actor, or null. |

The verdict vocabulary follows Vervet annotations with `unknown` added.
Resolution and impact use TheHive's closeout vocabulary.

## Bounds and validation

The schema requires useful object shapes and limits records to 10,000 and
annotations per record to 64. Objects have at most 64 properties with keys at most
128 characters. Identity, tool, provider, version, title, and ref strings have
1 to 1,024 characters. Rationale and summary allow up to 8,192 characters.
Timestamps allow up to 64 characters. Raw data, annotation values, and additive
fields allow at most 4 nested containers, 64 items per array, 64 properties per
object, 8,192 characters per string, and finite numbers between -1e308 and 1e308.
A raw object counts as the first container. An unknown extension's value starts
its own four-container budget.

Consumers must also bound their input bytes before parsing. Hotwash caps exports
at 4 MiB of UTF-8 JSON, returning 422 rather than silently dropping records.
It also caps combined stored `steps_json` and `context_json` input at 4 MiB
before JSON parsing, returning 422 above that limit. Its Wazuh projection caps raw data at 32 KiB and uses null when projected data
exceeds the shape or byte bounds. JSON Schema cannot enforce serialized byte size.

Use a draft 2020-12 validator with format checking enabled. For Python tests this
is `Draft202012Validator(schema, format_checker=FormatChecker())`. A `format`
annotation alone does not reject an invalid RFC3339 timestamp. Without the optional
RFC3339 validator installed, register a calendar and offset checker explicitly
(the tests do this using the standard library). Both input and test checkers bound offset hours to 00-23 and minutes to 00-59.
Second 60 must resolve to the UTC last minute of June 30 or December 31.
They do not verify the historical leap-second announcement table. The tests validate
[the example](../api/tests/fixtures/evidence-record/example.json) and apply
[invalid mutations](../api/tests/fixtures/evidence-record/invalid.json) to it.

## Hotwash export mapping

`GET /api/executions/{id}/export?format=evidence-record` exports one run. The
existing `/report` JSON and `/report/markdown` representations retain their format.
Export returns 422 for malformed stored steps or context, invalid nested evidence
collections, oversized required facts, or an oversized document. Legacy reports
retain their existing malformed-step fallback.
`subject.kind` is `run`, `subject.id` is the execution ID as a string, and
`subject.title` is `incident_title`. `subject.incident_id` is an additive, nullable
field retaining the external incident ID. This avoids merging distinct runs
against the same incident. `generator.version` uses the API's declared version.

Each evidence item becomes `evidence:<node_id>:<index>` in stored step order.
`source.tool` prefers optional `source_tool`, then `connector`, then `hotwash`.
`source.ref` is the file SHA256, never the opaque upstream ref. Uploads store
`sha256` immediately. For historical items without a hash, export hashes only a
regular file reconstructed beneath this run's evidence directory with validated
node ID and filename, refusing symlinks and files over the upload limit. If no
safe file or known hash is available, ref stays null. Export never follows a
stored path or fetches a source ref. A stored hash can remain known after file
removal. SHA256 identifies bytes and does not prove origin or custody.

`source.observed_at` prefers optional `observed_at`, then `uploaded_at`.
`source.raw` retains bounded filename, size, node ID, upload time, hash, connector,
action, and optional source provenance. `source_ref` remains an opaque raw field.
Provider `result` payloads and file contents are excluded.

MCP `hotwash_attach_artifact` accepts optional `source_tool` and `source_ref`
(nonempty strings up to 1,024 characters) and `observed_at` (RFC3339 with offset).
The client sends them as multipart fields. They persist in `steps_json` and the
structured evidence event without a database migration. Provenance is supplied
by the caller and is not independently verified.

Each step with `decision_taken` gets a separate `decision:<node_id>` record,
including steps with no attachments. Evidence records have a null decision.
The decision's rationale and `source.raw.decision_taken` preserve the original
text. Only an exact match to a shared verdict string maps to that verdict.
Every other branch label, including `Yes` and `No`, maps to `unknown`.

Actor and time come from the latest matching `step_decision_taken` RunEvent
(node ID and original decision text). Actor is the event payload's actor when
present, otherwise null. Time is the event's creation time. Fork copies do not
preserve that time, so inherited decisions without a later local decision event
leave attribution null. Legacy prose events can supply attribution only if their
exact decision description identifies a uniquely labeled step. Assignees, starters,
and step completion times are never used as decision attribution. SQLite's naive
server timestamps are UTC. Invalid or offset-free source times stay null.

A Wazuh-ingested run also gets `wazuh-alert`. Its ref is the stored
`context_json.ingest.fingerprint`, not a recomputed fingerprint or alert ID.
Observed time is the alert timestamp if valid. Raw contains only alert ID,
timestamp, rule ID/level/description/groups, and agent ID/name/IP. Unmodeled
provider fields, `data`, `full_log`, and credential fields are excluded.
No alert timestamp is inferred from ingest or execution time.

Active and paused runs map to open. Completed runs map to closed with null
resolution. Abandoned runs map to closed with resolution `Other`.
Impact, summary, closed actor, and closed time stay null until Hotwash records
those closeout facts. No enrichments are inferred from branch labels or provider
results.

## Producer coverage today

| Producer | Available facts | Null or unavailable facts |
| --- | --- | --- |
| Hotwash | Execution identity/title, incident ID extension, attached evidence metadata/hash when safe, connector or supplied provenance, Wazuh projection/fingerprint, step decisions and matching event time/actor when recorded, terminal run status. | Enrichment is empty. Historical hash/provenance or decision attribution can be null. Closeout impact/summary/time/actor remain null, and completed resolution remains null. |
| Vervet | Its existing case bundles carry case identity, evidence sources, annotations, export time, and format. These can supply subject/source/enrichment and stored verdict facts in a later exporter. | V1 export is follow-up Vervet #21. Generator version, missing source/annotation times and actor, and unrecorded structured closeout facts must be null. This Hotwash change makes no claim that Vervet already emits v1. |
| Intel Workbench | Existing project identity and raw project JSON can inform the later importer. | V1 import is follow-up Intel Workbench #15. No transport or importer is added here. |

## Example

```json
{
  "format": "evidence-record",
  "format_version": "1",
  "generator": {
    "name": "hotwash",
    "version": "0.1.0"
  },
  "exported_at": "2026-10-01T12:00:00Z",
  "subject": {
    "kind": "run",
    "id": "42",
    "title": "Suspicious host",
    "incident_id": "INC-42"
  },
  "records": [
    {
      "id": "evidence:node_1:0",
      "source": {
        "tool": "hotwash",
        "observed_at": "2026-10-01T11:00:00Z",
        "ref": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "raw": {
          "node_id": "node_1",
          "filename": "ioc-list.txt",
          "size": 12
        }
      },
      "enrichment": [],
      "decision": null
    },
    {
      "id": "decision:node_1",
      "source": {
        "tool": "hotwash",
        "observed_at": null,
        "ref": null,
        "raw": {
          "node_id": "node_1",
          "decision_taken": "Isolate host"
        }
      },
      "enrichment": [],
      "decision": {
        "verdict": "unknown",
        "rationale": "Isolate host",
        "by": null,
        "at": null
      }
    }
  ],
  "closeout": {
    "status": "closed",
    "resolution": null,
    "impact": null,
    "summary": null,
    "closed_at": null,
    "closed_by": null
  }
}
```
