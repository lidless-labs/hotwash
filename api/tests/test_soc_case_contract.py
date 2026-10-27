"""Finding candidates under synthetic SQLite and mocked connector transport only."""

import json
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.pool import QueuePool

from api.integrations.clients.thehive import TheHiveClient
from api.integrations.schemas import FindingCheckRequest
from api.orm_models import Execution, ExecutionEvent, Playbook, RunEvent
from api.security import PinnedURL
from api.services.soc_cases import check_finding


CANDIDATE = {"source": "wazuh", "source_instance_ref": "lab-a", "asset_id": "Asset01",
             "rule_id": "100100", "sha256": "a" * 64}
# SHA256 of the literal UTF-8 compact array specified in the portable contract.
DIGEST = "255cfdfdfa254df96548642065c9e2ebe82b6cbf5393a95028dbf64317cf5f2d"
TAG = "hotwash:finding:v1:" + DIGEST
BASE_GAPS = {"source_binding_unverified", "visibility_unverified", "query_contract_unverified"}


@pytest.fixture
def upstream(configured_thehive):
    with patch("api.routers.integrations.resolve_and_pin_integration_url",
               side_effect=lambda url: PinnedURL(url=url, hostname=None, host_header=None)), \
         patch.object(TheHiveClient, "_request", return_value=[]) as request:
        yield request


@pytest.fixture
def runs(temp_db):
    def seed(contexts, statuses=None):
        with temp_db() as db:
            playbook = Playbook(title="Synthetic finding check")
            db.add(playbook)
            db.flush()
            rows = [Execution(playbook_id=playbook.id, incident_title="untrusted title",
                              status=(statuses or ["active"] * len(contexts))[i],
                              started_by="ingest:verified", notes="authoritative=true",
                              context_json=(c if isinstance(c, str) else json.dumps(c)),
                              steps_json='[{"node_id":"step1","status":"completed"}]')
                    for i, c in enumerate(contexts)]
            db.add_all(rows)
            db.flush()
            ids = [r.id for r in rows]
            db.commit()
            return ids
    return seed


def read(client, api_key, **changes):
    return client.get("/api/integrations/thehive/finding-check", params={**CANDIDATE, **changes},
                      headers={"X-API-Key": api_key})


def context(**changes):
    return {"soc_finding_v1": {**CANDIDATE, "case_id": "~C1", **changes},
            "provenance": "verified", "authoritative": True}


def test_finding_check_exact_candidates_and_read_only(client, api_key, upstream, runs, temp_db, tmp_path):
    ids = runs([context(), context(sha256="A" * 64)], ["active", "completed"])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [TAG],
                              "description": "secret-upstream", "url": "https://private.invalid"}]
    with temp_db() as db:
        before = [(r.id, r.context_json, r.steps_json, r.status) for r in db.query(Execution)]
        engine = db.get_bind()
    statements = []
    def capture(conn, cursor, statement, parameters, ctx, many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        with patch("sqlalchemy.orm.Session.commit") as commit, \
             patch("api.routers.integrations._attach_action_result") as attach, \
             patch("api.routers.integrations.EVIDENCE_ROOT", tmp_path / "evidence"):
            response = read(client, api_key, sha256="A" * 64, run_id=str(ids[1]))
        assert response.status_code == 200
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    data = response.json()
    assert data["schema_version"] == 1
    assert data["fingerprint"] == "v1:" + DIGEST
    assert data["candidate"] == CANDIDATE
    assert data["identity_binding"] == "unverified"
    assert data["case_matches"] == [{"case_id": "~C1", "lifecycle": "open",
                                     "identity_basis": "fingerprint_tag_v1"}]
    assert data["run_matches"] == [{"run_id": i, "case_id": "~C1",
                                    "identity_basis": "untrusted_context_v1", "attempt_state": None}
                                   for i in ids]
    # Exact candidates remain visible, but unknown prior attempts block the
    # disposition under the approved finding-check contract.
    assert data["disposition"] == "blocked"
    assert BASE_GAPS | {"run_attempt_state_unverified"} <= set(data["gaps"])
    assert data["coverage"]["visibility"] == "unverified"
    assert data["coverage"]["observed_at"] and data["coverage"]["contract_version"] == 1
    assert "secret-upstream" not in response.text and "private.invalid" not in response.text
    assert "safe_to_create" not in data and "authoritative" not in data
    assert not any(s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")) for s in statements)
    commit.assert_not_called()
    attach.assert_not_called()
    assert not (tmp_path / "evidence").exists()
    with temp_db() as db:
        assert [(r.id, r.context_json, r.steps_json, r.status) for r in db.query(Execution)] == before
        assert db.query(ExecutionEvent).count() == db.query(RunEvent).count() == 0
    upstream.assert_called_once_with("POST", "/api/v1/query", params={"name": "cases"}, json={"query": [
        {"_name": "listCase"},
        {"_name": "sort", "_fields": [{"_createdAt": "asc"}, {"_id": "asc"}]},
        {"_name": "page", "from": 0, "to": 101, "extraData": []},
    ]}, require_success=True)


@pytest.mark.parametrize("status,lifecycle", [("New", "open"), ("Resolved", "closed")])
def test_matching_run_unknown_attempt_blocks_fully_linked_case(client, api_key, upstream, runs, status, lifecycle):
    ids = runs([context()], ["completed"])
    upstream.return_value = [{"_id": "~C1", "status": status, "tags": [TAG]}]
    response = read(client, api_key)
    assert response.status_code == 200
    data = response.json()
    assert data["case_matches"] == [{"case_id": "~C1", "lifecycle": lifecycle,
                                     "identity_basis": "fingerprint_tag_v1"}]
    assert data["run_matches"] == [{"run_id": ids[0], "case_id": "~C1",
                                    "identity_basis": "untrusted_context_v1", "attempt_state": None}]
    assert set(data["gaps"]) == BASE_GAPS | {"run_attempt_state_unverified"}
    assert data["disposition"] == "blocked"


@pytest.mark.parametrize("changes", [
    {"source": "other"}, {"source_instance_ref": "lab-b"}, {"asset_id": "asset01"},
    {"rule_id": "10010"}, {"sha256": "b" * 64},
])
def test_tuple_members_are_exact_and_hash_only_is_normalized(client, api_key, upstream, runs, changes):
    # Unsupported source cannot be disguised as an empty result.
    runs([context(**changes)])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": ["hotwash:finding:v1:" + "0" * 64]}]
    data = read(client, api_key).json()
    assert data["run_matches"] == data["case_matches"] == []
    if changes.get("source") == "other":
        assert data["disposition"] == "blocked" and "run_identity_unmapped" in data["gaps"]
    else:
        assert data["disposition"] == "no_match_visible"
    assert BASE_GAPS <= set(data["gaps"])


@pytest.mark.parametrize("changes", [
    {"source": "other"}, {"source": "WAZUH"}, {"source_instance_ref": " lab-a"},
    {"asset_id": "Asset01 "}, {"rule_id": "a\nb"}, {"asset_id": "a\x00b"},
    {"source_instance_ref": "https://example.invalid"}, {"asset_id": "../a"},
    {"asset_id": "a?b"}, {"rule_id": "a/b"}, {"rule_id": "a#b"},
    {"rule_id": "a" * 129}, {"sha256": "a" * 63}, {"sha256": "g" * 64},
    {"sha256": "a" * 64 + "\n"}, {"authoritative": "true"}, {"provenance": "verified"},
    {"url": "https://example.invalid"}, {"run_id": "01"}, {"run_id": "0"},
    {"run_id": "-1"}, {"run_id": "+1"}, {"run_id": " 1"}, {"run_id": "1.0"},
    {"run_id": "1e0"}, {"run_id": "١"}, {"run_id": "9223372036854775808"},
    {"run_id": "9" * 5000},
])
def test_invalid_query_is_sanitized_before_transport(client, api_key, upstream, changes):
    response = read(client, api_key, **changes)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid finding check parameters"}
    upstream.assert_not_called()


@pytest.mark.parametrize("key", list(CANDIDATE) + ["run_id"])
def test_duplicate_query_is_rejected(client, api_key, upstream, key):
    query = list(CANDIDATE.items()) + [(key, "1" if key == "run_id" else CANDIDATE[key])]
    if key == "run_id":
        query.append((key, "2"))
    response = client.get("/api/integrations/thehive/finding-check", params=query,
                          headers={"X-API-Key": api_key})
    assert response.status_code == 422
    upstream.assert_not_called()


def test_missing_fields_and_authentication(client, api_key, upstream, monkeypatch):
    assert client.get("/api/integrations/thehive/finding-check", params=CANDIDATE).status_code == 401
    missing = {k: v for k, v in CANDIDATE.items() if k != "asset_id"}
    assert client.get("/api/integrations/thehive/finding-check", params=missing,
                      headers={"X-API-Key": api_key}).status_code == 422
    upstream.assert_not_called()
    monkeypatch.setenv("HOTWASH_READ_ONLY_API_KEY", "read-test-key")
    response = read(client, "read-test-key")
    assert response.status_code == 200
    data = response.json()
    assert data["disposition"] == "no_match_visible"
    assert data["identity_binding"] == data["coverage"]["visibility"] == "unverified"
    assert BASE_GAPS <= set(data["gaps"])


@pytest.mark.parametrize("tags", [["prefix" + TAG], [TAG + "suffix"], [TAG.upper()],
                                  ["soc-bot"], [], None, [123], "not-a-list"])
def test_unsupported_case_identity_blocks_negatives(client, api_key, upstream, tags):
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": tags, "title": TAG}]
    data = read(client, api_key).json()
    assert data["case_matches"] == []
    assert data["disposition"] == "blocked" and data["coverage"]["cases"] == "incomplete"


@pytest.mark.parametrize("status,stage,lifecycle,disposition,gap", [
    ("New", None, "open", "one_open_candidate", None),
    ("InProgress", "InProgress", "open", "one_open_candidate", None),
    ("Resolved", "Closed", "closed", "closed_only", None),
    ("Deleted", None, "closed", "closed_only", None),
    ("Unknown", None, "unknown", "blocked", "case_lifecycle_unknown"),
    (None, None, "unknown", "blocked", "case_lifecycle_unknown"),
    (123, None, "unknown", "blocked", "case_lifecycle_unknown"),
    ("New", "Closed", "unknown", "ambiguous", "case_lifecycle_conflict"),
    ("Resolved", "InProgress", "unknown", "ambiguous", "case_lifecycle_conflict"),
    ("New", "unrecognized", "unknown", "blocked", "case_lifecycle_unknown"),
])
def test_case_lifecycle_is_conservative(client, api_key, upstream, status, stage, lifecycle, disposition, gap):
    row = {"_id": "~C1", "status": status, "tags": [TAG]}
    if stage is not None:
        row["stage"] = stage
    upstream.return_value = [row]
    data = read(client, api_key).json()
    assert data["case_matches"][0]["lifecycle"] == lifecycle
    assert data["disposition"] == disposition
    if gap:
        assert gap in data["gaps"]


@pytest.mark.parametrize("conflict_first", [True, False])
def test_lifecycle_gaps_are_independent_of_row_order(client, api_key, upstream, conflict_first):
    rows = [{"_id": "~Conflict", "status": "New", "stage": "Closed", "tags": [TAG]},
            {"_id": "~Unknown", "status": "Unrecognized", "tags": [TAG]}]
    upstream.return_value = rows if conflict_first else list(reversed(rows))
    response = read(client, api_key)
    assert response.status_code == 200
    data = response.json()
    assert {r["case_id"] for r in data["case_matches"]} == {"~Conflict", "~Unknown"}
    assert all(r["lifecycle"] == "unknown" for r in data["case_matches"])
    assert set(data["gaps"]) == BASE_GAPS | {"case_lifecycle_conflict", "case_lifecycle_unknown"}
    assert data["disposition"] == "blocked"


@pytest.mark.parametrize("sibling,disposition,gap", [
    ("hotwash:finding:v1:" + "b" * 64, "ambiguous", "case_identity_conflict"),
    ("hotwash:finding:v1:invalid", "blocked", "case_identity_invalid"),
    (None, "blocked", "case_identity_invalid"),
])
def test_raw_tags_preserve_positive_despite_conflicting_or_malformed_siblings(client, api_key, upstream, sibling, disposition, gap):
    # The matching tag is past the old projection's tag truncation boundary.
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": ["x"] * 150 + [TAG, sibling]}]
    data = read(client, api_key).json()
    assert [r["case_id"] for r in data["case_matches"]] == ["~C1"]
    assert data["disposition"] == disposition and gap in data["gaps"]


@pytest.mark.parametrize("statuses", [["New", "New"], ["New", "Resolved"], ["Resolved", "Deleted"]])
def test_distinct_matching_cases_are_ambiguous(client, api_key, upstream, statuses):
    upstream.return_value = [{"_id": f"~C{i}", "status": s, "tags": [TAG]} for i, s in enumerate(statuses)]
    data = read(client, api_key).json()
    assert len(data["case_matches"]) == 2 and data["disposition"] == "ambiguous"


@pytest.mark.parametrize("record,gap", [
    ({}, "run_identity_unmapped"),
    ({"wazuh_alert": CANDIDATE, "ingest": {"fingerprint": DIGEST}}, "run_identity_unmapped"),
    ({"soc_finding_v1": {**CANDIDATE, "authoritative": True}}, "run_identity_unmapped"),
    ({"soc_finding_v1": {**CANDIDATE, "case_id": "https://private.invalid/secret"}}, "run_identity_unmapped"),
    ({"soc_finding_v1": {**CANDIDATE, "sha256": 123}}, "run_identity_unmapped"),
    ("{not-json", "run_context_invalid"),
    ("[]", "run_context_invalid"),
    ('{"soc_finding_v1":{},"soc_finding_v1":{}}', "run_context_invalid"),
    ("x" * 65537, "run_context_oversized"),
    (json.dumps({"padding": "é" * 40000}, ensure_ascii=False), "run_context_oversized"),
    ("[" * 2000, "run_context_invalid"),
])
def test_untrusted_legacy_or_malformed_runs_block_negative(client, api_key, upstream, runs, record, gap):
    runs([record])
    data = read(client, api_key).json()
    assert data["run_matches"] == [] and data["disposition"] == "blocked"
    assert gap in data["gaps"] and data["coverage"]["runs"] == "incomplete"
    assert data["identity_binding"] == "unverified"


@pytest.mark.parametrize("case_id,visible,gap", [
    (None, True, "run_case_link_missing"), ("~C2", True, "run_case_link_unresolved"),
    ("~C1", False, "run_case_link_unresolved"),
])
def test_matching_run_with_unresolved_case_link_blocks(client, api_key, upstream, runs, case_id, visible, gap):
    record = context()
    if case_id is None:
        del record["soc_finding_v1"]["case_id"]
    else:
        record["soc_finding_v1"]["case_id"] = case_id
    runs([record], ["abandoned"])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [TAG]}] if visible else []
    data = read(client, api_key).json()
    assert len(data["run_matches"]) == 1 and data["run_matches"][0]["attempt_state"] is None
    assert data["disposition"] == "blocked" and gap in data["gaps"]


@pytest.mark.parametrize("case_id,conflict", [("~C1", True), ("~Unrelated", False)])
def test_different_fingerprint_run_link_conflict(client, api_key, upstream, runs, case_id, conflict):
    runs([context(sha256="b" * 64, case_id=case_id)])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [TAG]}]
    response = read(client, api_key)
    assert response.status_code == 200
    data = response.json()
    assert data["case_matches"] == [{"case_id": "~C1", "lifecycle": "open",
                                     "identity_basis": "fingerprint_tag_v1"}]
    assert data["run_matches"] == []
    expected_gaps = BASE_GAPS | ({"run_case_link_conflict"} if conflict else set())
    assert set(data["gaps"]) == expected_gaps
    assert data["disposition"] == ("blocked" if conflict else "one_open_candidate")
    assert data["coverage"]["runs"] == ("incomplete" if conflict else "complete")
    upstream.assert_called_once()


def test_run_hint_must_exist_and_does_not_narrow_bounded_scan(client, api_key, upstream, runs):
    ids = runs([context()] * 101, ["completed"] * 100 + ["other"])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [TAG]}]
    data = read(client, api_key, run_id=str(ids[-1])).json()
    assert [r["run_id"] for r in data["run_matches"]] == ids[:100]
    assert data["disposition"] == "blocked" and "runs_capped" in data["gaps"]
    assert data["coverage"]["runs"] == "incomplete"
    upstream.reset_mock()
    response = read(client, api_key, run_id=str(ids[-1] + 1))
    assert response.status_code == 404 and response.json() == {"detail": "Run not found"}
    upstream.assert_not_called()


def test_finding_check_needs_only_one_available_pool_connection(client, api_key, upstream, runs, temp_db, monkeypatch):
    from api import database

    ids = runs([context()], ["completed"])
    engine = create_engine(
        temp_db.kw["bind"].url,
        connect_args={"check_same_thread": False},
        poolclass=QueuePool, pool_size=1, max_overflow=0, pool_timeout=0,
    )
    temp_db.configure(bind=engine)
    monkeypatch.setattr(database, "engine", engine)

    def outbound(*args, **kwargs):
        # The integration lookup and snapshot must both return the sole
        # connection before transport, not just release SQLite read locks.
        assert engine.pool.checkedout() == 0
        with engine.connect() as connection:
            assert not connection.connection.driver_connection.in_transaction
            assert connection.execute(select(Execution.id)).scalars().all() == ids
        return [{"_id": "~C1", "status": "New", "tags": [TAG]}]

    upstream.side_effect = outbound
    try:
        response = read(client, api_key, run_id=str(ids[0]))
        assert response.status_code == 200
        data = response.json()
        assert [row["run_id"] for row in data["run_matches"]] == ids
        assert data["disposition"] == "blocked"
        upstream.assert_called_once()
        assert engine.pool.checkedout() == 0

        upstream.reset_mock()
        response = read(client, api_key, run_id=str(ids[0] + 1))
        assert response.status_code == 404
        assert response.json() == {"detail": "Run not found"}
        upstream.assert_not_called()
        assert engine.pool.checkedout() == 0
    finally:
        engine.dispose()


def test_run_snapshot_releases_sqlite_reader_before_outbound(client, api_key, upstream, runs, temp_db):
    ids = runs([context()], ["completed"])
    engine = temp_db.kw["bind"]
    reads = []
    with temp_db() as writer:
        def after_read(conn, cursor, statement, parameters, ctx, many):
            if ctx.compiled is not None and ctx.compiled.statement.is_select and "FROM executions" in statement:
                native = conn.connection.driver_connection
                reads.append((native, native.in_transaction))
                if len(reads) == 1:
                    # An independent writer changes the stored identity after
                    # the optional lookup, while the read snapshot is open.
                    writer.execute(Execution.__table__.update().where(Execution.id == ids[0])
                                   .values(context_json=json.dumps(context(sha256="b" * 64))))

        def outbound(*args, **kwargs):
            # A materialized read must release its lock before network I/O.
            writer.commit()
            with temp_db() as observer:
                stored = observer.get(Execution, ids[0])
                assert json.loads(stored.context_json)["soc_finding_v1"]["sha256"] == "b" * 64
            return [{"_id": "~C1", "status": "New", "tags": [TAG]}]

        event.listen(engine, "after_cursor_execute", after_read)
        upstream.side_effect = outbound
        try:
            response = read(client, api_key, run_id=str(ids[0]))
        finally:
            event.remove(engine, "after_cursor_execute", after_read)
    assert response.status_code == 200
    data = response.json()
    # Both local reads happened within the same real SQLite transaction.
    assert len(reads) >= 2
    assert reads[0][0] is reads[1][0] and reads[0][1] and reads[1][1]
    # The response keeps the old identity, even though the writer committed
    # its replacement before returning the synthetic upstream page.
    assert [r["run_id"] for r in data["run_matches"]] == ids
    assert data["disposition"] == "blocked"
    upstream.assert_called_once()


@pytest.mark.parametrize("flushed", [False, True])
def test_run_snapshot_preserves_caller_owned_work(temp_db, runs, flushed):
    ids = runs([context()])
    with temp_db() as caller:
        caller.connection().exec_driver_sql("BEGIN")
        row = caller.get(Execution, ids[0])
        row.status = "abandoned"
        pending = Playbook(title="Caller owned, uncommitted")
        caller.add(pending)
        if flushed:
            caller.flush()
        native = caller.connection().connection.driver_connection
        with patch.object(TheHiveClient, "list_cases", return_value=[]) as upstream:
            data = check_finding(caller, TheHiveClient(base_url="http://thehive.test", api_key="fake-key"),
                                 FindingCheckRequest(**CANDIDATE, run_id=ids[0]))
        assert native.in_transaction
        assert row.status == "abandoned"
        assert pending in caller
        if not flushed:
            assert row in caller.dirty and pending in caller.new and pending.id is None
        with temp_db() as observer:
            assert observer.get(Execution, ids[0]).status == "active"
            assert observer.execute(select(Playbook.id).where(Playbook.title == pending.title)).first() is None
        assert [r.run_id for r in data.run_matches] == ids
        upstream.assert_called_once_with(offset=0, limit=100)
        caller.rollback()
    with temp_db() as observer:
        assert observer.get(Execution, ids[0]).status == "active"
        assert observer.execute(select(Playbook.id).where(Playbook.title == pending.title)).first() is None


def test_case_sentinel_blocks_without_returning_or_following_it(client, api_key, upstream):
    upstream.return_value = [{"_id": f"~C{i}", "status": "Resolved", "tags": ["hotwash:finding:v1:" + "b" * 64]}
                             for i in range(100)] + [{"_id": "~Sentinel", "status": "New", "tags": [TAG]}]
    data = read(client, api_key).json()
    assert data["case_matches"] == [] and data["disposition"] == "blocked"
    assert "cases_capped" in data["gaps"] and data["coverage"]["cases"] == "incomplete"
    assert upstream.call_count == 1


@pytest.mark.parametrize("body", [{"items": []}, [None], [{"_id": "https://private.invalid/secret", "tags": [TAG]}],
                                  [{"_id": "~C1", "id": "~C2", "tags": [TAG]}],
                                  [{"_id": "~C1", "tags": [TAG]}] * 2,
                                  [{"_id": f"~C{i}"} for i in range(102)]])
def test_malformed_case_response_is_sanitized_or_incomplete(client, api_key, upstream, body):
    upstream.return_value = body
    response = read(client, api_key)
    assert response.status_code in (200, 502)
    if response.status_code == 200:
        assert response.json()["disposition"] == "blocked"
        assert response.json()["coverage"]["cases"] == "incomplete"
    else:
        assert response.json() == {"detail": {"message": "TheHive read failed"}}
    assert "private.invalid" not in response.text and "secret" not in response.text


def test_transport_failure_and_integration_gates_are_finite(client, api_key, upstream, temp_db):
    from api.integrations.clients.thehive import TheHiveError
    from api.integrations.config import Integration
    upstream.side_effect = TheHiveError("secret https://private.invalid", status_code=401, details={"key": "secret"})
    response = read(client, api_key)
    assert response.status_code == 502
    assert response.json() == {"detail": {"message": "TheHive read failed"}}
    upstream.reset_mock()
    for field, value in [("enabled", False), ("mock_mode", True), ("api_key", None)]:
        with temp_db() as db:
            row = db.query(Integration).filter_by(tool_name="thehive").one()
            row.enabled, row.mock_mode = True, False
            setattr(row, field, value)
            db.commit()
        assert read(client, api_key).status_code == 400
        upstream.assert_not_called()


# v2 fixtures are portable synthetic observations, independent of source receipts.
ROOTCHECK = {"source": "wazuh", "source_instance_ref": "synthetic-a",
             "agent_registration_ref": "registration-a", "agent_id": "022",
             "signature": "hidden-file-on-dev-v1", "scope": "group", "subject": "/dev/.lxc/proc"}
ROOTCHECK_URL = "/api/integrations/thehive/finding-check/rootcheck-v2"


def rootcheck_read(client, api_key, **changes):
    return client.get(ROOTCHECK_URL, params={**ROOTCHECK, **changes}, headers={"X-API-Key": api_key})


def rootcheck_key(**changes):
    from api.integrations import schemas
    from api.services import soc_cases
    return soc_cases.rootcheck_candidate_key(schemas.RootcheckCandidate(**{**ROOTCHECK, **changes}))


def rootcheck_tag(**changes):
    return "hotwash:rootcheck:v2:" + changes.get("scope", "group") + ":" + rootcheck_key(**changes)[3:]


def rootcheck_context(**changes):
    return {"soc_rootcheck_v2": {**ROOTCHECK, "case_id": "~C1", **changes}}


def receipt_payload(paths=("/dev/.lxc/proc/7/status",), other=True):
    rows = [{"receipt_index": i, "source_record_id": None, "status": "outstanding",
             "source_signature_log": "<untrusted_siem_data>File '" + path +
             "' present on /dev. Possible hidden file.</untrusted_siem_data>",
             "proc_paths": [path], "date_first": "2026-01-01T00:00:00Z",
             "date_last": "2026-01-02T00:00:00Z"} for i, path in enumerate(paths)]
    if other:
        rows.append({"receipt_index": len(rows), "source_record_id": None, "status": "outstanding",
                     "source_signature_log": "<untrusted_siem_data>Unrelated synthetic observation.</untrusted_siem_data>",
                     "proc_paths": [], "date_first": "2026-01-01T00:00:00Z", "date_last": "2026-01-02T00:00:00Z"})
    return {"mode": "historical_cached_receipt_recovery", "recovered_at": "2026-01-03T00:00:00Z",
            "source_session": "synthetic-session", "cache_offset": 0, "tool_name": "synthetic_rootcheck",
            "tool_call_id": "synthetic-call", "request": {"agent_id": "022", "status": "outstanding", "limit": 100},
            "request_observed_at": "2026-01-02T00:00:00Z", "result_observed_at": "2026-01-02T00:00:01Z",
            "result_is_error": False, "total": len(rows), "returned": len(rows),
            "proc_path_records": len(paths), "other_records": int(other),
            "pagination": {"total": len(rows), "limit": 100, "offset": 0, "has_more": False},
            "output_metadata": {"untrusted_data_note": "Synthetic untrusted data"},
            "source_payload_sha256": "a" * 64, "records": rows, "exact_proc_paths": sorted(set(paths)),
            "limits": ["historical only"], "new_soc_calls": 0}


def project_receipt(payload):
    from api.services import soc_cases
    return soc_cases.project_rootcheck_receipt(payload).model_dump(mode="json")


def test_rootcheck_route_is_separate_candidate_read(client, api_key, upstream, temp_db):
    statements = []
    engine = temp_db.kw["bind"]
    def capture(conn, cursor, statement, parameters, ctx, many):
        statements.append(statement)
    event.listen(engine, "before_cursor_execute", capture)
    try:
        response = rootcheck_read(client, api_key)
    finally:
        event.remove(engine, "before_cursor_execute", capture)
    assert response.status_code == 200
    data = response.json()
    assert data["schema_version"] == data["coverage"]["contract_version"] == 2
    assert data["candidate"] == ROOTCHECK and data["candidate_key"].startswith("v2:")
    assert data["disposition"] == "no_match_visible"
    assert set(data["gaps"]) == BASE_GAPS
    assert data["identity_binding"] == data["coverage"]["visibility"] == "unverified"
    assert not {"permit_create", "authoritative", "safe_to_create"} & data.keys()
    assert not any(s.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for s in statements)
    upstream.assert_called_once()


def test_rootcheck_exact_tuple_and_receipt_membership_independence():
    import hashlib
    expected = hashlib.sha256(b'["hotwash-rootcheck",2,"wazuh","synthetic-a","registration-a","022","hidden-file-on-dev-v1","group","/dev/.lxc/proc"]').hexdigest()
    key = rootcheck_key()
    assert key == "v2:" + expected
    for changes in ({"agent_id": "22"}, {"source_instance_ref": "synthetic-b"},
                    {"agent_registration_ref": "registration-b"},
                    {"scope": "path", "subject": "/dev/.lxc/proc/7/status"}):
        assert rootcheck_key(**changes) != key
    a = project_receipt(receipt_payload())
    b = project_receipt(receipt_payload(("/dev/.lxc/proc/8/status",)))
    assert a["exact_proc_paths"] != b["exact_proc_paths"]
    assert rootcheck_key() == key  # Membership is not an identity input.


@pytest.mark.parametrize("changes", [
    {"agent_id": 22}, {"agent_id": "022 "}, {"agent_id": "٢٢"}, {"agent_id": ""},
    {"agent_id": "1" * 129}, {"source_instance_ref": " synthetic-a"},
    {"agent_registration_ref": "https://example.invalid"}, {"source": "WAZUH"},
    {"signature": "other"}, {"subject": "/dev/.lxc/proc/"},
    {"scope": "path", "subject": "/dev/.lxc/proc/../status"},
    {"scope": "path", "subject": "/dev/.lxc/proc//status"},
    {"scope": "path", "subject": "/dev/.lxc/proc/./status"},
    {"scope": "path", "subject": "/dev/.lxc/proc/a\\b"},
    {"scope": "path", "subject": "/dev/.lxc/proc/a\n"},
    {"scope": "path", "subject": "/dev/.lxc/proc/a'b"},
    {"scope": "path", "subject": "/dev/.lxc/proc/a\u200eb"},
    {"scope": "path", "subject": "/dev/.lxc/proc/a\ud800b"},
    {"scope": "path", "subject": "/dev/.lxc/proc/" + "a" * 2000},
    {"scope": "path", "subject": " /dev/.lxc/proc/a"}, {"scope": "other"},
    {"sha256": "a" * 64}, {"rule_id": "1"}, {"run_id": "01"}, {"run_id": "+1"},
    {"run_id": "9223372036854775808"}, {"receipt_url": "https://example.invalid"},
])
def test_rootcheck_schema_and_query_reject_exactness_violations(client, api_key, upstream, changes):
    from api.integrations import schemas
    from pydantic import ValidationError
    # Direct schema proves no integer coercion that query strings cannot expose.
    with pytest.raises(ValidationError):
        schemas.RootcheckCheckRequest(**{**ROOTCHECK, **changes})
    if changes == {"agent_id": 22} or "\ud800" in changes.get("subject", ""):
        return
    response = rootcheck_read(client, api_key, **changes)
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid rootcheck check parameters"}
    upstream.assert_not_called()


def test_rootcheck_missing_duplicate_auth_and_run_before_transport(client, api_key, upstream, runs):
    assert client.get(ROOTCHECK_URL, params=ROOTCHECK).status_code == 401
    for field in ROOTCHECK:
        missing = {k: v for k, v in ROOTCHECK.items() if k != field}
        assert client.get(ROOTCHECK_URL, params=missing, headers={"X-API-Key": api_key}).status_code == 422
        assert client.get(ROOTCHECK_URL, params=list(ROOTCHECK.items()) + [(field, ROOTCHECK[field])],
                          headers={"X-API-Key": api_key}).status_code == 422
    assert rootcheck_read(client, api_key, run_id="1").status_code == 404
    upstream.assert_not_called()
    ids = runs([rootcheck_context()] * 101, ["completed"] * 100 + ["abandoned"])
    data = rootcheck_read(client, api_key, run_id=str(ids[-1])).json()
    assert [r["run_id"] for r in data["run_matches"]] == ids[:100]
    assert data["disposition"] == "blocked" and "runs_capped" in data["gaps"]


@pytest.mark.parametrize("status,stage,expected,gap", [
    ("New", "Open", "one_open_candidate", None),
    ("InProgress", None, "one_open_candidate", None),
    ("Resolved", "Closed", "closed_only", None), ("Deleted", None, "closed_only", None),
    ("New", "Closed", "ambiguous", "case_lifecycle_conflict"),
    ("unknown", None, "blocked", "case_lifecycle_unknown"),
])
def test_rootcheck_lifecycles_remain_candidate_only(client, api_key, upstream, status, stage, expected, gap):
    row = {"_id": "~C1", "status": status, "tags": [rootcheck_tag()]}
    if stage is not None:
        row["stage"] = stage
    upstream.return_value = [row]
    data = rootcheck_read(client, api_key).json()
    assert data["disposition"] == expected
    assert data["case_matches"][0]["identity_basis"] == "candidate_tag_v2"
    assert BASE_GAPS <= set(data["gaps"])
    if gap:
        assert gap in data["gaps"]


def test_rootcheck_multiple_raw_tags_legacy_crossscope_and_sentinel(client, api_key, upstream):
    tag = rootcheck_tag()
    for tags, disposition in ([TAG], "blocked"), ([rootcheck_tag(scope="path", subject="/dev/.lxc/proc/7/status")], "blocked"), \
                             (["unassociated"], "blocked"), ([tag, rootcheck_tag(agent_id="22")], "ambiguous"), \
                             ([tag, "hotwash:rootcheck:v2:group:invalid"], "blocked"):
        upstream.return_value = [{"_id": "~C1", "status": "New", "tags": ["x"] * 150 + tags}]
        assert rootcheck_read(client, api_key).json()["disposition"] == disposition
    upstream.return_value = [{"_id": "~C1", "status": "Resolved", "tags": [tag]},
                             {"_id": "~C2", "status": "Deleted", "tags": [tag]}]
    assert rootcheck_read(client, api_key).json()["disposition"] == "ambiguous"
    upstream.return_value = [{"_id": f"~C{i}", "status": "Resolved", "tags": [rootcheck_tag(agent_id="22")]}
                             for i in range(100)] + [{"_id": "~Sentinel", "status": "New", "tags": [tag]}]
    data = rootcheck_read(client, api_key).json()
    assert data["case_matches"] == [] and data["disposition"] == "blocked"
    assert "cases_capped" in data["gaps"]


@pytest.mark.parametrize("record,gap", [
    ({}, "run_identity_unmapped"), (context(), "run_identity_unmapped"),
    (rootcheck_context(authoritative=True), "run_identity_unmapped"),
    (rootcheck_context(scope="path", subject="/dev/.lxc/proc/7/status"), "run_identity_unmapped"),
    (rootcheck_context(case_id="~Other"), "run_case_link_unresolved"),
    (rootcheck_context(case_id=None), "run_case_link_missing"),
    (rootcheck_context(agent_registration_ref="registration-b"), "run_case_link_conflict"),
    ('{"soc_rootcheck_v2":{},"soc_rootcheck_v2":{}}', "run_context_invalid"),
    ("x" * 65537, "run_context_oversized"),
])
def test_rootcheck_untrusted_runs_block_absence(client, api_key, upstream, runs, record, gap):
    runs([record], ["abandoned"])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [rootcheck_tag()]}]
    data = rootcheck_read(client, api_key).json()
    assert data["disposition"] == "blocked" and gap in data["gaps"]


def test_rootcheck_matching_run_all_states_and_no_authority(client, api_key, upstream, runs):
    ids = runs([rootcheck_context()] * 4, ["active", "completed", "abandoned", "unknown"])
    upstream.return_value = [{"_id": "~C1", "status": "New", "tags": [rootcheck_tag()]}]
    data = rootcheck_read(client, api_key).json()
    assert [r["run_id"] for r in data["run_matches"]] == ids
    assert all(r["attempt_state"] is None and r["identity_basis"] == "untrusted_context_v2" for r in data["run_matches"])
    assert data["disposition"] == "blocked" and "run_attempt_state_unverified" in data["gaps"]


def test_rootcheck_sole_connection_released_and_errors_sanitized(client, api_key, upstream, runs, temp_db, monkeypatch):
    from api import database
    from api.integrations.clients.thehive import TheHiveError
    ids = runs([rootcheck_context()])
    engine = create_engine(temp_db.kw["bind"].url, connect_args={"check_same_thread": False},
                           poolclass=QueuePool, pool_size=1, max_overflow=0, pool_timeout=0)
    temp_db.configure(bind=engine)
    monkeypatch.setattr(database, "engine", engine)
    def outbound(*args, **kwargs):
        assert engine.pool.checkedout() == 0
        with engine.connect() as connection:
            assert not connection.connection.driver_connection.in_transaction
            assert connection.execute(select(Execution.id)).scalars().all() == ids
        raise TheHiveError("secret upstream details")
    upstream.side_effect = outbound
    try:
        response = rootcheck_read(client, api_key, run_id=str(ids[0]))
        assert response.status_code == 502 and response.json() == {"detail": {"message": "TheHive read failed"}}
        assert engine.pool.checkedout() == 0
    finally:
        engine.dispose()


@pytest.mark.parametrize("flushed", [False, True])
def test_rootcheck_preserves_caller_owned_session(temp_db, runs, flushed):
    from api.services import soc_cases
    from api.integrations import schemas
    ids = runs([rootcheck_context()])
    with temp_db() as caller:
        caller.connection().exec_driver_sql("BEGIN")
        row = caller.get(Execution, ids[0])
        row.status = "abandoned"
        pending = Playbook(title="Uncommitted rootcheck owner")
        caller.add(pending)
        if flushed:
            caller.flush()
        with patch.object(TheHiveClient, "list_cases", return_value=[]) as transport:
            data = soc_cases.check_rootcheck(caller, TheHiveClient(base_url="http://thehive.test", api_key="fake"),
                                             schemas.RootcheckCheckRequest(**ROOTCHECK, run_id=ids[0]))
        assert caller.connection().connection.driver_connection.in_transaction
        assert pending in caller and row.status == "abandoned"
        if not flushed:
            assert pending in caller.new and pending.id is None and row in caller.dirty
        with temp_db() as observer:
            assert observer.get(Execution, ids[0]).status == "active"
            assert observer.execute(select(Playbook.id).where(Playbook.title == pending.title)).first() is None
        assert [r.run_id for r in data.run_matches] == ids
        transport.assert_called_once_with(offset=0, limit=100)
        caller.rollback()


def test_rootcheck_projection_retains_rows_not_logs_and_one_pass_entities():
    paths = ("/dev/.lxc/proc/7/a&amp;lt;b", "/dev/.lxc/proc/7/a&amp;lt;b")
    payload = receipt_payload(paths)
    # Documented entities decode once: &amp;lt; becomes literal &lt;.
    for row in payload["records"][:2]:
        row["proc_paths"] = ["/dev/.lxc/proc/7/a&lt;b"]
    payload["exact_proc_paths"] = ["/dev/.lxc/proc/7/a&lt;b"]
    result = project_receipt(payload)
    assert result["disposition"] == "projected"
    assert result["exact_proc_paths"] == payload["exact_proc_paths"]
    assert [r["path"] for r in result["rows"]] == payload["exact_proc_paths"] * 2
    assert [r["receipt_index"] for r in result["rows"]] == [0, 1]
    assert all(r["source_record_id"] is None for r in result["rows"])
    assert result["other_records"] == 1 and result["other_receipt_indexes"] == [2]
    assert result["provenance"] == "historical_cached_receipt_recovery"
    assert result["source_binding"] == "unverified"
    for name in ("tool_name", "tool_call_id", "request", "request_observed_at", "result_observed_at",
                 "recovered_at", "result_is_error", "total", "returned", "pagination", "source_payload_sha256"):
        assert result[name] == payload[name]
    assert "source_signature_log" not in json.dumps(result) and "result_id" not in result


@pytest.mark.parametrize("log", [
    "File '/dev/.lxc/proc/a' present on /dev. Possible hidden file.",
    "<untrusted_siem_data> File '/dev/.lxc/proc/a' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/a' present on /dev. Possible hidden file. extra</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/../a' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/a\\b' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/a\x00b' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/a\nb' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/a'b' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc//a' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/./a' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data>File '/dev/.lxc/proc/' present on /dev. Possible hidden file.</untrusted_siem_data>",
    "<untrusted_siem_data><untrusted_siem_data>File '/dev/.lxc/proc/a' present on /dev. Possible hidden file.</untrusted_siem_data></untrusted_siem_data>",
])
def test_rootcheck_projection_rejects_hostile_or_ambiguous_logs_atomically(log):
    payload = receipt_payload()
    payload["records"][0]["source_signature_log"] = log
    result = project_receipt(payload)
    assert result["disposition"] == "receipt_invalid"
    assert result["rows"] == result["exact_proc_paths"] == result["other_receipt_indexes"] == []


@pytest.mark.parametrize("mutation,expected", [
    (lambda p: p.update(total=101), "receipt_capped"),
    (lambda p: p["pagination"].update(has_more=True), "receipt_capped"),
    (lambda p: p.update(returned=1), "receipt_inconsistent"),
    (lambda p: p.update(exact_proc_paths=["/dev/.lxc/proc/forged"]), "receipt_inconsistent"),
    (lambda p: p["records"][0].update(proc_paths=["/dev/.lxc/proc/forged"]), "receipt_inconsistent"),
    (lambda p: p["records"][0].update(source_record_id="invented"), "receipt_invalid"),
    (lambda p: p["records"][0].update(receipt_index=9), "receipt_inconsistent"),
    (lambda p: p.update(result_is_error=True), "receipt_invalid"),
    (lambda p: p.update(proc_path_records=0), "receipt_inconsistent"),
    (lambda p: p.update(other_records=0), "receipt_inconsistent"),
    (lambda p: p["pagination"].update(offset=1), "receipt_capped"),
    (lambda p: p.update(limits=["x" * 1048576]), "receipt_capped"),
    (lambda p: p["records"][0].update(source_signature_log="x" * 8193), "receipt_capped"),
    (lambda p: p.update(records=p["records"] * 51), "receipt_capped"),
    (lambda p: p.update(records="malformed"), "receipt_invalid"),
])
def test_rootcheck_projection_bounds_and_inconsistency_never_return_subset(mutation, expected):
    payload = receipt_payload()
    mutation(payload)
    result = project_receipt(payload)
    assert result["disposition"] == expected
    assert result["rows"] == result["exact_proc_paths"] == result["other_receipt_indexes"] == []


@pytest.mark.parametrize("outcome", ["projected", "receipt_invalid", "receipt_capped", "receipt_inconsistent"])
def test_rootcheck_projection_mandatory_gaps_on_every_outcome(outcome):
    payload = receipt_payload()
    if outcome == "receipt_invalid":
        payload["result_is_error"] = True
    elif outcome == "receipt_capped":
        payload["pagination"]["has_more"] = True
    elif outcome == "receipt_inconsistent":
        payload["returned"] = 0
    result = project_receipt(payload)
    assert result["disposition"] == outcome
    assert set(result["gaps"]) == BASE_GAPS
    assert result["source_binding"] == "unverified"


@pytest.mark.parametrize("field", ["request_observed_at", "result_observed_at", "recovered_at", "date_first", "date_last"])
@pytest.mark.parametrize("value", ["", "not-a-date", "2026-02-30T00:00:00Z", "2026-01-01", "2026-01-01T00:00:00"])
def test_rootcheck_projection_rejects_malformed_or_naive_times(field, value):
    payload = receipt_payload()
    if field.startswith("date_"):
        payload["records"][0][field] = value
    else:
        payload[field] = value
    result = project_receipt(payload)
    assert result["disposition"] == "receipt_invalid"
    assert result["rows"] == result["exact_proc_paths"] == result["other_receipt_indexes"] == []


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(request_observed_at="2026-01-02T00:00:02Z"),
    lambda p: p.update(recovered_at="2026-01-01T00:00:00Z"),
    lambda p: p["records"][0].update(date_first="2026-01-02T00:00:01Z"),
    lambda p: p["records"][0].update(date_last="2026-01-02T00:00:02Z"),
    lambda p: p["records"][-1].update(date_first="2026-01-03T00:00:00Z"),
    lambda p: p["records"][0].update(status="resolved"),
])
def test_rootcheck_projection_rejects_impossible_chronology_or_status(mutation):
    payload = receipt_payload()
    mutation(payload)
    result = project_receipt(payload)
    assert result["disposition"] == "receipt_inconsistent"
    assert result["rows"] == result["exact_proc_paths"] == result["other_receipt_indexes"] == []


def test_rootcheck_projection_preserves_exact_aware_time_strings():
    payload = receipt_payload()
    payload.update(request_observed_at="2026-01-02T01:00:00.123456+01:00",
                   result_observed_at="2026-01-02T01:00:01.123456+01:00",
                   recovered_at="2026-01-03T00:00:00.000000+00:00")
    result = project_receipt(payload)
    assert result["disposition"] == "projected"
    for name in ("request_observed_at", "result_observed_at", "recovered_at"):
        assert result[name] == payload[name]
    for name in ("date_first", "date_last"):
        assert result["rows"][0][name] == payload["records"][0][name]
