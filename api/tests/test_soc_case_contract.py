"""Finding candidates under synthetic SQLite and mocked connector transport only."""

import json
from unittest.mock import patch

import pytest
from sqlalchemy import event, select

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
