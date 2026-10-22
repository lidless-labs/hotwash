"""HTTP-level tests for the Wazuh ingest router (webhook, mappings, suggestions)."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone

import pytest

from api.orm_models import (
    Execution,
    IngestSuggestion,
    IngestSuppressionLog,
    Playbook,
    WazuhMapping,
)

SECRET = "ingest-secret-0001"
WEBHOOK = "/api/ingest/wazuh"
INVALID_DETAIL = "Invalid signature or mapping"


def _alert(rule_id: str = "5710", agent_id: str = "001", agent_name: str = "web-01", groups=None) -> dict:
    return {
        "rule": {
            "id": rule_id,
            "description": "sshd: attempt to login using a non-existent user",
            "groups": groups if groups is not None else ["syslog", "sshd"],
        },
        "agent": {"id": agent_id, "name": agent_name},
        "full_log": "example log line",
    }


def _sign(body: bytes, secret: str = SECRET) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _headers(mapping_id: int, body: bytes, secret: str = SECRET) -> dict:
    return {
        "X-Hotwash-Mapping-Id": str(mapping_id),
        "X-Hotwash-Signature": _sign(body, secret),
        "Content-Type": "application/json",
    }


@pytest.fixture
def playbook_id(temp_db) -> int:
    graph = {
        "nodes": [
            {"id": "n1", "label": "Triage the alert", "type": "step"},
            {"id": "n2", "label": "Contain the host", "type": "step"},
        ],
        "edges": [{"id": "e1", "source": "n1", "target": "n2"}],
    }
    with temp_db() as session:
        playbook = Playbook(
            title="Ingest playbook",
            category="Incident Response",
            content_markdown="# Ingest playbook",
            graph_json=json.dumps(graph),
        )
        session.add(playbook)
        session.commit()
        return playbook.id


@pytest.fixture
def make_mapping(client, api_key, playbook_id):
    def _make(**overrides) -> dict:
        payload = {
            "name": "ssh failures",
            "playbook_id": playbook_id,
            "mode": "suggest",
            "rule_id_pattern": "5710",
            "cooldown_seconds": 300,
            "hmac_secret": SECRET,
        }
        payload.update(overrides)
        response = client.post("/api/ingest/mappings", headers={"X-API-Key": api_key}, json=payload)
        assert response.status_code == 201, response.text
        return response.json()

    return _make


def _post_alert(client, mapping_id: int, alert: dict | None = None, secret: str = SECRET):
    body = json.dumps(alert if alert is not None else _alert()).encode()
    return client.post(WEBHOOK, content=body, headers=_headers(mapping_id, body, secret))


def _count(temp_db, model, **filters) -> int:
    with temp_db() as session:
        return session.query(model).filter_by(**filters).count()


# --- Webhook authentication ---------------------------------------------------


def test_valid_signature_is_accepted(client, make_mapping):
    mapping = make_mapping()

    response = _post_alert(client, mapping["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "suggested"
    assert response.json()["mapping_id"] == mapping["id"]


def test_bare_hex_signature_without_prefix_is_accepted(client, make_mapping):
    mapping = make_mapping()
    body = json.dumps(_alert()).encode()
    headers = _headers(mapping["id"], body)
    headers["X-Hotwash-Signature"] = headers["X-Hotwash-Signature"].removeprefix("sha256=")

    assert client.post(WEBHOOK, content=body, headers=headers).status_code == 200


def test_every_authentication_failure_returns_the_same_401(client, make_mapping, temp_db):
    mapping = make_mapping()
    disabled = make_mapping(name="disabled mapping", enabled=False)
    body = json.dumps(_alert()).encode()
    good = _headers(mapping["id"], body)
    cases = {
        "wrong signature": {**good, "X-Hotwash-Signature": _sign(body, "some-other-secret")},
        "tampered body": None,
        "missing signature": {k: v for k, v in good.items() if k != "X-Hotwash-Signature"},
        "empty signature": {**good, "X-Hotwash-Signature": ""},
        "malformed signature": {**good, "X-Hotwash-Signature": "not-a-signature"},
        "short hex signature": {**good, "X-Hotwash-Signature": "sha256=abcd"},
        "prefix only": {**good, "X-Hotwash-Signature": "sha256="},
        "unknown mapping id": {**good, "X-Hotwash-Mapping-Id": "9999"},
        "disabled mapping": _headers(disabled["id"], body),
    }

    for label, headers in cases.items():
        if label == "tampered body":
            response = client.post(WEBHOOK, content=body + b" ", headers=good)
        else:
            response = client.post(WEBHOOK, content=body, headers=headers)
        assert response.status_code == 401, label
        assert response.json()["detail"] == INVALID_DETAIL, label

    assert _count(temp_db, IngestSuggestion) == 0


def test_mapping_id_header_must_be_present_and_numeric(client, make_mapping):
    make_mapping()
    body = json.dumps(_alert()).encode()

    missing = client.post(WEBHOOK, content=body, headers={"X-Hotwash-Signature": _sign(body)})
    non_numeric = client.post(
        WEBHOOK,
        content=body,
        headers={"X-Hotwash-Mapping-Id": "abc", "X-Hotwash-Signature": _sign(body)},
    )

    assert missing.status_code == 400
    assert non_numeric.status_code == 400


def test_webhook_does_not_need_an_api_key(client, make_mapping):
    mapping = make_mapping()

    response = _post_alert(client, mapping["id"])

    assert response.status_code == 200


def test_signed_but_invalid_bodies_are_rejected(client, make_mapping):
    mapping = make_mapping()
    for raw in (b"not json", b"[1, 2]", b'"text"'):
        response = client.post(WEBHOOK, content=raw, headers=_headers(mapping["id"], raw))
        assert response.status_code == 400, raw


# --- Body size cap ----------------------------------------------------------------


def test_oversized_body_with_matching_content_length_returns_413(client, make_mapping):
    mapping = make_mapping()
    body = json.dumps({"full_log": "x" * (256 * 1024 + 1)}).encode()

    response = client.post(WEBHOOK, content=body, headers=_headers(mapping["id"], body))

    assert response.status_code == 413


def test_oversized_body_without_content_length_returns_413(client, make_mapping):
    mapping = make_mapping()
    body = json.dumps({"full_log": "x" * (256 * 1024 + 1)}).encode()

    def chunks():
        for start in range(0, len(body), 64 * 1024):
            yield body[start : start + 64 * 1024]

    response = client.post(WEBHOOK, content=chunks(), headers=_headers(mapping["id"], body))

    assert response.status_code == 413


def test_body_at_the_cap_is_still_processed(client, make_mapping):
    mapping = make_mapping()
    alert = _alert()
    alert["full_log"] = ""
    overhead = len(json.dumps(alert).encode())
    alert["full_log"] = "x" * (256 * 1024 - overhead)
    body = json.dumps(alert).encode()
    assert len(body) == 256 * 1024

    response = client.post(WEBHOOK, content=body, headers=_headers(mapping["id"], body))

    assert response.status_code == 200


# --- Modes -----------------------------------------------------------------------------


def test_auto_mode_starts_an_execution_with_the_alert_as_context(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto")

    response = _post_alert(client, mapping["id"])

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "dispatched"
    with temp_db() as session:
        execution = session.query(Execution).filter_by(id=data["execution_id"]).one()
        context = json.loads(execution.context_json)
        assert execution.status == "active"
        assert execution.started_by == "wazuh-ingest"
        assert context["wazuh_alert"]["rule"]["id"] == "5710"
        assert context["ingest"]["mapping_id"] == mapping["id"]
    assert _count(temp_db, IngestSuggestion) == 0


def test_suggest_mode_queues_a_pending_suggestion_and_starts_nothing(client, make_mapping, temp_db, api_key):
    mapping = make_mapping(mode="suggest")

    response = _post_alert(client, mapping["id"])

    assert response.json()["status"] == "suggested"
    assert _count(temp_db, Execution) == 0
    queue = client.get("/api/ingest/suggestions", headers={"X-API-Key": api_key}).json()
    assert [row["id"] for row in queue] == [response.json()["suggestion_id"]]
    assert queue[0]["state"] == "pending"
    assert queue[0]["rule_id"] == "5710"
    assert queue[0]["agent_name"] == "web-01"


def test_off_mode_logs_only(client, make_mapping, temp_db):
    mapping = make_mapping(mode="off")

    response = _post_alert(client, mapping["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "ignored"
    assert _count(temp_db, Execution) == 0
    assert _count(temp_db, IngestSuggestion) == 0
    assert _count(temp_db, IngestSuppressionLog, reason="mode_off") == 1


def test_alert_that_does_not_match_the_mapping_is_ignored_and_logged(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto")

    response = _post_alert(client, mapping["id"], _alert(rule_id="9999"))

    assert response.json()["status"] == "ignored"
    assert _count(temp_db, Execution) == 0
    assert _count(temp_db, IngestSuppressionLog, reason="no_match") == 1


# --- Cooldown ---------------------------------------------------------------------------


def test_second_alert_inside_the_cooldown_is_suppressed(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto", cooldown_seconds=300)

    first = _post_alert(client, mapping["id"])
    second = _post_alert(client, mapping["id"])

    assert first.json()["status"] == "dispatched"
    assert second.json()["status"] == "suppressed"
    assert "300s cooldown" in second.json()["reason"]
    assert _count(temp_db, Execution) == 1
    assert _count(temp_db, IngestSuppressionLog, reason="cooldown") == 1


def test_cooldown_is_per_agent(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto")

    _post_alert(client, mapping["id"], _alert(agent_id="001"))
    other = _post_alert(client, mapping["id"], _alert(agent_id="002", agent_name="web-02"))

    assert other.json()["status"] == "dispatched"
    assert _count(temp_db, Execution) == 2


def test_zero_cooldown_never_suppresses(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto", cooldown_seconds=0)

    statuses = [_post_alert(client, mapping["id"]).json()["status"] for _ in range(3)]

    assert statuses == ["dispatched"] * 3
    assert _count(temp_db, Execution) == 3


def test_alert_after_the_cooldown_window_is_dispatched_again(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto", cooldown_seconds=300)
    assert _post_alert(client, mapping["id"]).json()["status"] == "dispatched"
    with temp_db() as session:
        for row in session.query(IngestSuppressionLog).all():
            row.created_at = datetime.now(timezone.utc) - timedelta(seconds=301)
        session.commit()

    again = _post_alert(client, mapping["id"])

    assert again.json()["status"] == "dispatched"
    assert _count(temp_db, Execution) == 2


def test_no_match_rows_do_not_anchor_the_cooldown(client, make_mapping, temp_db):
    mapping = make_mapping(mode="auto", rule_id_pattern=None, rule_groups_pattern="authentication_failed")

    miss = _post_alert(client, mapping["id"], _alert(groups=["other"]))
    hit = _post_alert(client, mapping["id"], _alert(groups=["authentication_failed"]))

    assert miss.json()["status"] == "ignored"
    assert miss.json()["fingerprint"] == hit.json()["fingerprint"]
    assert hit.json()["status"] == "dispatched"


def test_mode_off_rows_do_not_anchor_the_cooldown(client, make_mapping, api_key):
    mapping = make_mapping(mode="off")
    assert _post_alert(client, mapping["id"]).json()["status"] == "ignored"
    patched = client.patch(
        f"/api/ingest/mappings/{mapping['id']}", headers={"X-API-Key": api_key}, json={"mode": "suggest"}
    )
    assert patched.status_code == 200

    after = _post_alert(client, mapping["id"])

    assert after.json()["status"] == "suggested"


# --- Mapping CRUD -----------------------------------------------------------------------------


def test_create_mapping_never_returns_the_secret(client, api_key, make_mapping):
    mapping = make_mapping()

    assert mapping["has_hmac_secret"] is True
    assert "hmac_secret" not in mapping
    fetched = client.get(f"/api/ingest/mappings/{mapping['id']}", headers={"X-API-Key": api_key})
    listed = client.get("/api/ingest/mappings", headers={"X-API-Key": api_key})
    for response in (fetched, listed):
        assert SECRET not in response.text
        assert "hmac_secret" not in response.text.replace("has_hmac_secret", "")
    assert [row["id"] for row in listed.json()] == [mapping["id"]]


def test_secret_is_stored_encrypted(make_mapping, temp_db):
    mapping = make_mapping()

    with temp_db() as session:
        row = session.query(WazuhMapping).filter_by(id=mapping["id"]).one()
        assert row.hmac_secret_encrypted
        assert SECRET not in row.hmac_secret_encrypted


@pytest.mark.parametrize(
    "overrides, status",
    [
        ({"mode": "loud"}, 400),
        ({"rule_id_pattern": None}, 400),
        ({"rule_id_pattern": "   "}, 400),
        ({"playbook_id": 9999}, 404),
        ({"hmac_secret": "short"}, 422),
        ({"name": ""}, 422),
        ({"cooldown_seconds": -1}, 422),
        ({"unexpected": True}, 422),
    ],
)
def test_create_mapping_validation(client, api_key, playbook_id, overrides, status):
    payload = {
        "name": "m",
        "playbook_id": playbook_id,
        "mode": "suggest",
        "rule_id_pattern": "5710",
        "hmac_secret": SECRET,
        **overrides,
    }

    response = client.post("/api/ingest/mappings", headers={"X-API-Key": api_key}, json=payload)

    assert response.status_code == status


def test_patch_updates_fields_and_keeps_the_secret_when_not_supplied(client, api_key, make_mapping):
    mapping = make_mapping()

    response = client.patch(
        f"/api/ingest/mappings/{mapping['id']}",
        headers={"X-API-Key": api_key},
        json={"name": "renamed", "cooldown_seconds": 10, "mode": "auto"},
    )

    assert response.status_code == 200
    body = response.json()
    assert (body["name"], body["cooldown_seconds"], body["mode"]) == ("renamed", 10, "auto")
    assert _post_alert(client, mapping["id"]).status_code == 200


def test_secret_rotation_invalidates_the_old_secret(client, api_key, make_mapping):
    mapping = make_mapping()
    assert _post_alert(client, mapping["id"]).status_code == 200

    rotated = client.patch(
        f"/api/ingest/mappings/{mapping['id']}",
        headers={"X-API-Key": api_key},
        json={"hmac_secret": "rotated-secret-0002"},
    )

    assert rotated.status_code == 200
    assert "rotated-secret-0002" not in rotated.text
    assert rotated.json()["has_hmac_secret"] is True
    assert _post_alert(client, mapping["id"], secret=SECRET).status_code == 401
    assert _post_alert(client, mapping["id"], secret="rotated-secret-0002").status_code == 200


def test_patch_rejects_removing_every_pattern_and_bad_values(client, api_key, make_mapping, playbook_id):
    mapping = make_mapping()
    url = f"/api/ingest/mappings/{mapping['id']}"
    headers = {"X-API-Key": api_key}

    assert client.patch(url, headers=headers, json={"rule_id_pattern": ""}).status_code == 400
    assert client.patch(url, headers=headers, json={"mode": "loud"}).status_code == 400
    assert client.patch(url, headers=headers, json={"playbook_id": 9999}).status_code == 404
    assert client.patch(url, headers=headers, json={"hmac_secret": "short"}).status_code == 422
    assert client.patch("/api/ingest/mappings/9999", headers=headers, json={"name": "x"}).status_code == 404
    assert client.get(url, headers=headers).json()["rule_id_pattern"] == "5710"


def test_disabled_mapping_stops_accepting_alerts(client, api_key, make_mapping):
    mapping = make_mapping()
    client.patch(f"/api/ingest/mappings/{mapping['id']}", headers={"X-API-Key": api_key}, json={"enabled": False})

    response = _post_alert(client, mapping["id"])

    assert response.status_code == 401
    assert response.json()["detail"] == INVALID_DETAIL


def test_delete_mapping(client, api_key, make_mapping):
    mapping = make_mapping()
    headers = {"X-API-Key": api_key}

    assert client.delete(f"/api/ingest/mappings/{mapping['id']}", headers=headers).status_code == 204
    assert client.get(f"/api/ingest/mappings/{mapping['id']}", headers=headers).status_code == 404
    assert client.delete(f"/api/ingest/mappings/{mapping['id']}", headers=headers).status_code == 404
    assert _post_alert(client, mapping["id"]).status_code == 401


def test_mapping_and_suggestion_routes_require_the_api_key(client, make_mapping):
    mapping = make_mapping()
    routes = [
        ("get", "/api/ingest/mappings"),
        ("post", "/api/ingest/mappings"),
        ("get", f"/api/ingest/mappings/{mapping['id']}"),
        ("patch", f"/api/ingest/mappings/{mapping['id']}"),
        ("delete", f"/api/ingest/mappings/{mapping['id']}"),
        ("get", "/api/ingest/suggestions"),
        ("get", "/api/ingest/suggestions/1"),
        ("post", "/api/ingest/suggestions/1/accept"),
        ("post", "/api/ingest/suggestions/1/dismiss"),
    ]
    for method, path in routes:
        assert getattr(client, method)(path).status_code == 401, (method, path)
        assert getattr(client, method)(path, headers={"X-API-Key": "wrong"}).status_code == 401, (method, path)


# --- Suggestions ---------------------------------------------------------------------------------


@pytest.fixture
def suggestion(client, make_mapping):
    mapping = make_mapping(mode="suggest")
    created = _post_alert(client, mapping["id"]).json()
    return {"id": created["suggestion_id"], "mapping_id": mapping["id"]}


def test_list_filters_and_bounds(client, api_key, make_mapping, suggestion):
    headers = {"X-API-Key": api_key}
    other = make_mapping(name="other", rule_id_pattern="5711")
    _post_alert(client, other["id"], _alert(rule_id="5711"))

    assert len(client.get("/api/ingest/suggestions", headers=headers).json()) == 2
    only = client.get(f"/api/ingest/suggestions?mapping_id={suggestion['mapping_id']}", headers=headers).json()
    assert [row["id"] for row in only] == [suggestion["id"]]
    assert client.get("/api/ingest/suggestions?state=accepted", headers=headers).json() == []
    assert len(client.get("/api/ingest/suggestions?limit=1", headers=headers).json()) == 1
    assert client.get("/api/ingest/suggestions?state=bogus", headers=headers).status_code == 400
    assert client.get("/api/ingest/suggestions?limit=0", headers=headers).status_code == 422
    assert client.get("/api/ingest/suggestions?limit=501", headers=headers).status_code == 422


def test_suggestion_detail_includes_alert_and_mapping(client, api_key, suggestion):
    response = client.get(f"/api/ingest/suggestions/{suggestion['id']}", headers={"X-API-Key": api_key})

    assert response.status_code == 200
    body = response.json()
    assert body["alert_payload"]["rule"]["id"] == "5710"
    assert body["playbook_title"] == "Ingest playbook"
    assert body["mapping"]["id"] == suggestion["mapping_id"]
    assert "hmac_secret" not in json.dumps(body).replace("has_hmac_secret", "")
    assert client.get("/api/ingest/suggestions/9999", headers={"X-API-Key": api_key}).status_code == 404


def test_accept_creates_an_execution_and_is_idempotent(client, api_key, suggestion, temp_db):
    headers = {"X-API-Key": api_key}
    url = f"/api/ingest/suggestions/{suggestion['id']}/accept?confirm=true"

    first = client.post(url, headers=headers)
    second = client.post(url, headers=headers)

    assert first.status_code == 200
    assert first.json()["already_accepted"] is False
    assert second.status_code == 200
    assert second.json()["already_accepted"] is True
    assert second.json()["execution"]["id"] == first.json()["execution"]["id"]
    assert first.json()["execution"]["steps_total"] == 2
    assert _count(temp_db, Execution) == 1
    detail = client.get(f"/api/ingest/suggestions/{suggestion['id']}", headers=headers).json()
    assert detail["state"] == "accepted"
    assert detail["accepted_execution_id"] == first.json()["execution"]["id"]
    assert detail["resolved_at"] is not None


def test_dismiss_resolves_and_cannot_be_repeated_or_reversed(client, api_key, suggestion, temp_db):
    headers = {"X-API-Key": api_key}
    dismiss = f"/api/ingest/suggestions/{suggestion['id']}/dismiss?confirm=true"

    first = client.post(dismiss, headers=headers, json={"reason": "known scanner"})

    assert first.status_code == 200
    assert first.json()["state"] == "dismissed"
    assert "known scanner" not in first.text
    assert client.post(dismiss, headers=headers).status_code == 409
    accept = client.post(f"/api/ingest/suggestions/{suggestion['id']}/accept?confirm=true", headers=headers)
    assert accept.status_code == 409
    assert _count(temp_db, Execution) == 0


def test_dismissing_an_accepted_suggestion_returns_409(client, api_key, suggestion):
    headers = {"X-API-Key": api_key}
    client.post(f"/api/ingest/suggestions/{suggestion['id']}/accept?confirm=true", headers=headers)

    response = client.post(f"/api/ingest/suggestions/{suggestion['id']}/dismiss?confirm=true", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == "Suggestion has already been accepted"


def test_accept_and_dismiss_report_404_for_unknown_ids(client, api_key):
    headers = {"X-API-Key": api_key}

    assert client.post("/api/ingest/suggestions/9999/accept?confirm=true", headers=headers).status_code == 404
    assert client.post("/api/ingest/suggestions/9999/dismiss?confirm=true", headers=headers).status_code == 404


def test_dismiss_reason_is_bounded(client, api_key, suggestion):
    response = client.post(
        f"/api/ingest/suggestions/{suggestion['id']}/dismiss?confirm=true",
        headers={"X-API-Key": api_key},
        json={"reason": "x" * 501},
    )

    assert response.status_code == 422


def test_dismiss_anchors_the_cooldown_for_the_same_fingerprint(client, api_key, suggestion, temp_db):
    headers = {"X-API-Key": api_key}
    # Age the original dispatch past the window so only the dismissal can anchor.
    with temp_db() as session:
        for row in session.query(IngestSuppressionLog).all():
            row.created_at = datetime.now(timezone.utc) - timedelta(seconds=3600)
        session.commit()

    client.post(f"/api/ingest/suggestions/{suggestion['id']}/dismiss?confirm=true", headers=headers)
    again = _post_alert(client, suggestion["mapping_id"])

    assert _count(temp_db, IngestSuppressionLog, reason="suggestion_dismissed") == 1
    assert again.json()["status"] == "suppressed"


def test_accept_fails_cleanly_when_the_playbook_was_removed(client, api_key, suggestion, temp_db):
    with temp_db() as session:
        session.query(Playbook).update({"is_deleted": True})
        session.commit()

    response = client.post(
        f"/api/ingest/suggestions/{suggestion['id']}/accept?confirm=true", headers={"X-API-Key": api_key}
    )

    assert response.status_code == 409
    assert _count(temp_db, Execution) == 0


def test_accept_fails_cleanly_when_the_stored_alert_is_corrupt(client, api_key, suggestion, temp_db):
    with temp_db() as session:
        session.query(IngestSuggestion).update({"alert_payload_json": "{not json"})
        session.commit()

    response = client.post(
        f"/api/ingest/suggestions/{suggestion['id']}/accept?confirm=true", headers={"X-API-Key": api_key}
    )

    assert response.status_code == 409
    assert "not valid JSON" not in response.text
