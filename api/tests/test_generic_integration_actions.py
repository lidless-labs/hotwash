"""Tests for generic integration action endpoints."""

from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from api.crypto import encrypt_secret
from api.orm_models import Execution, ExecutionEvent, Playbook, RunEvent
from api.security import PinnedURL
from api.services import replay
from api.services.executions import serialize_steps


def _enable_webhook(temp_db, *, mock_mode: bool = False):
    from api.integrations.config import Integration

    with temp_db() as session:
        integration = session.query(Integration).filter_by(tool_name="http_webhook").first()
        integration.base_url = "https://webhook.example/base"
        integration.enabled = True
        integration.mock_mode = mock_mode
        integration.verify_ssl = True
        integration.api_key = encrypt_secret("webhook-key")
        session.commit()


def _enable_wazuh(temp_db, *, mock_mode: bool = False):
    from api.integrations.config import Integration

    with temp_db() as session:
        integration = session.query(Integration).filter_by(tool_name="wazuh").first()
        integration.base_url = "https://wazuh.example:55000"
        integration.username = "alice"
        integration.password = encrypt_secret("secret")
        integration.enabled = True
        integration.mock_mode = mock_mode
        integration.verify_ssl = True
        session.commit()


def _create_execution(temp_db, *, node_id: str = "exec_1") -> int:
    steps = [
        {
            "node_id": node_id,
            "node_type": "execute",
            "node_label": "Notify webhook",
            "phase": None,
            "status": "not_started",
            "assignee": None,
            "notes": [],
            "evidence": [],
            "decision_taken": None,
            "decision_options": None,
            "started_at": None,
            "completed_at": None,
        }
    ]
    with temp_db() as session:
        playbook = Playbook(
            title="Webhook playbook",
            category="Test",
            content_markdown="# Test",
            graph_json=json.dumps({"nodes": [{"id": node_id, "type": "execute", "label": "Notify webhook"}], "edges": []}),
        )
        session.add(playbook)
        session.flush()
        execution = Execution(
            playbook_id=playbook.id,
            incident_title="Incident",
            status="active",
            steps_json=serialize_steps(steps),
        )
        session.add(execution)
        session.flush()
        session.add(
            RunEvent(
                execution_id=execution.id,
                event_type=replay.RUN_STARTED,
                payload_json=json.dumps({"genesis": steps}),
            )
        )
        session.commit()
        return execution.id


def test_lists_actions_for_registered_tool(client, api_key):
    resp = client.get("/api/integrations/http_webhook/actions", headers={"X-API-Key": api_key})

    assert resp.status_code == 200
    body = resp.json()
    assert body[0]["name"] == "post_json"
    assert "schema" in body[0]
    assert "body" in body[0]["schema"]["properties"]


def test_lists_wazuh_actions(client, api_key):
    resp = client.get("/api/integrations/wazuh/actions", headers={"X-API-Key": api_key})

    assert resp.status_code == 200
    names = [item["name"] for item in resp.json()]
    assert names == ["get_agent", "get_agents", "run_active_response"]


def test_seed_integrations_adds_missing_default_without_duplicates(temp_db):
    from api.integrations.config import Integration
    from api.seed import seed_integrations

    with temp_db() as session:
        session.query(Integration).filter_by(tool_name="http_webhook").delete()
        session.commit()

        inserted = seed_integrations(session)
        second_insert = seed_integrations(session)
        tools = [row[0] for row in session.query(Integration.tool_name).all()]

    assert inserted == 1
    assert second_insert == 0
    assert tools.count("http_webhook") == 1


def test_generic_route_dispatches_thehive_with_existing_response_shape(client, configured_thehive, api_key):
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        side_effect=lambda url: PinnedURL(url=url, hostname=None, host_header=None),
    ), patch("api.integrations.connectors.TheHiveClient") as MockClient:
        MockClient.return_value.create_case.return_value = {"_id": "~123", "number": 42}
        resp = client.post(
            "/api/integrations/thehive/actions/create_case",
            headers={"X-API-Key": api_key},
            json={"title": "case", "description": "desc"},
        )

    assert resp.status_code == 200
    assert resp.json() == {
        "case_id": "~123",
        "number": 42,
        "url": "http://thehive.test:9000/cases/42/details",
        "raw": {"_id": "~123", "number": 42},
    }


def test_generic_route_dispatches_wazuh_action(client, temp_db, api_key):
    _enable_wazuh(temp_db)

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.get_agent.return_value = {
            "data": {"affected_items": [{"id": "001", "name": "web01"}], "total_affected_items": 1}
        }
        resp = client.post(
            "/api/integrations/wazuh/actions/get_agent",
            headers={"X-API-Key": api_key},
            json={"agent_id": "001"},
        )

    assert resp.status_code == 200
    assert resp.json() == {
        "agent": {"id": "001", "name": "web01"},
        "raw": {"data": {"affected_items": [{"id": "001", "name": "web01"}], "total_affected_items": 1}},
    }
    MockClient.return_value.get_agent.assert_called_once_with("001")


def test_wazuh_upstream_error_maps_to_502(client, temp_db, api_key):
    from api.integrations.clients.wazuh import WazuhError

    _enable_wazuh(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.get_agent.side_effect = WazuhError(
            "Wazuh returned 503",
            status_code=503,
            details={"title": "Service unavailable"},
        )
        resp = client.post(
            "/api/integrations/wazuh/actions/get_agent",
            headers={"X-API-Key": api_key},
            json={"agent_id": "001"},
        )

    assert resp.status_code == 502
    assert resp.json()["detail"] == {
        "message": "Wazuh returned 503",
        "upstream_status": 503,
        "details": {"title": "Service unavailable"},
    }


def test_wazuh_test_endpoint_uses_connector_api_info(client, temp_db, api_key):
    _enable_wazuh(temp_db)

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.api_info.return_value = {"title": "Wazuh API", "api_version": "4.7.2"}
        resp = client.post("/api/integrations/wazuh/test", headers={"X-API-Key": api_key})

    assert resp.status_code == 200
    assert resp.json()["result"] == {
        "status": "connected",
        "title": "Wazuh API",
        "api_version": "4.7.2",
        "raw": {"title": "Wazuh API", "api_version": "4.7.2"},
    }


def test_unknown_tool_and_action_return_404(client, api_key):
    unknown_tool = client.get("/api/integrations/nope/actions", headers={"X-API-Key": api_key})
    unknown_action = client.post(
        "/api/integrations/http_webhook/actions/nope",
        headers={"X-API-Key": api_key},
        json={"body": {"event": "x"}},
    )

    assert unknown_tool.status_code == 404
    assert unknown_action.status_code == 404


def test_generic_action_rejects_disabled_integration(client, api_key):
    resp = client.post(
        "/api/integrations/http_webhook/actions/post_json",
        headers={"X-API-Key": api_key},
        json={"body": {"event": "x"}},
    )

    assert resp.status_code == 400
    assert "disabled" in resp.json()["detail"].lower()


def test_mock_mode_short_circuits_without_http_request(client, temp_db, api_key):
    _enable_webhook(temp_db, mock_mode=True)

    with patch("api.integrations.connectors.requests.Session") as session_cls:
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"body": {"event": "x"}},
        )

    assert resp.status_code == 200
    assert resp.json()["status_code"] == 200
    assert resp.json()["mock"] is True
    session_cls.assert_not_called()


def test_wazuh_mock_mode_short_circuits_without_client(client, temp_db, api_key):
    _enable_wazuh(temp_db, mock_mode=True)

    with patch("api.integrations.connectors.WazuhClient") as MockClient:
        resp = client.post(
            "/api/integrations/wazuh/actions/run_active_response",
            headers={"X-API-Key": api_key},
            json={"command": "restart-wazuh0", "agent_ids": ["001"]},
        )

    assert resp.status_code == 200
    assert resp.json()["mock"] is True
    assert resp.json()["connector"] == "wazuh"
    assert resp.json()["action"] == "run_active_response"
    MockClient.assert_not_called()


def test_action_result_attaches_to_run_evidence_before_return(client, temp_db, api_key, monkeypatch, tmp_path):
    from api.routers import integrations

    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db)
    monkeypatch.setattr(integrations, "EVIDENCE_ROOT", tmp_path / "evidence")

    response = type(
        "Response",
        (),
        {
            "status_code": 200,
            "text": '{"ok": true}',
            "json": lambda self: {"ok": True},
        },
    )()
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34/base", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.requests.Session") as session_cls:
        session = session_cls.return_value
        session.headers = {}
        session.post.return_value = response
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"run_id": execution_id, "node_id": "exec_1", "body": {"event": "x"}},
        )

    assert resp.status_code == 200
    with temp_db() as session:
        execution = session.query(Execution).filter_by(id=execution_id).one()
        steps = json.loads(execution.steps_json)
        evidence = steps[0]["evidence"][-1]
        assert evidence["filename"] == "http_webhook-post_json-result.json"
        assert evidence["connector"] == "http_webhook"
        assert evidence["action"] == "post_json"
        assert evidence["result"] == {"status_code": 200, "body": {"ok": True}}
        evidence["unexpected_internal_field"] = "must not be exposed"
        execution.steps_json = serialize_steps(steps)
        session.commit()
        assert session.query(ExecutionEvent).filter_by(event_type="evidence_attached").count() == 1
        assert session.query(RunEvent).filter_by(event_type=replay.STEP_EVIDENCE_ATTACHED).count() == 1

    detail = client.get(f"/api/executions/{execution_id}", headers={"X-API-Key": api_key})
    assert detail.status_code == 200
    api_evidence = detail.json()["steps"][0]["evidence"][-1]
    assert api_evidence["connector"] == "http_webhook"
    assert api_evidence["action"] == "post_json"
    assert api_evidence["result"] == {"status_code": 200, "body": {"ok": True}}
    assert "unexpected_internal_field" not in api_evidence


@pytest.mark.parametrize(
    "run_context",
    [
        {"run_id": "execution"},
        {"node_id": "exec_1"},
    ],
)
def test_partial_run_context_is_rejected_before_action(
    client, temp_db, api_key, run_context
):
    from api.integrations.connectors import HttpWebhookConnector

    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db)
    payload = {"body": {"event": "x"}}
    payload.update(run_context)
    if payload.get("run_id") == "execution":
        payload["run_id"] = execution_id

    with patch.object(
        HttpWebhookConnector,
        "execute",
        return_value={"status_code": 200, "body": {"ok": True}},
    ) as execute:
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json=payload,
        )

    assert resp.status_code == 422
    assert "run_id and node_id" in resp.json()["detail"]
    execute.assert_not_called()


def test_action_result_retries_cas_conflict_and_preserves_concurrent_update(monkeypatch, tmp_path):
    from api.routers import integrations

    monkeypatch.setattr(integrations, "EVIDENCE_ROOT", tmp_path / "evidence")
    original_steps = [
        {
            "node_id": "exec_1",
            "node_label": "Notify webhook",
            "notes": [],
            "evidence": [],
        }
    ]
    concurrent_steps = json.loads(serialize_steps(original_steps))
    concurrent_steps[0]["notes"] = ["updated during evidence attachment"]
    execution = SimpleNamespace(id=42, steps_json=serialize_steps(original_steps))

    class FakeQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def first(self):
            return execution

    class ConflictingSession:
        def __init__(self):
            self.execute_calls = 0
            self.rollbacks = 0
            self.persisted_steps_json = None
            self.added = []

        def expire_all(self):
            return None

        def query(self, _model):
            return FakeQuery()

        def execute(self, statement):
            self.execute_calls += 1
            if self.execute_calls == 1:
                execution.steps_json = serialize_steps(concurrent_steps)
                return SimpleNamespace(rowcount=0)
            params = statement.compile().params
            self.persisted_steps_json = next(
                value for key, value in params.items() if key.startswith("steps_json")
            )
            return SimpleNamespace(rowcount=1)

        def rollback(self):
            self.rollbacks += 1

        def add(self, value):
            self.added.append(value)

    db = ConflictingSession()
    integrations._attach_action_result(
        db,
        execution.id,
        "exec_1",
        tool="http_webhook",
        action="post_json",
        result={"status_code": 200, "body": {"ok": True}},
    )

    persisted_steps = json.loads(db.persisted_steps_json)
    assert db.execute_calls == 2
    assert db.rollbacks == 1
    assert persisted_steps[0]["notes"] == ["updated during evidence attachment"]
    assert len(persisted_steps[0]["evidence"]) == 1


def test_action_result_cleans_file_after_exhausted_cas_retries(monkeypatch, tmp_path):
    from api.routers import integrations

    monkeypatch.setattr(integrations, "EVIDENCE_ROOT", tmp_path / "evidence")
    monkeypatch.setattr(integrations, "STEPS_JSON_CAS_MAX_RETRIES", 2)
    steps = [{"node_id": "exec_1", "node_label": "Notify webhook", "evidence": []}]
    execution = SimpleNamespace(id=42, steps_json=serialize_steps(steps))

    class AlwaysConflictingSession:
        def expire_all(self):
            return None

        def query(self, _model):
            return SimpleNamespace(
                filter=lambda *_args, **_kwargs: SimpleNamespace(first=lambda: execution)
            )

        def execute(self, _statement):
            return SimpleNamespace(rowcount=0)

        def rollback(self):
            return None

    with pytest.raises(HTTPException, match="Concurrent execution update"):
        integrations._attach_action_result(
            AlwaysConflictingSession(),
            execution.id,
            "exec_1",
            tool="http_webhook",
            action="post_json",
            result={"status_code": 200, "body": {"ok": True}},
        )

    target_dir = tmp_path / "evidence" / "42" / "exec_1"
    assert list(target_dir.iterdir()) == []


def test_action_result_bounds_inline_payload_but_keeps_full_evidence_file(
    client, temp_db, api_key, monkeypatch, tmp_path
):
    from api.integrations.connectors import HttpWebhookConnector
    from api.routers import integrations

    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db)
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(integrations, "EVIDENCE_ROOT", evidence_root)
    large_payload = {"blob": "x" * 5000}
    connector_result = {"status_code": 200, "body": large_payload}

    with patch.object(
        HttpWebhookConnector,
        "execute",
        return_value=connector_result,
    ):
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"run_id": execution_id, "node_id": "exec_1", "body": {"event": "x"}},
        )

    assert resp.status_code == 200
    assert resp.json() == connector_result

    file_body = json.dumps(connector_result, default=str, indent=2, sort_keys=True).encode("utf-8")
    expected_summary = {
        "truncated": True,
        "size_bytes": len(file_body),
        "sha256": hashlib.sha256(file_body).hexdigest(),
    }

    evidence_path = evidence_root / str(execution_id) / "exec_1" / "http_webhook-post_json-result.json"
    assert json.loads(evidence_path.read_text(encoding="utf-8")) == connector_result

    with temp_db() as session:
        execution = session.query(Execution).filter_by(id=execution_id).one()
        evidence = json.loads(execution.steps_json)[0]["evidence"][-1]
        assert evidence["result"] == expected_summary
        assert evidence["result"] != connector_result

        run_event = session.query(RunEvent).filter_by(event_type=replay.STEP_EVIDENCE_ATTACHED).one()
        payload = json.loads(run_event.payload_json)
        assert payload["evidence"]["result"] == expected_summary


def test_connector_evidence_filename_exhaustion_reports_completed_action_without_retry(
    client, temp_db, api_key, monkeypatch, tmp_path
):
    from api.integrations.connectors import HttpWebhookConnector
    from api.routers import integrations

    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db)
    evidence_root = tmp_path / "evidence"
    monkeypatch.setattr(integrations, "EVIDENCE_ROOT", evidence_root)

    target_dir = evidence_root / str(execution_id) / "exec_1"
    target_dir.mkdir(parents=True)
    base_name = "http_webhook-post_json-result.json"
    (target_dir / base_name).write_bytes(b"occupied")
    stem = Path(base_name).stem
    suffix = Path(base_name).suffix
    for index in range(1, 10000):
        (target_dir / f"{stem}-{index}{suffix}").write_bytes(b"occupied")

    connector_result = {"status_code": 200, "body": {"ok": True}}
    with patch.object(
        HttpWebhookConnector,
        "execute",
        return_value=connector_result,
    ):
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"run_id": execution_id, "node_id": "exec_1", "body": {"event": "x"}},
        )

    assert resp.status_code == 200
    assert resp.json() == connector_result
    assert resp.headers["x-hotwash-action-status"] == "completed"
    assert resp.headers["x-hotwash-evidence-status"] == "failed"
    with temp_db() as session:
        assert json.loads(session.query(Execution).one().steps_json)[0]["evidence"] == []


def test_connector_evidence_file_allocation_is_atomic_under_race(monkeypatch, tmp_path):
    from api.routers import integrations

    original_allocator = integrations._unique_evidence_path
    first_choice = Barrier(2)

    def force_same_initial_choice(target_dir, filename):
        candidate, stored_name = original_allocator(target_dir, filename)
        if stored_name == filename:
            first_choice.wait(timeout=5)
        return candidate, stored_name

    monkeypatch.setattr(integrations, "_unique_evidence_path", force_same_initial_choice)

    def write(body):
        return integrations._write_unique_evidence_file(tmp_path, "result.json", body)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(write, (b"first", b"second")))

    paths = {path for path, _name in results}
    names = {name for _path, name in results}
    assert names == {"result.json", "result-1.json"}
    assert {path.read_bytes() for path in paths} == {b"first", b"second"}


def test_invalid_run_or_node_prevents_action_execution(client, temp_db, api_key):
    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db)

    with patch("api.integrations.connectors.requests.Session") as session_cls:
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"run_id": execution_id, "node_id": "missing", "body": {"event": "x"}},
        )

    assert resp.status_code == 404
    session_cls.assert_not_called()


def test_unsafe_existing_node_id_prevents_action_execution(client, temp_db, api_key):
    _enable_webhook(temp_db)
    execution_id = _create_execution(temp_db, node_id="bad node")

    with patch("api.integrations.connectors.requests.Session") as session_cls:
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"run_id": execution_id, "node_id": "bad node", "body": {"event": "x"}},
        )

    assert resp.status_code == 400
    assert "unsafe node_id" in resp.json()["detail"].lower()
    session_cls.assert_not_called()
