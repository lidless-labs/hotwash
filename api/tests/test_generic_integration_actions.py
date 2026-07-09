"""Tests for generic integration action endpoints."""

from __future__ import annotations

import json
from unittest.mock import patch

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
        assert session.query(ExecutionEvent).filter_by(event_type="evidence_attached").count() == 1
        assert session.query(RunEvent).filter_by(event_type=replay.STEP_EVIDENCE_ATTACHED).count() == 1


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
