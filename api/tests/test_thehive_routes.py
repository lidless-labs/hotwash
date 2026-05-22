"""Tests for /api/integrations/thehive/* routes."""

from __future__ import annotations

from unittest.mock import patch

from api.integrations.clients.thehive import TheHiveError


def test_test_endpoint_mock_mode_uses_mock_data(client, temp_db, api_key):
    resp = client.post(
        "/api/integrations/thehive/test", headers={"X-API-Key": api_key}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mock_mode"] is True
    assert body["result"]["status"] == "connected"


def test_test_endpoint_live_mode_calls_thehive_client(client, configured_thehive, api_key):
    fake_status = {
        "status": "connected",
        "version": "5.4.0",
        "user": "admin@thehive.local",
        "stats": {},
    }
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.status.return_value = fake_status
        resp = client.post(
            "/api/integrations/thehive/test",
            headers={"X-API-Key": api_key},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mock_mode"] is False
    assert body["result"] == fake_status
    MockClient.assert_called_once()


def test_test_endpoint_live_mode_maps_thehive_error_to_502(client, configured_thehive, api_key):
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.status.side_effect = TheHiveError(
            "Invalid API key for TheHive", status_code=401, details={}
        )
        resp = client.post(
            "/api/integrations/thehive/test",
            headers={"X-API-Key": api_key},
        )
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert "Invalid API key" in detail["message"]
    assert detail["upstream_status"] == 401


def test_test_endpoint_rejects_without_api_key(client):
    resp = client.post("/api/integrations/thehive/test")
    assert resp.status_code in (401, 403)


def _call_action(client, api_key, verb, payload):
    return client.post(
        f"/api/integrations/thehive/actions/{verb}",
        headers={"X-API-Key": api_key},
        json=payload,
    )


def test_create_case_action_happy_path(client, configured_thehive, api_key):
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.create_case.return_value = {
            "_id": "~123",
            "number": 42,
            "title": "x",
        }
        resp = _call_action(
            client,
            api_key,
            "create_case",
            {"title": "x", "description": "y", "severity": 3, "tags": ["t"]},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["case_id"] == "~123"
    assert body["number"] == 42
    MockClient.return_value.create_case.assert_called_once_with(
        title="x", description="y", severity=3, tlp=2, pap=2, tags=["t"]
    )


def test_create_case_rejects_when_disabled(client, temp_db, api_key):
    resp = _call_action(
        client, api_key, "create_case", {"title": "x", "description": "y"}
    )
    assert resp.status_code == 400
    assert "disabled" in resp.json()["detail"].lower()


def test_create_case_rejects_when_mock_mode(client, temp_db, api_key):
    from api.integrations.config import Integration
    with temp_db() as session:
        i = session.query(Integration).filter_by(tool_name="thehive").first()
        i.enabled = True
        i.mock_mode = True
        i.base_url = "http://example:9000"
        session.commit()
    resp = _call_action(
        client, api_key, "create_case", {"title": "x", "description": "y"}
    )
    assert resp.status_code == 400
    assert "mock" in resp.json()["detail"].lower()


def test_create_case_rejects_when_no_api_key_configured(client, temp_db, api_key):
    from api.integrations.config import Integration
    with temp_db() as session:
        i = session.query(Integration).filter_by(tool_name="thehive").first()
        i.enabled = True
        i.mock_mode = False
        i.base_url = "http://example:9000"
        i.api_key = ""
        session.commit()
    resp = _call_action(
        client, api_key, "create_case", {"title": "x", "description": "y"}
    )
    assert resp.status_code == 400
    assert "api key" in resp.json()["detail"].lower()


def test_create_case_maps_upstream_401_to_502(client, configured_thehive, api_key):
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.create_case.side_effect = TheHiveError(
            "Invalid API key for TheHive", status_code=401, details={}
        )
        resp = _call_action(
            client, api_key, "create_case", {"title": "x", "description": "y"}
        )
    assert resp.status_code == 502
    assert resp.json()["detail"]["upstream_status"] == 401


def test_create_alert_action_happy_path(client, configured_thehive, api_key):
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.create_alert.return_value = {
            "_id": "~A1",
            "sourceRef": "wazuh-1",
        }
        resp = _call_action(
            client,
            api_key,
            "create_alert",
            {
                "type": "vulnerability",
                "source": "wazuh",
                "source_ref": "wazuh-1",
                "title": "x",
                "description": "y",
                "observables": [{"dataType": "ip", "data": "1.2.3.4"}],
            },
        )
    assert resp.status_code == 200
    assert resp.json()["alert_id"] == "~A1"
    MockClient.return_value.create_alert.assert_called_once_with(
        type="vulnerability",
        source="wazuh",
        source_ref="wazuh-1",
        title="x",
        description="y",
        severity=2,
        tlp=2,
        pap=2,
        observables=[{"dataType": "ip", "data": "1.2.3.4"}],
        tags=[],
    )


def test_add_observable_action_happy_path(client, configured_thehive, api_key):
    with patch("api.routers.integrations.validate_integration_url", return_value=None), \
         patch("api.routers.integrations.TheHiveClient") as MockClient:
        MockClient.return_value.add_observable.return_value = {"_id": "~O1"}
        resp = _call_action(
            client,
            api_key,
            "add_observable",
            {
                "case_id": "~123",
                "data_type": "ip",
                "data": "1.2.3.4",
                "ioc": True,
            },
        )
    assert resp.status_code == 200
    assert resp.json()["observable_id"] == "~O1"
    MockClient.return_value.add_observable.assert_called_once_with(
        case_id="~123",
        data_type="ip",
        data="1.2.3.4",
        message=None,
        tlp=2,
        ioc=True,
        sighted=False,
        tags=[],
    )


def test_action_payload_validation_422(client, configured_thehive, api_key):
    resp = _call_action(client, api_key, "create_case", {"description": "y"})
    assert resp.status_code == 422
