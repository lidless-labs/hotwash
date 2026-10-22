"""Scope, confirmation, gating and bounding behavior enforced by the API itself."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests
from starlette.websockets import WebSocketDisconnect

from api.integrations.clients.bounded import (
    UpstreamResponseTooLarge,
    max_upstream_bytes,
    read_bounded,
)
from api.security import PinnedURL
from api.tests.test_execution_hardening import _create_execution
from api.tests.test_generic_integration_actions import _enable_wazuh

AR_URL = "/api/integrations/wazuh/actions/run_active_response"
AR_BODY = {"command": "firewall-drop", "agent_ids": ["001"], "confirm": True}


def _pinned():
    return PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None)


# --- Wazuh active response -------------------------------------------------


@pytest.mark.parametrize("value", [None, "", "  ", " , "])
def test_active_response_is_disabled_without_an_allowlist(client, temp_db, api_key, monkeypatch, value):
    if value is None:
        monkeypatch.delenv("HOTWASH_WAZUH_AR_COMMANDS", raising=False)
    else:
        monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", value)
    _enable_wazuh(temp_db)

    with patch("api.integrations.connectors.resolve_and_pin_integration_url", return_value=_pinned()), patch(
        "api.integrations.connectors.WazuhClient"
    ) as MockClient:
        resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json=AR_BODY)

    assert resp.status_code == 403
    assert "HOTWASH_WAZUH_AR_COMMANDS" in resp.json()["detail"]
    MockClient.return_value.run_active_response.assert_not_called()


@pytest.mark.parametrize("confirm", [None, False, "yes", 1])
def test_active_response_requires_literal_confirm(client, temp_db, api_key, monkeypatch, confirm):
    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop")
    _enable_wazuh(temp_db)
    body = {key: value for key, value in AR_BODY.items() if key != "confirm"}
    if confirm is not None:
        body["confirm"] = confirm

    with patch("api.integrations.connectors.resolve_and_pin_integration_url", return_value=_pinned()), patch(
        "api.integrations.connectors.WazuhClient"
    ) as MockClient:
        resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json=body)

    assert resp.status_code == 422
    MockClient.return_value.run_active_response.assert_not_called()


def test_active_response_dry_run_never_contacts_wazuh(client, temp_db, api_key, monkeypatch):
    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop")
    _enable_wazuh(temp_db)

    with patch("api.integrations.connectors.resolve_and_pin_integration_url", return_value=_pinned()) as pin, patch(
        "api.integrations.connectors.WazuhClient"
    ) as MockClient:
        resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json={**AR_BODY, "dry_run": True})

    assert resp.status_code == 200
    assert resp.json()["dry_run"] is True
    assert resp.json()["would_run"] == {
        "command": "firewall-drop",
        "agent_ids": ["001"],
        "arguments": [],
        "alert": {},
    }
    MockClient.assert_not_called()
    pin.assert_not_called()


def test_active_response_dry_run_includes_the_alert(client, temp_db, api_key, monkeypatch):
    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop")
    _enable_wazuh(temp_db)
    alert = {"rule": {"id": "5710"}}

    resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json={**AR_BODY, "dry_run": True, "alert": alert})

    assert resp.status_code == 200
    assert resp.json()["would_run"]["alert"] == alert


def test_active_response_dry_run_still_enforces_the_allowlist(client, temp_db, api_key, monkeypatch):
    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "host-deny")
    _enable_wazuh(temp_db)

    resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json={**AR_BODY, "dry_run": True})

    assert resp.status_code == 422


def test_active_response_dry_run_reports_the_request_in_mock_mode(client, temp_db, api_key, monkeypatch):
    # Mock mode never reaches a manager, so it needs no allow-list; a dry run
    # still reports the request instead of returning the canned result.
    monkeypatch.delenv("HOTWASH_WAZUH_AR_COMMANDS", raising=False)
    _enable_wazuh(temp_db, mock_mode=True)

    resp = client.post(AR_URL, headers={"X-API-Key": api_key}, json={**AR_BODY, "dry_run": True})

    assert resp.status_code == 200
    assert resp.json()["dry_run"] is True
    assert resp.json()["would_run"]["command"] == "firewall-drop"


# --- Key scopes and read-only mode -----------------------------------------


@pytest.fixture
def read_key(monkeypatch):
    monkeypatch.setenv("HOTWASH_READ_ONLY_API_KEY", "read-only-key-456")
    return "read-only-key-456"


def test_read_only_key_can_read_but_not_change(client, temp_db, api_key, read_key):
    execution_id = _create_execution(temp_db)
    headers = {"X-API-Key": read_key}

    assert client.get("/api/executions", headers=headers).status_code == 200
    assert client.get(f"/api/executions/{execution_id}", headers=headers).status_code == 200

    patched = client.patch(f"/api/executions/{execution_id}", headers=headers, json={"notes": "x"})
    assert patched.status_code == 403
    deleted = client.delete(f"/api/executions/{execution_id}?confirm=true", headers=headers)
    assert deleted.status_code == 403
    created = client.post("/api/executions", headers=headers, json={"playbook_id": 1, "incident_title": "t"})
    assert created.status_code == 403
    assert client.delete("/api/playbooks/1", headers=headers).status_code == 403
    assert client.get(f"/api/executions/{execution_id}", headers={"X-API-Key": api_key}).status_code == 200


def test_read_only_key_cannot_trigger_integration_actions(client, temp_db, api_key, read_key, monkeypatch):
    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop")
    _enable_wazuh(temp_db)

    with patch("api.integrations.connectors.WazuhClient") as MockClient:
        resp = client.post(AR_URL, headers={"X-API-Key": read_key}, json=AR_BODY)

    assert resp.status_code == 403
    MockClient.assert_not_called()


def test_write_key_keeps_write_scope_when_a_read_key_is_configured(client, temp_db, api_key, read_key):
    execution_id = _create_execution(temp_db)

    resp = client.patch(f"/api/executions/{execution_id}", headers={"X-API-Key": api_key}, json={"notes": "n"})

    assert resp.status_code == 200


def test_read_key_equal_to_write_key_is_ignored(client, temp_db, api_key, monkeypatch):
    monkeypatch.setenv("HOTWASH_READ_ONLY_API_KEY", api_key)
    execution_id = _create_execution(temp_db)

    resp = client.patch(f"/api/executions/{execution_id}", headers={"X-API-Key": api_key}, json={"notes": "n"})

    assert resp.status_code == 200


@pytest.mark.parametrize("flag", ["1", "true", "TRUE", "yes", "on"])
def test_global_read_only_mode_limits_every_key(client, temp_db, api_key, monkeypatch, flag):
    monkeypatch.setenv("HOTWASH_READ_ONLY", flag)
    execution_id = _create_execution(temp_db)
    headers = {"X-API-Key": api_key}

    assert client.get(f"/api/executions/{execution_id}", headers=headers).status_code == 200
    assert client.patch(f"/api/executions/{execution_id}", headers=headers, json={"notes": "n"}).status_code == 403
    assert client.delete(f"/api/executions/{execution_id}?confirm=true", headers=headers).status_code == 403


def test_global_read_only_mode_is_off_by_default(client, temp_db, api_key, monkeypatch):
    monkeypatch.delenv("HOTWASH_READ_ONLY", raising=False)
    execution_id = _create_execution(temp_db)

    resp = client.patch(f"/api/executions/{execution_id}", headers={"X-API-Key": api_key}, json={"notes": "n"})

    assert resp.status_code == 200


def test_invalid_and_non_ascii_keys_are_rejected_cleanly(client, temp_db, api_key):
    assert client.get("/api/executions").status_code == 401
    assert client.get("/api/executions", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/executions", headers={"X-API-Key": "café".encode("latin-1")}).status_code == 401


# --- Confirmation at the REST boundary --------------------------------------


def test_abandoning_an_execution_requires_confirm(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)
    headers = {"X-API-Key": api_key}
    url = f"/api/executions/{execution_id}"

    assert client.patch(url, headers=headers, json={"status": "abandoned"}).status_code == 422
    assert client.patch(url, headers=headers, json={"status": "abandoned", "confirm": False}).status_code == 422
    assert client.get(url, headers=headers).json()["execution"]["status"] == "completed"

    confirmed = client.patch(url, headers=headers, json={"status": "abandoned", "confirm": True})
    assert confirmed.status_code == 200
    assert confirmed.json()["status"] == "abandoned"


def test_other_status_changes_do_not_need_confirm(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)

    resp = client.patch(
        f"/api/executions/{execution_id}", headers={"X-API-Key": api_key}, json={"status": "paused"}
    )

    assert resp.status_code == 200


def test_deleting_an_execution_requires_confirm(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)
    headers = {"X-API-Key": api_key}
    url = f"/api/executions/{execution_id}"

    assert client.delete(url, headers=headers).status_code == 422
    assert client.delete(f"{url}?confirm=false", headers=headers).status_code == 422
    assert client.get(url, headers=headers).status_code == 200

    assert client.delete(f"{url}?confirm=true", headers=headers).status_code == 204
    assert client.get(url, headers=headers).status_code == 404


@pytest.mark.parametrize("action", ["accept", "dismiss"])
def test_suggestion_transitions_require_confirm_before_lookup(client, api_key, action):
    headers = {"X-API-Key": api_key}
    url = f"/api/ingest/suggestions/999/{action}"

    assert client.post(url, headers=headers).status_code == 422
    assert client.post(f"{url}?confirm=false", headers=headers).status_code == 422
    # Once confirmed the request proceeds to the lookup, which reports the missing row.
    assert client.post(f"{url}?confirm=true", headers=headers).status_code == 404


# --- Live socket tickets ----------------------------------------------------


def test_live_ticket_is_bound_to_one_execution(client, temp_db, api_key):
    first = _create_execution(temp_db)
    second = _create_execution(temp_db)
    ticket = client.post(f"/api/executions/{first}/live-ticket", headers={"X-API-Key": api_key}).json()["ticket"]

    with client.websocket_connect(f"/api/executions/{first}/live?ticket={ticket}") as socket:
        socket.send_text("ping")
    with pytest.raises(WebSocketDisconnect) as other:
        with client.websocket_connect(f"/api/executions/{second}/live?ticket={ticket}"):
            pass
    assert other.value.code == 4401


def test_live_ticket_requires_a_valid_key_and_a_real_execution(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)

    assert client.post(f"/api/executions/{execution_id}/live-ticket").status_code == 401
    assert client.post("/api/executions/9999/live-ticket", headers={"X-API-Key": api_key}).status_code == 404


def test_read_only_key_can_open_the_live_socket(client, temp_db, api_key, read_key):
    execution_id = _create_execution(temp_db)

    minted = client.post(f"/api/executions/{execution_id}/live-ticket", headers={"X-API-Key": read_key})
    assert minted.status_code == 200
    with client.websocket_connect(f"/api/executions/{execution_id}/live?ticket={minted.json()['ticket']}") as socket:
        socket.send_text("ping")


def test_live_ticket_expires_and_rejects_tampering(api_key):
    from api import auth

    ticket, ttl = auth.issue_ws_ticket(7, now=1000.0)

    assert ttl == auth.WS_TICKET_TTL_SECONDS
    assert auth.verify_ws_ticket(ticket, 7, now=1000.0 + ttl)
    assert not auth.verify_ws_ticket(ticket, 7, now=1000.0 + ttl + 1)
    assert not auth.verify_ws_ticket(ticket, 8, now=1000.0)
    purpose, execution_id, expires, signature = ticket.split(".")
    assert not auth.verify_ws_ticket(f"{purpose}.{execution_id}.{int(expires) + 600}.{signature}", 7, now=1000.0)
    assert not auth.verify_ws_ticket(f"other.{execution_id}.{expires}.{signature}", 7, now=1000.0)
    assert not auth.verify_ws_ticket("", 7)
    assert not auth.verify_ws_ticket("not-a-ticket", 7)
    assert not auth.verify_ws_ticket("a.b.c.é", 7)


def test_live_ticket_does_not_authenticate_rest_routes(client, temp_db, api_key):
    execution_id = _create_execution(temp_db)
    ticket = client.post(f"/api/executions/{execution_id}/live-ticket", headers={"X-API-Key": api_key}).json()["ticket"]

    assert client.get(f"/api/executions/{execution_id}", headers={"X-API-Key": ticket}).status_code == 401


# --- Bounded upstream reads -------------------------------------------------


def _streaming_response(chunks: list[bytes], headers: dict | None = None):
    response = requests.Response()
    response.status_code = 200
    response.headers.update(headers or {})
    response.iter_content = lambda chunk_size=1: iter(chunks)  # type: ignore[method-assign]
    response.close = MagicMock()  # type: ignore[method-assign]
    return response


def test_read_bounded_buffers_a_small_body_for_parsing():
    response = read_bounded(_streaming_response([b'{"ok":', b" true}"]), limit=64)

    assert response.json() == {"ok": True}
    assert response.text == '{"ok": true}'


def test_read_bounded_stops_an_oversized_stream():
    response = _streaming_response([b"x" * 40, b"x" * 40])

    with pytest.raises(UpstreamResponseTooLarge):
        read_bounded(response, limit=64)
    response.close.assert_called_once()


def test_read_bounded_rejects_a_declared_oversize_without_reading():
    response = _streaming_response([b"never read"], headers={"Content-Length": "100"})
    response.iter_content = MagicMock(side_effect=AssertionError("body must not be read"))

    with pytest.raises(UpstreamResponseTooLarge):
        read_bounded(response, limit=64)


def test_upstream_limit_is_configurable(monkeypatch):
    monkeypatch.setenv("HOTWASH_MAX_UPSTREAM_BYTES", "1024")
    assert max_upstream_bytes() == 1024
    monkeypatch.setenv("HOTWASH_MAX_UPSTREAM_BYTES", "bogus")
    assert max_upstream_bytes() == 5 * 1024 * 1024


def test_thehive_client_reports_an_oversized_response():
    from api.integrations.clients.thehive import TheHiveClient, TheHiveError

    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request", return_value=_streaming_response([b"x" * 200])), patch.dict(
        "os.environ", {"HOTWASH_MAX_UPSTREAM_BYTES": "100"}
    ):
        with pytest.raises(TheHiveError) as exc:
            client._request("GET", "/api/v1/user/current")

    assert exc.value.details["upstream"] == "response_too_large"


def test_wazuh_client_reports_an_oversized_response():
    from api.integrations.clients.wazuh import WazuhClient, WazuhError

    client = WazuhClient(base_url="https://wazuh.example:55000", username="a", password="b")
    client._jwt = "token"
    with patch.object(client._session, "request", return_value=_streaming_response([b"x" * 200])), patch.dict(
        "os.environ", {"HOTWASH_MAX_UPSTREAM_BYTES": "100"}
    ):
        with pytest.raises(WazuhError) as exc:
            client._request("GET", "/agents")

    assert exc.value.details["upstream"] == "response_too_large"


def test_webhook_connector_reports_an_oversized_response(client, temp_db, api_key):
    from api.tests.test_generic_integration_actions import _enable_webhook

    _enable_webhook(temp_db)
    session = MagicMock()
    session.headers = {}
    session.post.return_value = _streaming_response([b"x" * 200])

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34/base", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.requests.Session", return_value=session), patch.dict(
        "os.environ", {"HOTWASH_MAX_UPSTREAM_BYTES": "100"}
    ):
        resp = client.post(
            "/api/integrations/http_webhook/actions/post_json",
            headers={"X-API-Key": api_key},
            json={"body": {"event": "x"}},
        )

    assert resp.status_code == 502
    assert "size limit" in str(resp.json())
