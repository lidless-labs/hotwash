"""Unit tests for WazuhClient (mocked HTTP)."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
import requests

from api.integrations.clients.wazuh import WazuhClient, WazuhError
from api.security import PinnedURL


def _mock_response(status_code: int = 200, json_body: dict | list | None = None, text: str = ""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = text or (str(json_body) if json_body else "")
    return resp


def test_client_constructs_without_authenticating():
    client = WazuhClient(base_url="https://wazuh.example:55000/", username="alice", password="secret")

    assert client.base_url == "https://wazuh.example:55000"
    assert client.username == "alice"
    assert client.verify_ssl is True
    assert client.timeout == 10.0
    assert client._jwt is None


def test_error_carries_status_and_details_without_secret():
    err = WazuhError("bad", status_code=401, details={"title": "Unauthorized"})

    assert err.status_code == 401
    assert err.details == {"title": "Unauthorized"}
    assert "bad" in str(err)


def test_api_info_authenticates_lazily_and_uses_bearer_token():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client._session, "request") as mocked:
        mocked.side_effect = [
            _mock_response(200, text="jwt-token"),
            _mock_response(200, json_body={"title": "Wazuh API", "api_version": "4.7.2"}),
        ]
        result = client.api_info()

    assert result == {"title": "Wazuh API", "api_version": "4.7.2"}
    assert mocked.call_count == 2
    auth_call = mocked.call_args_list[0]
    assert auth_call.args == ("POST", "https://wazuh.example:55000/security/user/authenticate")
    assert auth_call.kwargs["params"] == {"raw": "true"}
    assert auth_call.kwargs["auth"] == ("alice", "secret")
    assert auth_call.kwargs["allow_redirects"] is False
    info_call = mocked.call_args_list[1]
    assert info_call.args == ("GET", "https://wazuh.example:55000/")
    assert info_call.kwargs["headers"]["Authorization"] == "Bearer jwt-token"
    assert info_call.kwargs["allow_redirects"] is False


def test_request_reauthenticates_once_on_401():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client._session, "request") as mocked:
        mocked.side_effect = [
            _mock_response(200, text="first-token"),
            _mock_response(401, json_body={"title": "Unauthorized"}),
            _mock_response(200, text="second-token"),
            _mock_response(200, json_body={"data": {"affected_items": []}}),
        ]
        result = client.list_agents(status="active")

    assert result == {"data": {"affected_items": []}}
    assert mocked.call_count == 4
    assert mocked.call_args_list[3].kwargs["headers"]["Authorization"] == "Bearer second-token"


def test_request_raises_sanitized_error_after_retry_fails():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client._session, "request") as mocked:
        mocked.side_effect = [
            _mock_response(200, text="first-token"),
            _mock_response(401, json_body={"detail": "bad jwt first-token secret"}),
            _mock_response(200, text="second-token"),
            _mock_response(401, json_body={"detail": "bad jwt first-token second-token secret"}),
        ]
        with pytest.raises(WazuhError) as exc:
            client.api_info()

    assert exc.value.status_code == 401
    assert "secret" not in str(exc.value)
    assert "first-token" not in str(exc.value.details)
    assert "second-token" not in str(exc.value.details)
    assert exc.value.details == {"detail": "bad jwt [redacted] [redacted] [redacted]"}


def test_authentication_failure_raises_wazuh_error_without_password():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(
            401,
            json_body={
                "title": "Unauthorized",
                "secret-key": "secret rejected",
            },
        )
        with pytest.raises(WazuhError) as exc:
            client.api_info()

    assert exc.value.status_code == 401
    assert "secret" not in str(exc.value)
    assert "secret" not in str(exc.value.details)
    assert exc.value.details["[redacted]-key"] == "[redacted] rejected"


def test_authentication_failure_redacts_basic_auth_value():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")
    encoded_credentials = base64.b64encode(b"alice:secret").decode("ascii")

    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(
            401,
            json_body={"detail": f"reflected Authorization: Basic {encoded_credentials}"},
        )
        with pytest.raises(WazuhError) as exc:
            client.api_info()

    assert encoded_credentials not in str(exc.value.details)
    assert exc.value.details == {"detail": "reflected Authorization: Basic [redacted]"}


def test_connection_error_is_mapped_to_wazuh_error():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client._session, "request", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(WazuhError) as exc:
            client.api_info()

    assert exc.value.status_code is None
    assert exc.value.details == {"upstream": "connection_error"}


def test_list_agents_builds_expected_query_params():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client, "_authenticated_request") as mocked:
        mocked.return_value = {"data": {"affected_items": []}}
        client.list_agents(status="active", search="web", limit=25, select="id,name,status")

    mocked.assert_called_once_with(
        "GET",
        "/agents",
        params={"status": "active", "search": "web", "limit": 25, "select": "id,name,status"},
    )


def test_get_agent_uses_agents_list_query_param():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client, "_authenticated_request") as mocked:
        mocked.return_value = {"data": {"affected_items": [{"id": "001"}]}}
        client.get_agent("001")

    mocked.assert_called_once_with("GET", "/agents", params={"agents_list": "001"})


def test_run_active_response_puts_expected_payload():
    client = WazuhClient(base_url="https://wazuh.example:55000", username="alice", password="secret")

    with patch.object(client, "_authenticated_request") as mocked:
        mocked.return_value = {"data": {"affected_items": []}}
        client.run_active_response(
            command="restart-wazuh0",
            agent_ids=["001", "002"],
            arguments=["arg1"],
            alert={"rule": {"id": "5710"}},
        )

    mocked.assert_called_once_with(
        "PUT",
        "/active-response",
        params={"agents_list": "001,002"},
        json={"command": "restart-wazuh0", "arguments": ["arg1"], "alert": {"rule": {"id": "5710"}}},
    )


def test_pinned_url_is_used_for_requests():
    pinned = PinnedURL(
        url="https://93.184.216.34:55000/base",
        hostname="wazuh.example",
        host_header="wazuh.example:55000",
    )
    client = WazuhClient(
        base_url="https://wazuh.example:55000/base",
        username="alice",
        password="secret",
        pinned=pinned,
    )

    assert client.base_url == "https://wazuh.example:55000/base"
    assert client._session.headers["Host"] == "wazuh.example:55000"
    with patch.object(client._session, "request") as mocked:
        mocked.side_effect = [
            _mock_response(200, text="jwt-token"),
            _mock_response(200, json_body={"title": "Wazuh API"}),
        ]
        client.api_info()

    assert mocked.call_args_list[0].args[1] == "https://93.184.216.34:55000/base/security/user/authenticate"
    assert mocked.call_args_list[1].args[1] == "https://93.184.216.34:55000/base/"
