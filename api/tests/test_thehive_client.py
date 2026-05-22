"""Unit tests for TheHiveClient (mocked HTTP)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from api.integrations.clients.thehive import TheHiveClient, TheHiveError


def _mock_response(status_code: int = 200, json_body: dict | list | None = None, text: str = ""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_body if json_body is not None else {}
    resp.text = text or (str(json_body) if json_body else "")
    return resp


def test_client_constructs_with_base_url_and_key():
    client = TheHiveClient(base_url="http://example:9000", api_key="abc123")
    assert client.base_url == "http://example:9000"
    assert client.api_key == "abc123"
    assert client.verify_ssl is True
    assert client.timeout == 10.0


def test_client_strips_trailing_slash_from_base_url():
    client = TheHiveClient(base_url="http://example:9000/", api_key="abc123")
    assert client.base_url == "http://example:9000"


def test_thehive_error_carries_status_and_details():
    err = TheHiveError("nope", status_code=401, details={"type": "AuthenticationError"})
    assert err.status_code == 401
    assert err.details == {"type": "AuthenticationError"}
    assert "nope" in str(err)


def test_request_success_returns_parsed_json():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(200, json_body={"login": "admin"})
        result = client._request("GET", "/api/v1/user/current")
    assert result == {"login": "admin"}
    mocked.assert_called_once()
    args, kwargs = mocked.call_args
    assert args[0] == "GET"
    assert args[1] == "http://example:9000/api/v1/user/current"
    assert kwargs["timeout"] == 10.0
    assert kwargs["verify"] is True


def test_request_passes_json_body_on_post():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(201, json_body={"_id": "abc"})
        client._request("POST", "/api/v1/case", json={"title": "x"})
    _, kwargs = mocked.call_args
    assert kwargs["json"] == {"title": "x"}


def test_request_raises_on_401_with_clear_message():
    client = TheHiveClient(base_url="http://example:9000", api_key="bad")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(401, json_body={"type": "AuthenticationError"})
        with pytest.raises(TheHiveError) as exc:
            client._request("GET", "/api/v1/user/current")
    assert exc.value.status_code == 401
    assert "Invalid API key" in str(exc.value)
    assert exc.value.details == {"type": "AuthenticationError"}


def test_request_raises_on_5xx():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(503, text="upstream blew up")
        with pytest.raises(TheHiveError) as exc:
            client._request("GET", "/api/v1/status")
    assert exc.value.status_code == 503


def test_request_raises_on_connection_error():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request", side_effect=requests.ConnectionError("refused")):
        with pytest.raises(TheHiveError) as exc:
            client._request("GET", "/api/v1/status")
    assert exc.value.status_code is None
    assert "refused" in str(exc.value)


def test_request_handles_non_json_response_body():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    bad_resp = _mock_response(200)
    bad_resp.json.side_effect = ValueError("not json")
    bad_resp.text = "<html>oops</html>"
    with patch.object(client._session, "request", return_value=bad_resp):
        with pytest.raises(TheHiveError) as exc:
            client._request("GET", "/api/v1/status")
    assert "non-json" in str(exc.value).lower() or "invalid json" in str(exc.value).lower()


def test_status_returns_connected_when_auth_ok():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")

    def fake_request(method, url, **_):
        if url.endswith("/api/v1/user/current"):
            return _mock_response(200, json_body={"login": "admin@thehive.local", "name": "admin"})
        if url.endswith("/api/v1/status"):
            return _mock_response(
                200,
                json_body={"versions": {"TheHive": "5.4.0"}, "config": {}},
            )
        return _mock_response(404)

    with patch.object(client._session, "request", side_effect=fake_request):
        result = client.status()
    assert result["status"] == "connected"
    assert result["version"] == "5.4.0"
    assert result["user"] == "admin@thehive.local"


def test_status_handles_missing_version_field():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")

    def fake_request(method, url, **_):
        if url.endswith("/api/v1/user/current"):
            return _mock_response(200, json_body={"login": "admin"})
        if url.endswith("/api/v1/status"):
            return _mock_response(200, json_body={"config": {}})
        return _mock_response(404)

    with patch.object(client._session, "request", side_effect=fake_request):
        result = client.status()
    assert result["status"] == "connected"
    assert result["version"] == "unknown"


def test_status_propagates_auth_error():
    client = TheHiveClient(base_url="http://example:9000", api_key="bad")
    with patch.object(
        client._session,
        "request",
        return_value=_mock_response(401, json_body={"type": "AuthenticationError"}),
    ):
        with pytest.raises(TheHiveError) as exc:
            client.status()
    assert exc.value.status_code == 401
