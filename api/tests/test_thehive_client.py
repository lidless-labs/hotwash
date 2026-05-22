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


def test_create_case_posts_expected_payload():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(
            201,
            json_body={"_id": "~123", "number": 42, "title": "ransomware"},
        )
        result = client.create_case(
            title="ransomware",
            description="machine encrypted",
            severity=3,
            tlp=2,
            pap=2,
            tags=["wazuh", "ransom"],
        )
    args, kwargs = mocked.call_args
    assert args[0] == "POST"
    assert args[1] == "http://example:9000/api/v1/case"
    assert kwargs["json"] == {
        "title": "ransomware",
        "description": "machine encrypted",
        "severity": 3,
        "tlp": 2,
        "pap": 2,
        "tags": ["wazuh", "ransom"],
    }
    assert result["_id"] == "~123"
    assert result["number"] == 42


def test_create_case_defaults_severity_tlp_pap():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(201, json_body={"_id": "~1"})
        client.create_case(title="x", description="y")
    _, kwargs = mocked.call_args
    assert kwargs["json"]["severity"] == 2
    assert kwargs["json"]["tlp"] == 2
    assert kwargs["json"]["pap"] == 2
    assert "tags" not in kwargs["json"] or kwargs["json"]["tags"] == []


def test_create_alert_posts_expected_payload():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(
            201,
            json_body={"_id": "~A1", "sourceRef": "wazuh-23505-1"},
        )
        result = client.create_alert(
            type="vulnerability",
            source="wazuh",
            source_ref="wazuh-23505-1",
            title="CVE-2024-1234",
            description="patch needed",
            severity=2,
            observables=[{"dataType": "hostname", "data": "host01"}],
            tags=["cve"],
        )
    args, kwargs = mocked.call_args
    assert args[1] == "http://example:9000/api/v1/alert"
    body = kwargs["json"]
    assert body["type"] == "vulnerability"
    assert body["source"] == "wazuh"
    assert body["sourceRef"] == "wazuh-23505-1"
    assert body["title"] == "CVE-2024-1234"
    assert body["observables"] == [{"dataType": "hostname", "data": "host01"}]
    assert result["_id"] == "~A1"


def test_create_alert_without_observables_omits_field():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(201, json_body={"_id": "~A2"})
        client.create_alert(
            type="t", source="s", source_ref="r", title="x", description="y"
        )
    body = mocked.call_args[1]["json"]
    assert "observables" not in body


def test_add_observable_posts_to_case_observable_endpoint():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(201, json_body={"_id": "~O1"})
        result = client.add_observable(
            case_id="~123",
            data_type="ip",
            data="1.2.3.4",
            message="C2 server",
            tlp=3,
            ioc=True,
            sighted=True,
            tags=["c2"],
        )
    args, kwargs = mocked.call_args
    assert args[1] == "http://example:9000/api/v1/case/~123/observable"
    body = kwargs["json"]
    assert body["dataType"] == "ip"
    assert body["data"] == "1.2.3.4"
    assert body["message"] == "C2 server"
    assert body["tlp"] == 3
    assert body["ioc"] is True
    assert body["sighted"] is True
    assert body["tags"] == ["c2"]
    assert result["_id"] == "~O1"


def test_add_observable_defaults():
    client = TheHiveClient(base_url="http://example:9000", api_key="k")
    with patch.object(client._session, "request") as mocked:
        mocked.return_value = _mock_response(201, json_body={"_id": "~O2"})
        client.add_observable(case_id="~123", data_type="domain", data="evil.com")
    body = mocked.call_args[1]["json"]
    assert body["dataType"] == "domain"
    assert body["data"] == "evil.com"
    assert body["tlp"] == 2
    assert body["ioc"] is False
    assert body["sighted"] is False
    assert "message" not in body
    assert "tags" not in body
