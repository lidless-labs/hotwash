"""Tests for integration connector registry and HTTP webhook connector."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.crypto import encrypt_secret
from api.security import PinnedURL


def _webhook_integration(temp_db, *, mock_mode: bool = False, api_key: str = ""):
    from api.integrations.config import Integration

    with temp_db() as session:
        integration = session.query(Integration).filter_by(tool_name="http_webhook").first()
        integration.base_url = "https://webhook.example/base"
        integration.enabled = True
        integration.mock_mode = mock_mode
        integration.verify_ssl = False
        integration.api_key = encrypt_secret(api_key) if api_key else ""
        session.commit()
        session.refresh(integration)
        session.expunge(integration)
        return integration


def _wazuh_integration(
    temp_db,
    *,
    base_url: str = "https://wazuh.example:55000",
    username: str = "alice",
    password: str = "secret",
):
    from api.integrations.config import Integration

    with temp_db() as session:
        integration = session.query(Integration).filter_by(tool_name="wazuh").first()
        integration.base_url = base_url
        integration.username = username
        integration.password = encrypt_secret(password) if password else ""
        integration.enabled = True
        integration.mock_mode = False
        integration.verify_ssl = False
        session.commit()
        session.refresh(integration)
        session.expunge(integration)
        return integration


def test_registry_lists_registered_connectors():
    from api.integrations.connectors import get_connector, registered_tool_names

    assert registered_tool_names() == ["http_webhook", "thehive", "wazuh"]
    assert get_connector("thehive").tool_name == "thehive"
    assert get_connector("http_webhook").tool_name == "http_webhook"
    assert get_connector("wazuh").tool_name == "wazuh"
    assert get_connector("missing") is None


def test_connectors_declare_pydantic_action_schemas():
    from pydantic import BaseModel

    from api.integrations.connectors import get_connector

    actions = get_connector("http_webhook").actions()
    assert set(actions) == {"post_json"}
    assert issubclass(actions["post_json"], BaseModel)
    assert "body" in actions["post_json"].model_json_schema()["properties"]

    wazuh_actions = get_connector("wazuh").actions()
    assert set(wazuh_actions) == {"get_agent", "get_agents", "run_active_response"}
    assert issubclass(wazuh_actions["get_agents"], BaseModel)
    assert wazuh_actions["get_agent"].model_json_schema()["additionalProperties"] is False


def test_http_webhook_posts_json_to_pinned_url(temp_db):
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    integration = _webhook_integration(temp_db)
    response = MagicMock()
    response.status_code = 202
    response.json.return_value = {"accepted": True}
    response.text = '{"accepted": true}'
    session = MagicMock()
    session.post.return_value = response

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(
            url="https://93.184.216.34/base/notify",
            hostname="webhook.example",
            host_header="webhook.example",
        ),
    ) as resolve, patch(
        "api.integrations.connectors.requests.Session",
        return_value=session,
    ), patch(
        "api.integrations.connectors.apply_host_pinning"
    ) as apply_pinning:
        result = get_connector("http_webhook").execute(
            "post_json",
            HttpWebhookPostJsonRequest(path="/notify", body={"event": "x"}),
            integration,
        )

    assert result == {"status_code": 202, "body": {"accepted": True}}
    resolve.assert_called_once_with("https://webhook.example/base/notify")
    apply_pinning.assert_called_once()
    session.post.assert_called_once_with(
        "https://93.184.216.34/base/notify",
        json={"event": "x"},
        timeout=10.0,
        verify=False,
        allow_redirects=False,
    )


def test_http_webhook_rejects_ssrf_before_request(temp_db):
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    integration = _webhook_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        side_effect=HTTPException(status_code=422, detail="blocked"),
    ), patch("api.integrations.connectors.requests.Session") as session_cls:
        with pytest.raises(HTTPException) as exc:
            get_connector("http_webhook").execute(
                "post_json",
                HttpWebhookPostJsonRequest(path="/notify", body={"event": "x"}),
                integration,
            )

    assert exc.value.status_code == 422
    session_cls.assert_not_called()


def test_http_webhook_sends_bearer_header_when_api_key_configured(temp_db):
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    integration = _webhook_integration(temp_db, api_key="secret-token")
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"ok": True}
    session = MagicMock()
    session.headers = {}
    session.post.return_value = response

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34/base", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.requests.Session", return_value=session):
        get_connector("http_webhook").execute(
            "post_json",
            HttpWebhookPostJsonRequest(body={"event": "x"}),
            integration,
        )

    assert session.headers["Authorization"] == "Bearer secret-token"


def test_http_webhook_truncates_text_response_to_4kb(temp_db):
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    integration = _webhook_integration(temp_db)
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("not json")
    response.text = "x" * 5000
    session = MagicMock()
    session.post.return_value = response

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34/base", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.requests.Session", return_value=session):
        result = get_connector("http_webhook").execute(
            "post_json",
            HttpWebhookPostJsonRequest(body={"event": "x"}),
            integration,
        )

    assert result["status_code"] == 200
    assert result["body"] == "x" * 4096


def test_wazuh_get_agents_action_builds_client_and_returns_summary(temp_db):
    from api.integrations.connectors import WazuhGetAgentsRequest, get_connector

    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ) as resolve, patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.list_agents.return_value = {
            "data": {
                "affected_items": [{"id": "001", "name": "web01"}],
                "total_affected_items": 1,
            }
        }
        result = get_connector("wazuh").execute(
            "get_agents",
            WazuhGetAgentsRequest(status="active", search="web", limit=10, select="id,name"),
            integration,
        )

    assert result == {
        "agents": [{"id": "001", "name": "web01"}],
        "total": 1,
        "raw": {"data": {"affected_items": [{"id": "001", "name": "web01"}], "total_affected_items": 1}},
    }
    resolve.assert_called_once_with("https://wazuh.example:55000")
    MockClient.assert_called_once_with(
        base_url="https://wazuh.example:55000",
        username="alice",
        password="secret",
        verify_ssl=False,
        pinned=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    )
    MockClient.return_value.list_agents.assert_called_once_with(
        status="active",
        search="web",
        limit=10,
        select="id,name",
    )


def test_wazuh_test_connection_rejects_non_object_api_info(temp_db):
    from api.integrations.clients.wazuh import WazuhError
    from api.integrations.connectors import get_connector

    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.api_info.return_value = []
        with pytest.raises(WazuhError, match="object"):
            get_connector("wazuh").test_connection(integration)


def test_wazuh_get_agent_rejects_non_digit_agent_id():
    from api.integrations.connectors import WazuhGetAgentRequest

    with pytest.raises(ValueError):
        WazuhGetAgentRequest(agent_id="agent-001")


def test_wazuh_active_response_requires_digit_agent_ids():
    from api.integrations.connectors import WazuhRunActiveResponseRequest

    with pytest.raises(ValueError):
        WazuhRunActiveResponseRequest(command="restart-wazuh0", agent_ids=["001", "bad"])


@pytest.mark.parametrize(
    "payload",
    [
        {"agent_ids": ["٠٠١"]},
        {"agent_ids": [f"{index:03d}" for index in range(101)]},
        {"agent_ids": ["001"], "arguments": ["x"] * 33},
        {"agent_ids": ["001"], "arguments": ["x" * 1025]},
        {"agent_ids": ["001"], "alert": {"blob": "x" * 65536}},
    ],
)
def test_wazuh_active_response_bounds_destructive_payload(payload):
    from api.integrations.connectors import WazuhRunActiveResponseRequest

    with pytest.raises(ValueError):
        WazuhRunActiveResponseRequest(command="restart-wazuh0", **payload)


def test_wazuh_active_response_action_returns_summary(temp_db):
    from api.integrations.connectors import WazuhRunActiveResponseRequest, get_connector

    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.run_active_response.return_value = {
            "data": {"affected_items": [{"id": "001"}], "total_affected_items": 1}
        }
        result = get_connector("wazuh").execute(
            "run_active_response",
            WazuhRunActiveResponseRequest(
                command="restart-wazuh0",
                agent_ids=["001"],
                arguments=["arg1"],
                alert={"rule": {"id": "5710"}},
            ),
            integration,
        )

    assert result["affected_agents"] == [{"id": "001"}]
    assert result["total"] == 1
    assert result["raw"]["data"]["total_affected_items"] == 1
    MockClient.return_value.run_active_response.assert_called_once_with(
        command="restart-wazuh0",
        agent_ids=["001"],
        arguments=["arg1"],
        alert={"rule": {"id": "5710"}},
    )


def test_wazuh_missing_credentials_raise_400(temp_db):
    from api.integrations.connectors import WazuhGetAgentsRequest, get_connector

    for field, detail_fragment in (
        ("base_url", "base_url"),
        ("username", "username"),
        ("password", "password"),
    ):
        integration = _wazuh_integration(temp_db)
        setattr(integration, field, "")
        with pytest.raises(HTTPException) as exc:
            get_connector("wazuh").execute("get_agents", WazuhGetAgentsRequest(), integration)
        assert exc.value.status_code == 400
        assert detail_fragment in exc.value.detail.lower()


def test_wazuh_rejects_ssrf_before_request(temp_db):
    from api.integrations.connectors import WazuhGetAgentsRequest, get_connector

    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        side_effect=HTTPException(status_code=422, detail="blocked"),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        with pytest.raises(HTTPException) as exc:
            get_connector("wazuh").execute("get_agents", WazuhGetAgentsRequest(), integration)

    assert exc.value.status_code == 422
    MockClient.assert_not_called()


def test_wazuh_active_response_rejects_command_not_in_allowlist(temp_db, monkeypatch):
    from api.integrations.connectors import WazuhRunActiveResponseRequest, get_connector

    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop,host-deny")
    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        with pytest.raises(HTTPException) as exc:
            get_connector("wazuh").execute(
                "run_active_response",
                WazuhRunActiveResponseRequest(command="rm-everything", agent_ids=["001"]),
                integration,
            )

    assert exc.value.status_code == 422
    MockClient.return_value.run_active_response.assert_not_called()


def test_wazuh_active_response_allows_command_in_allowlist(temp_db, monkeypatch):
    from api.integrations.connectors import WazuhRunActiveResponseRequest, get_connector

    monkeypatch.setenv("HOTWASH_WAZUH_AR_COMMANDS", "firewall-drop")
    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.run_active_response.return_value = {
            "data": {"affected_items": [{"id": "001"}], "total_affected_items": 1}
        }
        result = get_connector("wazuh").execute(
            "run_active_response",
            WazuhRunActiveResponseRequest(command="firewall-drop", agent_ids=["001"]),
            integration,
        )

    assert result["total"] == 1
    MockClient.return_value.run_active_response.assert_called_once()


def test_wazuh_active_response_surfaces_failed_items(temp_db, monkeypatch):
    from api.integrations.connectors import WazuhRunActiveResponseRequest, get_connector

    monkeypatch.delenv("HOTWASH_WAZUH_AR_COMMANDS", raising=False)
    integration = _wazuh_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34:55000", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.WazuhClient") as MockClient:
        MockClient.return_value.run_active_response.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0,
                "failed_items": [{"id": "001", "error": {"message": "agent not active"}}],
                "total_failed_items": 1,
            }
        }
        result = get_connector("wazuh").execute(
            "run_active_response",
            WazuhRunActiveResponseRequest(command="firewall-drop", agent_ids=["001"]),
            integration,
        )

    assert result["affected_agents"] == []
    assert result["total"] == 0
    assert result["total_failed"] == 1
    assert result["failed"] == [{"id": "001", "error": {"message": "agent not active"}}]


@pytest.mark.parametrize(
    "path",
    [
        "../../admin",
        "..%2f..%2fadmin",
        "..\\admin",
        "%252e%252e/admin",
    ],
)
def test_http_webhook_rejects_path_traversal(temp_db, path):
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    integration = _webhook_integration(temp_db)
    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url"
    ) as resolve, patch("api.integrations.connectors.requests.Session") as session_cls:
        with pytest.raises(HTTPException) as exc:
            get_connector("http_webhook").execute(
                "post_json",
                HttpWebhookPostJsonRequest(path=path, body={}),
                integration,
            )

    assert exc.value.status_code == 422
    resolve.assert_not_called()
    session_cls.assert_not_called()


def test_http_webhook_fails_when_stored_key_cannot_be_decrypted(temp_db):
    from api.integrations.config import Integration
    from api.integrations.connectors import HttpWebhookPostJsonRequest, get_connector

    with temp_db() as session:
        integration = session.query(Integration).filter_by(tool_name="http_webhook").first()
        integration.base_url = "https://webhook.example/base"
        integration.enabled = True
        integration.mock_mode = False
        integration.verify_ssl = False
        # a stored value that is not a valid Fernet token (decryption fails)
        corrupt_ciphertext = "not-a-valid-fernet-token"
        integration.api_key = corrupt_ciphertext
        session.commit()
        session.refresh(integration)
        session.expunge(integration)

    with patch(
        "api.integrations.connectors.resolve_and_pin_integration_url",
        return_value=PinnedURL(url="https://93.184.216.34/base", hostname=None, host_header=None),
    ), patch("api.integrations.connectors.requests.Session") as session_cls:
        with pytest.raises(HTTPException) as exc:
            get_connector("http_webhook").execute(
                "post_json",
                HttpWebhookPostJsonRequest(body={"event": "x"}),
                integration,
            )

    assert exc.value.status_code == 500
    session_cls.return_value.post.assert_not_called()
