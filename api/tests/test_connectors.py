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


def test_registry_lists_registered_connectors():
    from api.integrations.connectors import get_connector, registered_tool_names

    assert registered_tool_names() == ["http_webhook", "thehive"]
    assert get_connector("thehive").tool_name == "thehive"
    assert get_connector("http_webhook").tool_name == "http_webhook"
    assert get_connector("missing") is None


def test_connectors_declare_pydantic_action_schemas():
    from pydantic import BaseModel

    from api.integrations.connectors import get_connector

    actions = get_connector("http_webhook").actions()
    assert set(actions) == {"post_json"}
    assert issubclass(actions["post_json"], BaseModel)
    assert "body" in actions["post_json"].model_json_schema()["properties"]


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
