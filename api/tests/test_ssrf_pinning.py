"""Tests for the SSRF DNS-rebinding fix: resolve once, validate, pin the IP."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest
import requests
from fastapi import HTTPException

from api import security
from api.integrations.clients.thehive import TheHiveClient
from api.integrations.clients.wazuh import WazuhClient
from api.security import PinnedURL, apply_host_pinning, resolve_and_pin_integration_url


def _addrinfo(*ips: str):
    """Build a getaddrinfo-style result list for the given IPs."""
    entries = []
    for ip in ips:
        if ":" in ip:
            entries.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", (ip, 9000, 0, 0)))
        else:
            entries.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 9000)))
    return entries


def test_pins_first_resolved_public_ip():
    with patch("api.security.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        pinned = resolve_and_pin_integration_url("http://thehive.example.com:9000/base")
    assert pinned.url == "http://93.184.216.34:9000/base"
    assert pinned.hostname == "thehive.example.com"
    assert pinned.host_header == "thehive.example.com:9000"


def test_host_header_omits_default_port():
    with patch("api.security.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        pinned = resolve_and_pin_integration_url("https://thehive.example.com/base")
    assert pinned.url == "https://93.184.216.34/base"
    assert pinned.host_header == "thehive.example.com"


def test_rejects_hostname_resolving_to_private_ip():
    """The rebinding case: public-looking hostname answers with a private IP."""
    with patch("api.security.socket.getaddrinfo", return_value=_addrinfo("10.0.0.5")):
        with pytest.raises(HTTPException) as exc:
            resolve_and_pin_integration_url("http://rebind.example.com:9000")
    assert exc.value.status_code == 422


def test_rejects_mixed_public_and_private_resolution():
    with patch(
        "api.security.socket.getaddrinfo",
        return_value=_addrinfo("93.184.216.34", "169.254.169.254"),
    ):
        with pytest.raises(HTTPException) as exc:
            resolve_and_pin_integration_url("http://rebind.example.com:9000")
    assert exc.value.status_code == 422


def test_literal_ip_url_is_not_rewritten():
    pinned = resolve_and_pin_integration_url("http://93.184.216.34:9000/base")
    assert pinned.url == "http://93.184.216.34:9000/base"
    assert pinned.hostname is None
    assert pinned.host_header is None


def test_ipv6_resolution_is_bracketed():
    with patch("api.security.socket.getaddrinfo", return_value=_addrinfo("2606:2800:220:1::1")):
        pinned = resolve_and_pin_integration_url("http://thehive.example.com:9000/base")
    assert pinned.url == "http://[2606:2800:220:1::1]:9000/base"
    assert pinned.hostname == "thehive.example.com"


def test_validate_integration_url_still_returns_original():
    with patch("api.security.socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        assert (
            security.validate_integration_url("http://thehive.example.com:9000")
            == "http://thehive.example.com:9000"
        )


def test_apply_host_pinning_sets_host_header_and_https_adapter():
    session = requests.Session()
    pinned = PinnedURL(
        url="https://93.184.216.34:9443/base",
        hostname="thehive.example.com",
        host_header="thehive.example.com:9443",
    )
    apply_host_pinning(session, pinned)
    assert session.headers["Host"] == "thehive.example.com:9443"
    adapter = session.get_adapter("https://93.184.216.34:9443/base")
    assert isinstance(adapter, security._PinnedHostAdapter)
    assert adapter._server_hostname == "thehive.example.com"


def test_apply_host_pinning_noop_for_literal_ip():
    session = requests.Session()
    pinned = PinnedURL(url="http://93.184.216.34:9000", hostname=None, host_header=None)
    apply_host_pinning(session, pinned)
    assert "Host" not in session.headers
    assert not isinstance(session.get_adapter("https://x"), security._PinnedHostAdapter)


def test_thehive_client_requests_go_to_pinned_ip():
    pinned = PinnedURL(
        url="http://93.184.216.34:9000/base",
        hostname="thehive.example.com",
        host_header="thehive.example.com:9000",
    )
    client = TheHiveClient(
        base_url="http://thehive.example.com:9000/base",
        api_key="k",
        pinned=pinned,
    )
    # Public-facing base_url is untouched (used for case links in responses).
    assert client.base_url == "http://thehive.example.com:9000/base"
    assert client._session.headers["Host"] == "thehive.example.com:9000"
    with patch.object(client._session, "request") as mock_request:
        mock_request.return_value.status_code = 200
        mock_request.return_value.ok = True
        mock_request.return_value.json.return_value = {}
        client._request("GET", "/api/v1/status")
    args, kwargs = mock_request.call_args
    assert args == ("GET", "http://93.184.216.34:9000/base/api/v1/status")
    assert kwargs["allow_redirects"] is False


def test_wazuh_client_requests_go_to_pinned_ip():
    pinned = PinnedURL(
        url="https://93.184.216.34:55000/base",
        hostname="wazuh.example.com",
        host_header="wazuh.example.com:55000",
    )
    client = WazuhClient(
        base_url="https://wazuh.example.com:55000/base",
        username="alice",
        password="secret",
        pinned=pinned,
    )

    assert client.base_url == "https://wazuh.example.com:55000/base"
    assert client._session.headers["Host"] == "wazuh.example.com:55000"
    with patch.object(client._session, "request") as mock_request:
        mock_request.side_effect = [
            type(
                "Response",
                (),
                {
                    "status_code": 200,
                    "ok": True,
                    "text": "jwt-token",
                    "json": lambda self: {},
                },
            )(),
            type(
                "Response",
                (),
                {
                    "status_code": 200,
                    "ok": True,
                    "text": '{"title": "Wazuh API"}',
                    "json": lambda self: {"title": "Wazuh API"},
                },
            )(),
        ]
        client.api_info()

    assert mock_request.call_args_list[0].args[1] == "https://93.184.216.34:55000/base/security/user/authenticate"
    assert mock_request.call_args_list[1].args[1] == "https://93.184.216.34:55000/base/"
    assert mock_request.call_args_list[1].kwargs["allow_redirects"] is False
