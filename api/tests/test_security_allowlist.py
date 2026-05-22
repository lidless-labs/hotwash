"""Tests for HOTWASH_PRIVATE_HOST_ALLOWLIST env handling in security.validate_integration_url."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from api import security


def test_blocks_private_lan_by_default(monkeypatch):
    monkeypatch.delenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", raising=False)
    security._reload_allowlist()
    with pytest.raises(HTTPException) as exc:
        security.validate_integration_url("http://192.168.1.50:9000")
    assert exc.value.status_code == 422


def test_allows_listed_cidr(monkeypatch):
    monkeypatch.setenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", "192.168.1.0/24")
    security._reload_allowlist()
    assert (
        security.validate_integration_url("http://192.168.1.50:9000")
        == "http://192.168.1.50:9000"
    )


def test_multiple_cidrs(monkeypatch):
    monkeypatch.setenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", "192.168.1.0/24, 10.0.0.0/8")
    security._reload_allowlist()
    assert security.validate_integration_url("http://10.5.5.5") == "http://10.5.5.5"
    assert security.validate_integration_url("http://192.168.1.50") == "http://192.168.1.50"


def test_ignores_malformed_cidrs(monkeypatch, caplog):
    monkeypatch.setenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", "not-a-cidr, 192.168.1.0/24")
    security._reload_allowlist()
    # Still allows the good one
    assert security.validate_integration_url("http://192.168.1.50") == "http://192.168.1.50"


def test_loopback_never_allowed_via_allowlist(monkeypatch):
    """127/8 stays blocked even if the allowlist includes it - defense in depth.

    If you really want loopback in tests, use mocked HTTP, not the network."""
    monkeypatch.setenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", "127.0.0.0/8")
    security._reload_allowlist()
    with pytest.raises(HTTPException) as exc:
        security.validate_integration_url("http://127.0.0.1:9000")
    assert exc.value.status_code == 422


@pytest.fixture(autouse=True)
def _reset_allowlist_after_test(monkeypatch):
    yield
    monkeypatch.delenv("HOTWASH_PRIVATE_HOST_ALLOWLIST", raising=False)
    security._reload_allowlist()
