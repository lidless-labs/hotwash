"""Opt-in live smoke test against a real Wazuh manager API.

Set HOTWASH_LIVE_WAZUH_URL, HOTWASH_LIVE_WAZUH_USERNAME, and
HOTWASH_LIVE_WAZUH_PASSWORD, then:
    pytest api/tests/test_wazuh_live.py -m live -v -s
"""

from __future__ import annotations

import os

import pytest

from api.integrations.clients.wazuh import WazuhClient, WazuhError

LIVE_URL = os.environ.get("HOTWASH_LIVE_WAZUH_URL")
LIVE_USERNAME = os.environ.get("HOTWASH_LIVE_WAZUH_USERNAME")
LIVE_PASSWORD = os.environ.get("HOTWASH_LIVE_WAZUH_PASSWORD")
# Lab managers commonly run on self-signed certs; opt out explicitly.
LIVE_VERIFY_SSL = os.environ.get("HOTWASH_LIVE_WAZUH_VERIFY_SSL", "true").lower() != "false"
SKIP_REASON = (
    "HOTWASH_LIVE_WAZUH_URL / HOTWASH_LIVE_WAZUH_USERNAME / "
    "HOTWASH_LIVE_WAZUH_PASSWORD not set"
)

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(not (LIVE_URL and LIVE_USERNAME and LIVE_PASSWORD), reason=SKIP_REASON),
]


@pytest.fixture(scope="module")
def live_client():
    return WazuhClient(
        base_url=LIVE_URL,
        username=LIVE_USERNAME,
        password=LIVE_PASSWORD,
        verify_ssl=LIVE_VERIFY_SSL,
        timeout=15.0,
    )


def test_api_info_returns_metadata(live_client):
    result = live_client.api_info()
    # Wazuh 4.x nests the payload under "data"; tolerate a flat shape too.
    info = result.get("data") if isinstance(result.get("data"), dict) else result
    assert info.get("title")
    assert info.get("api_version") or info.get("revision") or info.get("license_name")
    print(f"\n[live] Wazuh API: {info.get('title')} {info.get('api_version')}")


def test_list_agents_returns_agent_payload(live_client):
    try:
        result = live_client.list_agents(limit=1, select="id,name,status")
    except WazuhError as exc:
        raise AssertionError(f"Wazuh list_agents failed: {exc}") from exc

    assert "data" in result
    assert "affected_items" in result["data"]
    print(f"\n[live] Wazuh returned {len(result['data']['affected_items'])} agent(s)")
