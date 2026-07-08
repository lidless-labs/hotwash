"""Security validation helpers for outbound requests."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from typing import NamedTuple, Optional
from urllib.parse import urlparse

import requests.adapters
from fastapi import HTTPException, status

# starlette renamed HTTP_422_UNPROCESSABLE_ENTITY to ..._CONTENT; support both
# so the pinned fastapi/starlette pair and newer installs agree on 422.
HTTP_422 = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", status.HTTP_422_UNPROCESSABLE_ENTITY)

logger = logging.getLogger(__name__)

_ALLOWED_NETWORKS: list[ipaddress._BaseNetwork] = []


def _reload_allowlist() -> None:
    """Reload HOTWASH_PRIVATE_HOST_ALLOWLIST from env. Call after env mutations in tests."""
    global _ALLOWED_NETWORKS
    raw = os.environ.get("HOTWASH_PRIVATE_HOST_ALLOWLIST", "")
    parsed: list[ipaddress._BaseNetwork] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            parsed.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("Ignoring malformed CIDR in HOTWASH_PRIVATE_HOST_ALLOWLIST: %r", token)
    _ALLOWED_NETWORKS = parsed


_reload_allowlist()


def _is_never_allowed(ip: ipaddress._BaseAddress) -> bool:
    """Addresses that stay blocked even if the allowlist names them.

    Covers IPv4 + IPv6 loopback, link-local, unspecified, and multicast.
    Stdlib's IPv6Address.is_loopback / .is_link_local correctly classify
    IPv4-mapped forms like ::ffff:127.0.0.1.
    """
    return ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast


def _is_blocked_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if _is_never_allowed(ip):
        return True
    if any(ip in network for network in _ALLOWED_NETWORKS):
        return False
    # Blocks RFC 1918 + RFC 4193 ULA (fc00::/7) + reserved ranges in both v4 and v6.
    return ip.is_private or ip.is_reserved


class PinnedURL(NamedTuple):
    """An integration URL whose destination IP was validated at resolve time.

    ``url`` carries the validated literal IP in its netloc, so the HTTP
    client connects to exactly the address that passed the allowlist
    (closing the DNS-rebinding TOCTOU where a hostname re-resolves to a
    private address between validation and fetch). ``hostname`` keeps the
    original name for the Host header and TLS SNI/verification; it is None
    when the URL already used a literal IP and no rewrite happened.
    """

    url: str
    hostname: Optional[str]
    host_header: Optional[str]


def _pin_netloc(parsed, resolved_ip: str) -> str:
    """Rebuild the netloc with the validated literal IP (bracketed for v6)."""
    ip = ipaddress.ip_address(resolved_ip)
    host = f"[{resolved_ip}]" if ip.version == 6 else resolved_ip
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def resolve_and_pin_integration_url(url: str) -> PinnedURL:
    """Validate an outbound integration URL and pin its resolved IP.

    Resolves the hostname exactly once, requires every resolved address to
    pass the private/reserved allowlist, then returns a URL rewritten to the
    first validated IP. Callers must connect to ``PinnedURL.url`` and send
    ``PinnedURL.host_header`` (see apply_host_pinning) so no second DNS
    lookup can be steered to a private address.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Only HTTP(S) integration URLs are allowed",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Integration URL must include a hostname",
        )

    if _is_blocked_ip(parsed.hostname):
        raise HTTPException(
            status_code=HTTP_422,
            detail="Integration URL points to a disallowed private or local address",
        )

    # Literal IP: already validated above, nothing to pin.
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        return PinnedURL(url=url, hostname=None, host_header=None)

    try:
        resolved = socket.getaddrinfo(parsed.hostname, parsed.port or None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Integration URL hostname could not be resolved",
        ) from exc

    if not resolved:
        raise HTTPException(
            status_code=HTTP_422,
            detail="Integration URL hostname could not be resolved",
        )

    for _, _, _, _, sockaddr in resolved:
        resolved_ip = sockaddr[0]
        if _is_blocked_ip(resolved_ip):
            raise HTTPException(
                status_code=HTTP_422,
                detail="Integration URL resolves to a disallowed private or local address",
            )

    pinned_ip = resolved[0][4][0]
    pinned = parsed._replace(netloc=_pin_netloc(parsed, pinned_ip))

    host_header = parsed.hostname
    if parsed.port is not None and parsed.port != _default_port(parsed.scheme):
        host_header = f"{parsed.hostname}:{parsed.port}"

    return PinnedURL(url=pinned.geturl(), hostname=parsed.hostname, host_header=host_header)


def validate_integration_url(url: str) -> str:
    """Validate an integration URL without rewriting it.

    Kept for write-time validation (PUT /integrations) and backward
    compatibility; fetch paths should use resolve_and_pin_integration_url
    and connect to the pinned IP instead.
    """
    resolve_and_pin_integration_url(url)
    return url


class _PinnedHostAdapter(requests.adapters.HTTPAdapter):
    """HTTPS adapter that restores the original hostname for SNI and
    certificate verification when the request URL carries a literal IP."""

    def __init__(self, server_hostname: str, **kwargs):
        self._server_hostname = server_hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=requests.adapters.DEFAULT_POOLBLOCK, **pool_kwargs):
        pool_kwargs["server_hostname"] = self._server_hostname
        pool_kwargs["assert_hostname"] = self._server_hostname
        return super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


def apply_host_pinning(session: "requests.Session", pinned: PinnedURL) -> None:
    """Configure a requests Session to talk to a PinnedURL safely.

    Sends the original hostname as the Host header and, for HTTPS, uses it
    for TLS SNI and certificate verification while the TCP connection goes
    to the validated literal IP. No-op when the URL was already a literal IP.
    """
    if pinned.hostname is None:
        return
    session.headers["Host"] = pinned.host_header or pinned.hostname
    if urlparse(pinned.url).scheme == "https":
        session.mount("https://", _PinnedHostAdapter(pinned.hostname))
