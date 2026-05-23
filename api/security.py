"""Security validation helpers for outbound requests."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

from fastapi import HTTPException, status

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


def validate_integration_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only HTTP(S) integration URLs are allowed",
        )

    if not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Integration URL must include a hostname",
        )

    if _is_blocked_ip(parsed.hostname):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Integration URL points to a disallowed private or local address",
        )

    try:
        resolved = socket.getaddrinfo(parsed.hostname, parsed.port or None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Integration URL hostname could not be resolved",
        ) from exc

    for _, _, _, _, sockaddr in resolved:
        resolved_ip = sockaddr[0]
        if _is_blocked_ip(resolved_ip):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Integration URL resolves to a disallowed private or local address",
            )

    return url
