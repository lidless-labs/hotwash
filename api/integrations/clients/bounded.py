"""Bounded reads for upstream HTTP responses.

Requests are issued with ``stream=True`` and the body is consumed here through
a strict byte limit, so an oversized or endless upstream response is cut off
instead of being buffered whole before it is parsed.
"""

from __future__ import annotations

import os

import requests

DEFAULT_MAX_UPSTREAM_BYTES = 5 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024


class UpstreamResponseTooLarge(Exception):
    """Raised when an upstream body exceeds the configured byte limit."""

    def __init__(self, limit: int) -> None:
        super().__init__(f"Upstream response exceeded {limit} bytes")
        self.limit = limit


def max_upstream_bytes() -> int:
    """Byte ceiling for one upstream response (HOTWASH_MAX_UPSTREAM_BYTES)."""
    raw = os.environ.get("HOTWASH_MAX_UPSTREAM_BYTES", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw)
    return DEFAULT_MAX_UPSTREAM_BYTES


def read_bounded(response: requests.Response, limit: int | None = None) -> requests.Response:
    """Consume ``response`` up to ``limit`` bytes and return it ready to parse.

    After this returns, ``.json()``, ``.text`` and ``.content`` read from the
    buffered body. Raises UpstreamResponseTooLarge, closing the connection,
    when the declared or actual size passes the limit.
    """
    cap = limit if limit is not None else max_upstream_bytes()
    headers = getattr(response, "headers", None) or {}
    declared = headers.get("Content-Length") if hasattr(headers, "get") else None
    if isinstance(declared, str) and declared.isdigit() and int(declared) > cap:
        response.close()
        raise UpstreamResponseTooLarge(cap)

    chunks: list[bytes] = []
    total = 0
    for chunk in response.iter_content(chunk_size=_CHUNK_BYTES):
        total += len(chunk)
        if total > cap:
            response.close()
            raise UpstreamResponseTooLarge(cap)
        chunks.append(chunk)
    response._content = b"".join(chunks)  # type: ignore[attr-defined]
    response._content_consumed = True  # type: ignore[attr-defined]
    return response
