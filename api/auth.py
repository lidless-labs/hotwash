"""API key authentication helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
import uuid
from typing import Optional

from fastapi import Header, HTTPException, Request, status

from api._compat import getenv_compat

logger = logging.getLogger(__name__)

_API_KEY: Optional[str] = None


def initialize_api_key() -> str:
    global _API_KEY
    if _API_KEY:
        return _API_KEY

    configured = getenv_compat("HOTWASH_API_KEY", "PLAYBOOK_FORGE_API_KEY")
    if configured:
        _API_KEY = configured
    else:
        _API_KEY = str(uuid.uuid4())
        # Never log the generated key itself: debug-level logging would write
        # the live credential to logs. Real deployments must set HOTWASH_API_KEY.
        logger.warning(
            "No HOTWASH_API_KEY configured, generated an ephemeral API key. "
            "Authenticated routes are unreachable until HOTWASH_API_KEY is set."
        )

    return _API_KEY


SCOPE_WRITE = "write"
SCOPE_READ = "read"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
WS_TICKET_TTL_SECONDS = 30
_WS_TICKET_PURPOSE = "ws-live"
_TRUTHY = {"1", "true", "yes", "on"}


def read_only_mode() -> bool:
    """True when HOTWASH_READ_ONLY is set: every key is limited to read scope."""
    return os.environ.get("HOTWASH_READ_ONLY", "").strip().lower() in _TRUTHY


def _same(a: str, b: str) -> bool:
    # Encode first: compare_digest raises TypeError on non-ASCII str input.
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _read_only_key() -> str | None:
    configured = os.environ.get("HOTWASH_READ_ONLY_API_KEY", "").strip()
    if not configured:
        return None
    if _same(configured, initialize_api_key()):
        logger.warning(
            "HOTWASH_READ_ONLY_API_KEY matches HOTWASH_API_KEY and is ignored; "
            "use a distinct value for a read-only scope."
        )
        return None
    return configured


def resolve_scope(provided_key: str | None) -> str | None:
    """Map a presented key to its scope, or None when it is not a valid key.

    HOTWASH_API_KEY carries write scope unless HOTWASH_READ_ONLY is set.
    HOTWASH_READ_ONLY_API_KEY, when configured, is always read scope.
    """
    candidate = provided_key or ""
    # Compare against both keys so timing does not reveal which one matched.
    write_match = _same(candidate, initialize_api_key() or "")
    read_key = _read_only_key()
    read_match = read_key is not None and _same(candidate, read_key)
    if write_match:
        return SCOPE_READ if read_only_mode() else SCOPE_WRITE
    if read_match:
        return SCOPE_READ
    return None


def is_valid_api_key(provided_key: str | None) -> bool:
    return resolve_scope(provided_key) is not None


def get_any_scope_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> str:
    """Authenticate a caller without regard to scope (read or write)."""
    provided_key = x_api_key or ""
    if resolve_scope(provided_key) is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    return provided_key


def get_api_key(
    request: Request,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Authenticate a caller and enforce scope: read scope allows safe methods only."""
    provided_key = x_api_key or ""
    scope = resolve_scope(provided_key)
    if scope is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
        )
    if scope == SCOPE_READ and request.method not in SAFE_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Read-only access: this key or server mode does not permit changes",
        )
    return provided_key


def _ticket_signing_key() -> bytes:
    return hashlib.sha256(b"hotwash-ws-ticket:" + (initialize_api_key() or "").encode("utf-8")).digest()


def _sign_ticket(payload: str) -> str:
    digest = hmac.new(_ticket_signing_key(), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def issue_ws_ticket(execution_id: int, *, now: float | None = None) -> tuple[str, int]:
    """Mint a short-lived ticket that opens the live socket for one execution.

    The ticket is bound to the execution id and to the socket purpose, so it
    cannot be replayed against another execution or any REST route, and it
    expires after WS_TICKET_TTL_SECONDS.
    """
    expires = int((time.time() if now is None else now) + WS_TICKET_TTL_SECONDS)
    payload = f"{_WS_TICKET_PURPOSE}.{execution_id}.{expires}"
    return f"{payload}.{_sign_ticket(payload)}", WS_TICKET_TTL_SECONDS


def verify_ws_ticket(ticket: str | None, execution_id: int, *, now: float | None = None) -> bool:
    if not ticket:
        return False
    parts = ticket.split(".")
    if len(parts) != 4:
        return False
    purpose, raw_execution, raw_expires, signature = parts
    payload = ".".join(parts[:3])
    if not _same(signature, _sign_ticket(payload)):
        return False
    if purpose != _WS_TICKET_PURPOSE or raw_execution != str(execution_id):
        return False
    try:
        expires = int(raw_expires)
    except ValueError:
        return False
    return (time.time() if now is None else now) <= expires
