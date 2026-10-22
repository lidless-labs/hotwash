"""Server-side confirmation for destructive requests.

The MCP layer asks callers to confirm destructive tools, but any HTTP client
can reach the same routes directly, so the API enforces the same expectation.
"""

from __future__ import annotations

from fastapi import HTTPException


def require_confirmation(confirmed: bool | None, action: str) -> None:
    """Reject a destructive request unless the caller explicitly confirmed it."""
    if confirmed is True:
        return
    raise HTTPException(
        status_code=422,
        detail=f"Refusing to {action} without confirmation; resend with confirm=true",
    )
