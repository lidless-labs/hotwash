"""
Integrations Router — CRUD + connection testing for external tool integrations.
"""

import re
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.auth import get_api_key
from api.crypto import decrypt_secret, encrypt_secret
from api.database import get_db
from api.integrations.config import Integration
from api.integrations.mock_data import MOCK_HANDLERS
from api.schemas import IntegrationOut, IntegrationUpdate
from api.security import validate_integration_url

router = APIRouter(dependencies=[Depends(get_api_key)])

VALID_TOOLS = {"thehive", "cortex", "wazuh", "misp"}
URL_PATTERN = re.compile(r"^https?://\S+$")


def _to_out(i: Integration) -> IntegrationOut:
    return IntegrationOut(
        tool_name=i.tool_name,
        display_name=i.display_name,
        base_url=i.base_url or "",
        enabled=i.enabled,
        verify_ssl=i.verify_ssl,
        mock_mode=i.mock_mode,
        last_checked=i.last_checked,
        last_status=i.last_status or "unchecked",
        has_api_key=bool(decrypt_secret(i.api_key)),
        has_credentials=bool(i.username),
    )


def _get_integration(db: Session, tool: str) -> Integration:
    if tool not in VALID_TOOLS:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool}")
    integration = db.query(Integration).filter(Integration.tool_name == tool).first()
    if not integration:
        raise HTTPException(status_code=404, detail=f"Integration not found: {tool}")
    return integration


@router.get("/integrations", response_model=List[IntegrationOut])
def list_integrations(db: Session = Depends(get_db)):
    integrations = db.query(Integration).order_by(Integration.tool_name).all()
    return [_to_out(i) for i in integrations]


@router.get("/integrations/{tool}", response_model=IntegrationOut)
def get_integration(tool: str, db: Session = Depends(get_db)):
    return _to_out(_get_integration(db, tool))


@router.put("/integrations/{tool}", response_model=IntegrationOut)
def update_integration(tool: str, payload: IntegrationUpdate, db: Session = Depends(get_db)):
    integration = _get_integration(db, tool)

    if payload.base_url is not None:
        if payload.base_url and not URL_PATTERN.match(payload.base_url):
            raise HTTPException(status_code=422, detail="base_url must be a valid HTTP(S) URL")
        integration.base_url = payload.base_url

    if payload.api_key is not None:
        integration.api_key = encrypt_secret(payload.api_key)
    if payload.username is not None:
        integration.username = payload.username
    if payload.password is not None:
        integration.password = encrypt_secret(payload.password)
    if payload.enabled is not None:
        integration.enabled = payload.enabled
    if payload.verify_ssl is not None:
        integration.verify_ssl = payload.verify_ssl
    if payload.mock_mode is not None:
        integration.mock_mode = payload.mock_mode

    db.commit()
    db.refresh(integration)
    return _to_out(integration)


@router.post("/integrations/{tool}/test")
def test_integration(tool: str, db: Session = Depends(get_db)):
    integration = _get_integration(db, tool)
    now = datetime.now(timezone.utc)

    if integration.mock_mode:
        handler = MOCK_HANDLERS.get(tool)
        mock_result = handler() if handler else {"status": "connected"}
        integration.last_checked = now
        integration.last_status = "connected"
        db.commit()
        return {"tool": tool, "mock_mode": True, "result": mock_result}

    # Real connection test
    if not integration.base_url:
        integration.last_checked = now
        integration.last_status = "error"
        db.commit()
        raise HTTPException(status_code=400, detail="No base_url configured")

    validate_integration_url(integration.base_url)
    api_key = decrypt_secret(integration.api_key)

    try:
        import requests
        resp = requests.get(
            integration.base_url,
            timeout=5,
            verify=integration.verify_ssl,
            headers={"Authorization": f"Bearer {api_key}"} if api_key else {},
        )
        if resp.status_code in (200, 401, 403):
            integration.last_status = "connected"
        else:
            integration.last_status = "error"
    except Exception as exc:
        integration.last_status = "disconnected"
        integration.last_checked = now
        db.commit()
        return {"tool": tool, "mock_mode": False, "result": {"status": "disconnected", "error": str(exc)}}

    integration.last_checked = now
    db.commit()
    return {"tool": tool, "mock_mode": False, "result": {"status": integration.last_status}}
