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
from api.integrations.clients.thehive import TheHiveClient, TheHiveError
from api.integrations.config import Integration
from api.integrations.mock_data import MOCK_HANDLERS
from api.integrations.schemas import (
    AddObservableRequest,
    CreateAlertRequest,
    CreateCaseRequest,
)
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
    api_key_plain = decrypt_secret(integration.api_key)

    if tool == "thehive":
        client = TheHiveClient(
            base_url=integration.base_url,
            api_key=api_key_plain,
            verify_ssl=integration.verify_ssl,
        )
        try:
            result = client.status()
        except TheHiveError as exc:
            integration.last_checked = now
            integration.last_status = "error" if exc.status_code else "disconnected"
            db.commit()
            raise HTTPException(
                status_code=502,
                detail={
                    "message": str(exc),
                    "upstream_status": exc.status_code,
                    "details": exc.details,
                },
            ) from exc
        integration.last_checked = now
        integration.last_status = "connected"
        db.commit()
        return {"tool": tool, "mock_mode": False, "result": result}

    # Fallback generic probe for tools without a real client yet.
    try:
        import requests
        resp = requests.get(
            integration.base_url,
            timeout=5,
            verify=integration.verify_ssl,
            headers={"Authorization": f"Bearer {api_key_plain}"} if api_key_plain else {},
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


def _build_thehive_client(integration: Integration) -> TheHiveClient:
    """Validate state and construct a TheHiveClient, or raise HTTPException."""
    if not integration.enabled:
        raise HTTPException(status_code=400, detail="Integration disabled")
    if integration.mock_mode:
        raise HTTPException(
            status_code=400,
            detail="Cannot run live action in mock mode",
        )
    if not integration.base_url:
        raise HTTPException(status_code=400, detail="No base_url configured")
    api_key_plain = decrypt_secret(integration.api_key)
    if not api_key_plain:
        raise HTTPException(status_code=400, detail="No API key configured")
    validate_integration_url(integration.base_url)
    return TheHiveClient(
        base_url=integration.base_url,
        api_key=api_key_plain,
        verify_ssl=integration.verify_ssl,
    )


def _raise_for_thehive_error(exc: TheHiveError) -> None:
    raise HTTPException(
        status_code=502,
        detail={
            "message": str(exc),
            "upstream_status": exc.status_code,
            "details": exc.details,
        },
    )


@router.post("/integrations/thehive/actions/create_case")
def thehive_create_case(payload: CreateCaseRequest, db: Session = Depends(get_db)):
    integration = _get_integration(db, "thehive")
    client = _build_thehive_client(integration)
    try:
        result = client.create_case(
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            tlp=payload.tlp,
            pap=payload.pap,
            tags=payload.tags,
        )
    except TheHiveError as exc:
        _raise_for_thehive_error(exc)
    case_id = result.get("_id")
    number = result.get("number")
    case_url = (
        f"{integration.base_url.rstrip('/')}/cases/{number}/details" if number else None
    )
    return {"case_id": case_id, "number": number, "url": case_url, "raw": result}


@router.post("/integrations/thehive/actions/create_alert")
def thehive_create_alert(payload: CreateAlertRequest, db: Session = Depends(get_db)):
    integration = _get_integration(db, "thehive")
    client = _build_thehive_client(integration)
    try:
        result = client.create_alert(
            type=payload.type,
            source=payload.source,
            source_ref=payload.source_ref,
            title=payload.title,
            description=payload.description,
            severity=payload.severity,
            tlp=payload.tlp,
            pap=payload.pap,
            observables=payload.observables,
            tags=payload.tags,
        )
    except TheHiveError as exc:
        _raise_for_thehive_error(exc)
    return {"alert_id": result.get("_id"), "raw": result}


@router.post("/integrations/thehive/actions/add_observable")
def thehive_add_observable(payload: AddObservableRequest, db: Session = Depends(get_db)):
    integration = _get_integration(db, "thehive")
    client = _build_thehive_client(integration)
    try:
        result = client.add_observable(
            case_id=payload.case_id,
            data_type=payload.data_type,
            data=payload.data,
            message=payload.message,
            tlp=payload.tlp,
            ioc=payload.ioc,
            sighted=payload.sighted,
            tags=payload.tags,
        )
    except TheHiveError as exc:
        _raise_for_thehive_error(exc)
    return {"observable_id": result.get("_id"), "raw": result}
