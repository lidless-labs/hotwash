"""Integrations Router - CRUD, connection tests, and connector actions."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth import get_api_key
from api.crypto import decrypt_secret, encrypt_secret
from api.database import get_db
from api.integrations.clients.thehive import TheHiveClient, TheHiveError
from api.integrations.connectors import get_connector
from api.integrations.config import Integration
from api.integrations.mock_data import MOCK_HANDLERS, get_mock_action_result
from api.integrations.schemas import (
    AddObservableRequest,
    CreateAlertRequest,
    CreateCaseRequest,
)
from api.orm_models import Execution, ExecutionEvent, RunEvent
from api.routers.executions import _validate_node_id_for_path
from api.schemas import IntegrationOut, IntegrationUpdate
from api.security import apply_host_pinning, resolve_and_pin_integration_url
from api.services import replay
from api.services.executions import find_step, load_steps, now_iso, serialize_steps

router = APIRouter(dependencies=[Depends(get_api_key)])

VALID_TOOLS = {"thehive", "http_webhook", "cortex", "wazuh", "misp"}
URL_PATTERN = re.compile(r"^https?://\S+$")
EVIDENCE_ROOT = Path(__file__).resolve().parent.parent / "data" / "evidence"


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

    pinned = resolve_and_pin_integration_url(integration.base_url)
    api_key_plain = decrypt_secret(integration.api_key)

    if tool == "thehive":
        client = TheHiveClient(
            base_url=integration.base_url,
            api_key=api_key_plain,
            verify_ssl=integration.verify_ssl,
            pinned=pinned,
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
    # Connects to the pinned IP (with Host/SNI restored) and never follows
    # redirects, so DNS rebinding cannot steer the probe to a private address.
    try:
        import requests
        session = requests.Session()
        apply_host_pinning(session, pinned)
        if api_key_plain:
            session.headers["Authorization"] = f"Bearer {api_key_plain}"
        resp = session.get(
            pinned.url,
            timeout=5,
            verify=integration.verify_ssl,
            allow_redirects=False,
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
    pinned = resolve_and_pin_integration_url(integration.base_url)
    return TheHiveClient(
        base_url=integration.base_url,
        api_key=api_key_plain,
        verify_ssl=integration.verify_ssl,
        pinned=pinned,
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


def _schema_for_action(tool: str, action: str):
    connector = get_connector(tool)
    if connector is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool}")
    schema = connector.actions().get(action)
    if schema is None:
        raise HTTPException(status_code=404, detail=f"Unknown action: {action}")
    return connector, schema


def _extract_run_context(body: dict[str, Any]) -> tuple[int | None, str | None, dict[str, Any]]:
    payload = dict(body)
    run_id = payload.pop("run_id", None)
    node_id = payload.pop("node_id", None)
    return run_id, node_id, payload


def _validate_run_step(
    db: Session,
    run_id: int | None,
    node_id: str | None,
) -> tuple[Execution, list[dict[str, Any]], dict[str, Any]] | None:
    if run_id is None or node_id is None:
        return None
    execution = db.query(Execution).filter(Execution.id == run_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    steps = load_steps(execution)
    step = find_step(steps, node_id)
    if step is None:
        raise HTTPException(status_code=404, detail="Step not found")
    _validate_node_id_for_path(node_id)
    return execution, steps, step


def _attach_action_result(
    db: Session,
    execution: Execution,
    steps: list[dict[str, Any]],
    step: dict[str, Any],
    *,
    tool: str,
    action: str,
    result: dict[str, Any],
) -> None:
    uploaded_at = now_iso()
    filename = f"{tool}-{action}-result.json"
    body = json.dumps(result, default=str, indent=2, sort_keys=True).encode("utf-8")
    node_id = str(step.get("node_id") or "")

    target_dir = EVIDENCE_ROOT / str(execution.id) / node_id
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / filename
    if target_path.exists():
        stem = target_path.stem
        suffix = target_path.suffix
        for index in range(1, 10000):
            candidate = target_dir / f"{stem}-{index}{suffix}"
            if not candidate.exists():
                target_path = candidate
                filename = target_path.name
                break
    target_path.write_bytes(body)

    entry = {
        "filename": filename,
        "size": len(body),
        "uploaded_at": uploaded_at,
        "content_type": "application/json",
        "connector": tool,
        "action": action,
        "result": result,
    }
    step["evidence"] = list(step.get("evidence") or []) + [entry]
    execution.steps_json = serialize_steps(steps)
    db.add(
        ExecutionEvent(
            execution_id=execution.id,
            event_type="evidence_attached",
            description=f"Connector action '{tool}.{action}' result attached to '{step.get('node_label')}'",
        )
    )
    db.add(
        RunEvent(
            execution_id=execution.id,
            event_type=replay.STEP_EVIDENCE_ATTACHED,
            payload_json=json.dumps({"node_id": step.get("node_id"), "evidence": entry}, default=str),
        )
    )


def _validate_action_payload(schema, payload: dict[str, Any]):
    try:
        return schema.model_validate(payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc


def _dispatch_connector_action(
    tool: str,
    action: str,
    body: dict[str, Any],
    db: Session,
    *,
    allow_mock_mode: bool = True,
) -> dict[str, Any]:
    connector, schema = _schema_for_action(tool, action)
    integration = _get_integration(db, tool)
    run_id, node_id, connector_payload = _extract_run_context(body)
    run_context = _validate_run_step(db, run_id, node_id)
    validated_payload = _validate_action_payload(schema, connector_payload)

    if not integration.enabled:
        raise HTTPException(status_code=400, detail="Integration disabled")
    if integration.mock_mode:
        if not allow_mock_mode:
            raise HTTPException(status_code=400, detail="Cannot run live action in mock mode")
        result = get_mock_action_result(tool, action)
    else:
        try:
            result = connector.execute(action, validated_payload, integration)
        except TheHiveError as exc:
            _raise_for_thehive_error(exc)

    if run_context is not None:
        execution, steps, step = run_context
        _attach_action_result(
            db,
            execution,
            steps,
            step,
            tool=tool,
            action=action,
            result=result,
        )
        db.commit()

    return result


@router.get("/integrations/{tool}/actions")
def list_connector_actions(tool: str):
    connector = get_connector(tool)
    if connector is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool}")
    return [
        {"name": name, "schema": schema.model_json_schema()}
        for name, schema in sorted(connector.actions().items())
    ]


@router.post("/integrations/thehive/actions/create_case")
def thehive_create_case(payload: CreateCaseRequest = Body(...), db: Session = Depends(get_db)):
    return _dispatch_connector_action(
        "thehive",
        "create_case",
        payload.model_dump(),
        db,
        allow_mock_mode=False,
    )


@router.post("/integrations/thehive/actions/create_alert")
def thehive_create_alert(payload: CreateAlertRequest = Body(...), db: Session = Depends(get_db)):
    return _dispatch_connector_action(
        "thehive",
        "create_alert",
        payload.model_dump(),
        db,
        allow_mock_mode=False,
    )


@router.post("/integrations/thehive/actions/add_observable")
def thehive_add_observable(payload: AddObservableRequest = Body(...), db: Session = Depends(get_db)):
    return _dispatch_connector_action(
        "thehive",
        "add_observable",
        payload.model_dump(),
        db,
        allow_mock_mode=False,
    )


@router.post("/integrations/{tool}/actions/{action}")
def run_connector_action(
    tool: str,
    action: str,
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    return _dispatch_connector_action(tool, action, payload, db)
