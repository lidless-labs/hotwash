"""
Wazuh ingest router.

Three router instances mounted under /api/ingest:

- `webhook_router`: POST /api/ingest/wazuh, HMAC-authenticated. No global
  X-API-Key dep so Wazuh's integration script can call it without setting
  custom headers it cannot easily produce.

- `mappings_router`: CRUD on /api/ingest/mappings/*, gated by X-API-Key like
  the rest of the dashboard surface.

- `suggestions_router`: list / get / accept / dismiss for IngestSuggestion
  rows produced by `mode=suggest` mappings. Also gated by X-API-Key.
"""

from __future__ import annotations

import json
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.auth import get_api_key
from api.confirmation import require_confirmation
from api.crypto import encrypt_secret
from api.database import get_db
from api.orm_models import IngestSuggestion, Playbook, WazuhMapping
from api.schemas import (
    ExecutionSummary,
    IngestResponse,
    MappingCreate,
    MappingOut,
    MappingUpdate,
    SuggestionAcceptResponse,
    SuggestionDetail,
    SuggestionDismiss,
    SuggestionOut,
    WazuhAlertIngest,
)
from api.services.executions import load_steps, step_progress
from api.services.ingest import (
    VALID_MODES,
    SuggestionStateError,
    accept_suggestion,
    dismiss_suggestion,
    load_mapping,
    load_suggestion,
    mapping_secret,
    parse_signature_header,
    process_alert,
    verify_hmac,
)

logger = logging.getLogger(__name__)

# Cap inbound webhook bodies to keep a misbehaving (or compromised) Wazuh
# integration from forcing memory + DB growth with one giant alert payload.
# Real Wazuh alerts are typically a few KB; 256 KB is a generous ceiling.
MAX_INGEST_BODY_BYTES = 256 * 1024

webhook_router = APIRouter()
mappings_router = APIRouter(dependencies=[Depends(get_api_key)])
suggestions_router = APIRouter(dependencies=[Depends(get_api_key)])

VALID_SUGGESTION_STATES = {"pending", "accepted", "dismissed"}


def _serialize_mapping(mapping: WazuhMapping) -> MappingOut:
    return MappingOut(
        id=mapping.id,
        name=mapping.name,
        playbook_id=mapping.playbook_id,
        mode=mapping.mode,
        rule_id_pattern=mapping.rule_id_pattern,
        rule_groups_pattern=mapping.rule_groups_pattern,
        agent_name_pattern=mapping.agent_name_pattern,
        cooldown_seconds=mapping.cooldown_seconds,
        has_hmac_secret=bool(mapping.hmac_secret_encrypted),
        enabled=mapping.enabled,
        created_at=mapping.created_at,
        updated_at=mapping.updated_at,
    )


def _validate_mode(mode: str) -> None:
    if mode not in VALID_MODES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode '{mode}'. Must be one of: {sorted(VALID_MODES)}",
        )


def _ensure_pattern_present(
    rule_id_pattern: str | None,
    rule_groups_pattern: str | None,
    agent_name_pattern: str | None,
) -> None:
    if not any(
        (p or "").strip()
        for p in (rule_id_pattern, rule_groups_pattern, agent_name_pattern)
    ):
        raise HTTPException(
            status_code=400,
            detail="At least one pattern (rule_id_pattern, rule_groups_pattern, or agent_name_pattern) is required",
        )


def _ensure_playbook(db: Session, playbook_id: int) -> None:
    exists = (
        db.query(Playbook.id)
        .filter(Playbook.id == playbook_id, Playbook.is_deleted.is_(False))
        .first()
    )
    if not exists:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found")


# --- Webhook ---


@webhook_router.post("/ingest/wazuh", response_model=IngestResponse)
async def ingest_wazuh_alert(
    request: Request,
    db: Session = Depends(get_db),
    x_hotwash_mapping_id: str | None = Header(default=None, alias="X-Hotwash-Mapping-Id"),
    x_hotwash_signature: str | None = Header(default=None, alias="X-Hotwash-Signature"),
):
    if not x_hotwash_mapping_id:
        raise HTTPException(status_code=400, detail="Missing X-Hotwash-Mapping-Id header")
    try:
        mapping_id = int(x_hotwash_mapping_id)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="X-Hotwash-Mapping-Id must be an integer")

    mapping = load_mapping(db, mapping_id)
    if mapping is None or not mapping.enabled:
        # Don't disclose whether the id exists.
        raise HTTPException(status_code=401, detail="Invalid signature or mapping")

    secret = mapping_secret(mapping)
    if not secret:
        logger.error("Mapping %s has no usable HMAC secret", mapping.id)
        raise HTTPException(status_code=401, detail="Invalid signature or mapping")

    # Enforce the size cap before reading the body into memory when the client
    # honestly declares Content-Length, then re-check after read for safety.
    declared_length = request.headers.get("content-length")
    if declared_length is not None:
        try:
            if int(declared_length) > MAX_INGEST_BODY_BYTES:
                raise HTTPException(status_code=413, detail="Alert payload too large")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    body = await request.body()
    if len(body) > MAX_INGEST_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Alert payload too large")

    provided = parse_signature_header(x_hotwash_signature)
    if not provided or not verify_hmac(secret, body, provided):
        raise HTTPException(status_code=401, detail="Invalid signature or mapping")

    try:
        raw_alert = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    if not isinstance(raw_alert, dict):
        raise HTTPException(status_code=400, detail="Alert body must be a JSON object")

    try:
        alert = WazuhAlertIngest.model_validate(raw_alert)
    except ValidationError:
        raise HTTPException(status_code=400, detail="Invalid alert payload shape")

    result = process_alert(db, mapping, alert, raw_alert)
    return IngestResponse(**result)


# --- Mapping CRUD ---


@mappings_router.get("/ingest/mappings", response_model=List[MappingOut])
def list_mappings(db: Session = Depends(get_db)):
    rows = db.query(WazuhMapping).order_by(WazuhMapping.id.asc()).all()
    return [_serialize_mapping(m) for m in rows]


@mappings_router.post(
    "/ingest/mappings",
    response_model=MappingOut,
    status_code=status.HTTP_201_CREATED,
)
def create_mapping(payload: MappingCreate, db: Session = Depends(get_db)):
    _validate_mode(payload.mode)
    _ensure_pattern_present(
        payload.rule_id_pattern,
        payload.rule_groups_pattern,
        payload.agent_name_pattern,
    )
    _ensure_playbook(db, payload.playbook_id)

    encrypted = encrypt_secret(payload.hmac_secret)
    if not encrypted:
        raise HTTPException(status_code=500, detail="Failed to encrypt HMAC secret")

    mapping = WazuhMapping(
        name=payload.name,
        playbook_id=payload.playbook_id,
        mode=payload.mode,
        rule_id_pattern=payload.rule_id_pattern,
        rule_groups_pattern=payload.rule_groups_pattern,
        agent_name_pattern=payload.agent_name_pattern,
        cooldown_seconds=payload.cooldown_seconds,
        hmac_secret_encrypted=encrypted,
        enabled=payload.enabled,
    )
    db.add(mapping)
    db.commit()
    db.refresh(mapping)
    return _serialize_mapping(mapping)


@mappings_router.get("/ingest/mappings/{mapping_id}", response_model=MappingOut)
def get_mapping(mapping_id: int, db: Session = Depends(get_db)):
    mapping = load_mapping(db, mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    return _serialize_mapping(mapping)


@mappings_router.patch("/ingest/mappings/{mapping_id}", response_model=MappingOut)
def update_mapping(mapping_id: int, payload: MappingUpdate, db: Session = Depends(get_db)):
    mapping = load_mapping(db, mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")

    if payload.mode is not None:
        _validate_mode(payload.mode)
        mapping.mode = payload.mode
    if payload.name is not None:
        mapping.name = payload.name
    if payload.playbook_id is not None:
        _ensure_playbook(db, payload.playbook_id)
        mapping.playbook_id = payload.playbook_id
    if payload.rule_id_pattern is not None:
        mapping.rule_id_pattern = payload.rule_id_pattern or None
    if payload.rule_groups_pattern is not None:
        mapping.rule_groups_pattern = payload.rule_groups_pattern or None
    if payload.agent_name_pattern is not None:
        mapping.agent_name_pattern = payload.agent_name_pattern or None
    if payload.cooldown_seconds is not None:
        mapping.cooldown_seconds = payload.cooldown_seconds
    if payload.hmac_secret is not None:
        encrypted = encrypt_secret(payload.hmac_secret)
        if not encrypted:
            raise HTTPException(status_code=500, detail="Failed to encrypt HMAC secret")
        mapping.hmac_secret_encrypted = encrypted
    if payload.enabled is not None:
        mapping.enabled = payload.enabled

    _ensure_pattern_present(
        mapping.rule_id_pattern,
        mapping.rule_groups_pattern,
        mapping.agent_name_pattern,
    )

    db.commit()
    db.refresh(mapping)
    return _serialize_mapping(mapping)


@mappings_router.delete(
    "/ingest/mappings/{mapping_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_mapping(mapping_id: int, db: Session = Depends(get_db)):
    mapping = load_mapping(db, mapping_id)
    if not mapping:
        raise HTTPException(status_code=404, detail="Mapping not found")
    db.delete(mapping)
    db.commit()
    return None


# --- Suggestions ---


# Map service-layer SuggestionStateError codes to (status, public message).
# Internal exception messages are kept off the wire so we don't leak
# implementation detail (PR #9 finding #5 stripped this from the webhook
# path; the suggestion endpoints inherit the same hygiene).
_SUGGESTION_ERROR_RESPONSES: dict[str, tuple[int, str]] = {
    "already_accepted": (409, "Suggestion has already been accepted"),
    "already_dismissed": (409, "Suggestion has already been dismissed"),
    "concurrent": (409, "Suggestion state changed concurrently, please retry"),
    "inconsistent": (409, "Suggestion is in an inconsistent state and cannot be processed"),
}


def _http_for_state_error(exc: SuggestionStateError) -> HTTPException:
    status_code, public = _SUGGESTION_ERROR_RESPONSES.get(
        exc.code, (409, "Suggestion is in an inconsistent state and cannot be processed")
    )
    # Operator-facing detail goes to the log; clients see only the public message.
    logger.warning("Suggestion state error (%s): %s", exc.code, exc)
    return HTTPException(status_code=status_code, detail=public)


def _serialize_suggestion_row(suggestion: IngestSuggestion) -> SuggestionOut:
    return SuggestionOut(
        id=suggestion.id,
        mapping_id=suggestion.mapping_id,
        playbook_id=suggestion.playbook_id,
        state=suggestion.state,
        fingerprint=suggestion.fingerprint,
        rule_id=suggestion.rule_id,
        agent_id=suggestion.agent_id,
        agent_name=suggestion.agent_name,
        description=suggestion.description,
        accepted_execution_id=suggestion.accepted_execution_id,
        created_at=suggestion.created_at,
        resolved_at=suggestion.resolved_at,
    )


def _serialize_suggestion_detail(suggestion: IngestSuggestion) -> SuggestionDetail:
    """Build a SuggestionDetail. Caller MUST check ``suggestion.mapping`` first.

    This is a pure serializer: it does not raise HTTPException. Validation of
    referenced rows happens in the route handler so the helper can be reused
    in non-HTTP contexts.
    """
    if suggestion.alert_payload_json:
        try:
            alert_payload = json.loads(suggestion.alert_payload_json)
        except json.JSONDecodeError:
            logger.warning(
                "Suggestion %s has corrupt alert_payload_json; returning empty payload",
                suggestion.id,
            )
            alert_payload = {}
        if not isinstance(alert_payload, dict):
            alert_payload = {}
    else:
        alert_payload = {}

    playbook_title = suggestion.playbook.title if suggestion.playbook else None

    return SuggestionDetail(
        id=suggestion.id,
        mapping_id=suggestion.mapping_id,
        playbook_id=suggestion.playbook_id,
        state=suggestion.state,
        fingerprint=suggestion.fingerprint,
        rule_id=suggestion.rule_id,
        agent_id=suggestion.agent_id,
        agent_name=suggestion.agent_name,
        description=suggestion.description,
        accepted_execution_id=suggestion.accepted_execution_id,
        created_at=suggestion.created_at,
        resolved_at=suggestion.resolved_at,
        alert_payload=alert_payload,
        mapping=_serialize_mapping(suggestion.mapping),
        playbook_title=playbook_title,
    )


def _execution_summary(execution) -> ExecutionSummary:
    steps = load_steps(execution)
    total, completed = step_progress(steps)
    playbook_title = execution.playbook.title if execution.playbook else None
    return ExecutionSummary(
        id=execution.id,
        playbook_id=execution.playbook_id,
        playbook_title=playbook_title,
        incident_title=execution.incident_title,
        incident_id=execution.incident_id,
        status=execution.status,
        started_by=execution.started_by,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        steps_total=total,
        steps_completed=completed,
    )


@suggestions_router.get("/ingest/suggestions", response_model=List[SuggestionOut])
def list_suggestions(
    db: Session = Depends(get_db),
    state_filter: str = Query(default="pending", alias="state"),
    mapping_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    if state_filter not in VALID_SUGGESTION_STATES:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid state '{state_filter}'. "
                f"Must be one of: {sorted(VALID_SUGGESTION_STATES)}"
            ),
        )
    query = db.query(IngestSuggestion).filter(IngestSuggestion.state == state_filter)
    if mapping_id is not None:
        query = query.filter(IngestSuggestion.mapping_id == mapping_id)
    rows = query.order_by(desc(IngestSuggestion.created_at)).limit(limit).all()
    return [_serialize_suggestion_row(row) for row in rows]


@suggestions_router.get(
    "/ingest/suggestions/{suggestion_id}",
    response_model=SuggestionDetail,
)
def get_suggestion(suggestion_id: int, db: Session = Depends(get_db)):
    suggestion = load_suggestion(db, suggestion_id)
    if suggestion is None:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    if suggestion.mapping is None:
        # The mapping FK has no ON DELETE behaviour and SQLite default skips
        # foreign-key enforcement, so this is reachable if a mapping is hard
        # deleted while a suggestion still references it. 410 Gone signals
        # the resource existed but is no longer retrievable.
        raise HTTPException(
            status_code=410,
            detail="Suggestion's underlying mapping has been removed",
        )
    return _serialize_suggestion_detail(suggestion)


@suggestions_router.post(
    "/ingest/suggestions/{suggestion_id}/accept",
    response_model=SuggestionAcceptResponse,
)
def accept_suggestion_route(
    suggestion_id: int,
    confirm: bool = Query(False, description="Must be true to create an execution from the suggestion"),
    db: Session = Depends(get_db),
):
    require_confirmation(confirm, "accept this suggestion")
    try:
        execution, already_accepted = accept_suggestion(db, suggestion_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    except SuggestionStateError as exc:
        raise _http_for_state_error(exc)
    return SuggestionAcceptResponse(
        execution=_execution_summary(execution),
        already_accepted=already_accepted,
    )


@suggestions_router.post(
    "/ingest/suggestions/{suggestion_id}/dismiss",
    response_model=SuggestionOut,
)
def dismiss_suggestion_route(
    suggestion_id: int,
    payload: Optional[SuggestionDismiss] = None,
    confirm: bool = Query(False, description="Must be true to dismiss the suggestion"),
    db: Session = Depends(get_db),
):
    require_confirmation(confirm, "dismiss this suggestion")
    reason = payload.reason if payload else None
    try:
        suggestion = dismiss_suggestion(db, suggestion_id, reason)
    except LookupError:
        raise HTTPException(status_code=404, detail="Suggestion not found")
    except SuggestionStateError as exc:
        raise _http_for_state_error(exc)
    return _serialize_suggestion_row(suggestion)
