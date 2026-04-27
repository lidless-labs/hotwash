"""
Wazuh ingest router.

Two router instances mounted under /api/ingest:

- `webhook_router`: POST /api/ingest/wazuh, HMAC-authenticated. No global
  X-API-Key dep so Wazuh's integration script can call it without setting
  custom headers it cannot easily produce.

- `mappings_router`: CRUD on /api/ingest/mappings/*, gated by X-API-Key like
  the rest of the dashboard surface.
"""

from __future__ import annotations

import json
import logging
from typing import List

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from api.auth import get_api_key
from api.crypto import encrypt_secret
from api.database import get_db
from api.orm_models import Playbook, WazuhMapping
from api.schemas import (
    IngestResponse,
    MappingCreate,
    MappingOut,
    MappingUpdate,
    WazuhAlertIngest,
)
from api.services.ingest import (
    VALID_MODES,
    load_mapping,
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
