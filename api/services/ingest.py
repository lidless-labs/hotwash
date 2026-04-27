"""Wazuh alert ingest service: match, dedup, dispatch.

Pure functions plus a single orchestrator (`process_alert`) that the router
calls after authenticating the request. Kept separate from the HTTP layer so
the same logic can be reused by future polling or CLI ingestion paths.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.crypto import decrypt_secret
from api.orm_models import (
    Execution,
    ExecutionEvent,
    IngestSuggestion,
    IngestSuppressionLog,
    Playbook,
    WazuhMapping,
)
from api.schemas import WazuhAlertIngest
from api.services.executions import build_steps_from_playbook, serialize_steps

logger = logging.getLogger(__name__)

VALID_MODES = {"auto", "suggest", "off"}
INCIDENT_TITLE_MAX = 255

# Reasons that should anchor cooldown lookups. mode_off and no_match are
# excluded so flipping a mapping from off to suggest, or fixing a mis-aimed
# integration, does not silently swallow the first legitimate alert that
# follows.
COOLDOWN_ANCHOR_REASONS = ("dispatched_auto", "dispatched_suggest", "cooldown")

_HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# --- HMAC ---


def parse_signature_header(value: Optional[str]) -> Optional[str]:
    """Pull the hex digest out of `sha256=<hex>` or accept a bare hex digest."""
    if not value:
        return None
    raw = value.strip()
    if raw.lower().startswith("sha256="):
        raw = raw.split("=", 1)[1].strip()
    if not raw:
        return None
    return raw.lower()


def verify_hmac(secret: str, body: bytes, provided_hex: str) -> bool:
    if not _HEX64_RE.match(provided_hex or ""):
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected.lower(), provided_hex.lower())


# --- Matching ---


def _csv_to_set(value: Optional[str]) -> Optional[set[str]]:
    """Parse a CSV pattern into a set of stripped, lowercased exact tokens.

    None or empty string returns None to signal wildcard-match.
    """
    if value is None:
        return None
    tokens = {item.strip().lower() for item in value.split(",")}
    tokens.discard("")
    if not tokens:
        return None
    return tokens


def specificity(mapping: WazuhMapping) -> int:
    """Count of non-wildcard pattern fields."""
    return sum(
        1
        for field in (
            mapping.rule_id_pattern,
            mapping.rule_groups_pattern,
            mapping.agent_name_pattern,
        )
        if (field or "").strip()
    )


def alert_matches_mapping(alert: WazuhAlertIngest, mapping: WazuhMapping) -> bool:
    rule_ids = _csv_to_set(mapping.rule_id_pattern)
    rule_groups = _csv_to_set(mapping.rule_groups_pattern)
    agent_names = _csv_to_set(mapping.agent_name_pattern)

    rule = alert.rule
    agent = alert.agent

    if rule_ids is not None:
        rid = (rule.id if rule and rule.id else "").strip().lower()
        if not rid or rid not in rule_ids:
            return False

    if rule_groups is not None:
        groups = {g.strip().lower() for g in (rule.groups if rule else [])}
        groups.discard("")
        if not groups or rule_groups.isdisjoint(groups):
            return False

    if agent_names is not None:
        aname = (agent.name if agent and agent.name else "").strip().lower()
        if not aname or aname not in agent_names:
            return False

    return True


def select_mapping(db: Session, alert: WazuhAlertIngest) -> Optional[WazuhMapping]:
    """Highest specificity wins, tie-break by oldest created_at, then smallest id."""
    candidates = (
        db.query(WazuhMapping)
        .filter(WazuhMapping.enabled.is_(True))
        .all()
    )
    matched = [m for m in candidates if alert_matches_mapping(alert, m)]
    if not matched:
        return None
    matched.sort(key=lambda m: (-specificity(m), m.created_at, m.id))
    return matched[0]


# --- Cooldown ---


def fingerprint_for(mapping_id: int, rule_id: Optional[str], agent_id: Optional[str]) -> str:
    payload = f"{mapping_id}:{rule_id or ''}:{agent_id or ''}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_seen(db: Session, fingerprint: str) -> Optional[datetime]:
    row = (
        db.query(IngestSuppressionLog)
        .filter(
            IngestSuppressionLog.fingerprint == fingerprint,
            IngestSuppressionLog.reason.in_(COOLDOWN_ANCHOR_REASONS),
        )
        .order_by(desc(IngestSuppressionLog.created_at))
        .first()
    )
    return row.created_at if row else None


def is_in_cooldown(
    db: Session,
    fingerprint: str,
    cooldown_seconds: int,
    now: Optional[datetime] = None,
) -> bool:
    if cooldown_seconds <= 0:
        return False
    last = _last_seen(db, fingerprint)
    if last is None:
        return False
    current = now or datetime.now(timezone.utc)
    # SQLite's CURRENT_TIMESTAMP (which server_default=func.now() resolves to)
    # is documented UTC, so naive timestamps from the DB can be safely tagged
    # as UTC. If the schema ever moves to DateTime(timezone=True), `last` will
    # already be aware and we keep it as-is.
    last_aware = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
    return (current - last_aware) < timedelta(seconds=cooldown_seconds)


def _log(
    db: Session,
    mapping_id: Optional[int],
    fingerprint: str,
    rule_id: Optional[str],
    agent_id: Optional[str],
    reason: str,
) -> IngestSuppressionLog:
    row = IngestSuppressionLog(
        mapping_id=mapping_id,
        fingerprint=fingerprint,
        rule_id=rule_id,
        agent_id=agent_id,
        reason=reason,
    )
    db.add(row)
    db.flush()
    return row


# --- Dispatch ---


def _truncate(value: str, limit: int) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _incident_title(alert: WazuhAlertIngest) -> str:
    rule = alert.rule
    rid = rule.id if rule and rule.id else "?"
    desc_text = (rule.description if rule and rule.description else "Wazuh alert").strip() or "Wazuh alert"
    return _truncate(f"[Wazuh r{rid}] {desc_text}", INCIDENT_TITLE_MAX)


def _incident_id(alert: WazuhAlertIngest) -> str:
    rid = alert.rule.id if alert.rule and alert.rule.id else "unknown"
    aid = alert.agent.id if alert.agent and alert.agent.id else "unknown"
    epoch_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    return f"wazuh:{rid}:{aid}:{epoch_ms}"


def _create_execution(
    db: Session,
    mapping: WazuhMapping,
    alert: WazuhAlertIngest,
    raw_alert: Dict[str, Any],
    fingerprint: str,
) -> Execution:
    playbook = (
        db.query(Playbook)
        .filter(Playbook.id == mapping.playbook_id, Playbook.is_deleted.is_(False))
        .first()
    )
    if playbook is None:
        raise LookupError(f"Mapping {mapping.id} references missing playbook {mapping.playbook_id}")

    steps = build_steps_from_playbook(playbook)
    context = {
        "wazuh_alert": raw_alert,
        "ingest": {
            "mapping_id": mapping.id,
            "mapping_name": mapping.name,
            "fingerprint": fingerprint,
            "received_at": datetime.now(timezone.utc).isoformat(),
        },
    }
    execution = Execution(
        playbook_id=playbook.id,
        incident_title=_incident_title(alert),
        incident_id=_incident_id(alert),
        started_by="wazuh-ingest",
        status="active",
        steps_json=serialize_steps(steps),
        context_json=json.dumps(context),
    )
    db.add(execution)
    db.flush()

    db.add(
        ExecutionEvent(
            execution_id=execution.id,
            event_type="ingested_from_wazuh",
            actor="wazuh-ingest",
            description=(
                f"Auto-dispatched from Wazuh mapping '{mapping.name}' "
                f"(rule {alert.rule.id if alert.rule else '?'}, "
                f"agent {alert.agent.name if alert.agent else '?'})"
            ),
        )
    )
    db.flush()
    return execution


def _create_suggestion(
    db: Session,
    mapping: WazuhMapping,
    alert: WazuhAlertIngest,
    raw_alert: Dict[str, Any],
    fingerprint: str,
) -> IngestSuggestion:
    rule = alert.rule
    agent = alert.agent
    suggestion = IngestSuggestion(
        mapping_id=mapping.id,
        playbook_id=mapping.playbook_id,
        fingerprint=fingerprint,
        alert_payload_json=json.dumps(raw_alert),
        rule_id=rule.id if rule else None,
        agent_id=agent.id if agent else None,
        agent_name=agent.name if agent else None,
        description=rule.description if rule else None,
        state="pending",
    )
    db.add(suggestion)
    db.flush()
    return suggestion


def process_alert(
    db: Session,
    mapping: WazuhMapping,
    alert: WazuhAlertIngest,
    raw_alert: Dict[str, Any],
) -> Dict[str, Any]:
    """Run the post-auth pipeline for an alert against an already-loaded mapping.

    Caller has verified HMAC and confirmed the mapping exists. We re-match the
    alert against the mapping to reject mis-aimed callers, then dispatch by mode
    with cooldown dedup.

    Cooldown dedup is read-modify-write and not atomic across concurrent
    workers: two webhook requests with the same fingerprint that race the
    `is_in_cooldown` check can both dispatch. Hotwash currently ships as a
    single-process uvicorn deployment, so the practical race window is narrow.
    Multi-worker deployments will need a unique constraint on the suppression
    log keyed by fingerprint plus a time bucket to make the race deterministic.

    Returns a dict shaped like IngestResponse fields.
    """
    if not alert_matches_mapping(alert, mapping):
        rule_id = alert.rule.id if alert.rule else None
        agent_id = alert.agent.id if alert.agent else None
        fp = fingerprint_for(mapping.id, rule_id, agent_id)
        _log(db, mapping.id, fp, rule_id, agent_id, "no_match")
        db.commit()
        return {
            "status": "ignored",
            "reason": "alert does not match mapping criteria",
            "mapping_id": mapping.id,
            "fingerprint": fp,
        }

    if mapping.mode == "off":
        rule_id = alert.rule.id if alert.rule else None
        agent_id = alert.agent.id if alert.agent else None
        fp = fingerprint_for(mapping.id, rule_id, agent_id)
        _log(db, mapping.id, fp, rule_id, agent_id, "mode_off")
        db.commit()
        return {
            "status": "ignored",
            "reason": "mapping mode is off",
            "mapping_id": mapping.id,
            "fingerprint": fp,
        }

    rule_id = alert.rule.id if alert.rule else None
    agent_id = alert.agent.id if alert.agent else None
    fp = fingerprint_for(mapping.id, rule_id, agent_id)

    if is_in_cooldown(db, fp, mapping.cooldown_seconds):
        _log(db, mapping.id, fp, rule_id, agent_id, "cooldown")
        db.commit()
        return {
            "status": "suppressed",
            "reason": f"within {mapping.cooldown_seconds}s cooldown",
            "mapping_id": mapping.id,
            "fingerprint": fp,
        }

    if mapping.mode == "auto":
        execution = _create_execution(db, mapping, alert, raw_alert, fp)
        _log(db, mapping.id, fp, rule_id, agent_id, "dispatched_auto")
        db.commit()
        return {
            "status": "dispatched",
            "mapping_id": mapping.id,
            "fingerprint": fp,
            "execution_id": execution.id,
        }

    if mapping.mode == "suggest":
        suggestion = _create_suggestion(db, mapping, alert, raw_alert, fp)
        _log(db, mapping.id, fp, rule_id, agent_id, "dispatched_suggest")
        db.commit()
        return {
            "status": "suggested",
            "mapping_id": mapping.id,
            "fingerprint": fp,
            "suggestion_id": suggestion.id,
        }

    # Should never happen: mode is validated on insert/update.
    raise ValueError(f"Unknown mapping mode: {mapping.mode!r}")


# --- Helpers for the router ---


def load_mapping(db: Session, mapping_id: int) -> Optional[WazuhMapping]:
    return db.query(WazuhMapping).filter(WazuhMapping.id == mapping_id).first()


def mapping_secret(mapping: WazuhMapping) -> Optional[str]:
    if not mapping.hmac_secret_encrypted:
        return None
    return decrypt_secret(mapping.hmac_secret_encrypted)
