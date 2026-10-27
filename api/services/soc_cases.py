"""Bounded finding candidate checks. No source or account authority is implied."""

import hashlib
import json
import re
from datetime import datetime, timezone

from pydantic import ValidationError
from sqlalchemy import LargeBinary, case, cast, func, select
from sqlalchemy.orm import Session

from api.integrations.clients.thehive import TheHiveClient, TheHiveError
from api.integrations.schemas import (
    FindingCandidate, FindingCaseMatch, FindingCheckRequest, FindingCheckResponse,
    FindingCoverage, FindingRunMatch, TheHiveReadId,
)
from api.orm_models import Execution

INVENTORY_LIMIT = 100
MAX_CONTEXT_BYTES = 65536
_TAG = re.compile(r"hotwash:finding:v1:([a-f0-9]{64})")
_CASE_ID = re.compile(r"~[A-Za-z0-9]{1,127}")
_LIFECYCLES = {"New": "open", "InProgress": "open", "Resolved": "closed", "Deleted": "closed"}
_STAGES = {**_LIFECYCLES, "Open": "open", "Closed": "closed"}


class FindingRunNotFound(Exception):
    """The optional run reference is absent from the same local snapshot."""


class _RunCandidate(FindingCandidate):
    case_id: TheHiveReadId | None = None


def finding_fingerprint(candidate: FindingCheckRequest) -> str:
    encoded = json.dumps([
        "hotwash-finding", 1, candidate.source, candidate.source_instance_ref,
        candidate.asset_id, candidate.rule_id, "sha256", candidate.sha256,
    ], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "v1:" + hashlib.sha256(encoded).hexdigest()


def _safe_case_id(value: object) -> str | None:
    return value if isinstance(value, str) and _CASE_ID.fullmatch(value) else None


def _case_matches(rows: object, fingerprint: str) -> tuple[list[FindingCaseMatch], set[str]]:
    if not isinstance(rows, list) or len(rows) > INVENTORY_LIMIT + 1:
        raise TheHiveError("Invalid case inventory")
    gaps = {"cases_capped"} if len(rows) > INVENTORY_LIMIT else set()
    matches = []
    seen = set()
    for row in rows[:INVENTORY_LIMIT]:
        if not isinstance(row, dict):
            gaps.add("case_record_invalid")
            continue
        case_id = _safe_case_id(row.get("_id", row.get("id")))
        if case_id is None or ("id" in row and row["id"] != case_id) or case_id in seen:
            gaps.add("case_record_invalid")
            continue
        seen.add(case_id)
        tags = row.get("tags")
        identities = set()
        if not isinstance(tags, list):
            gaps.add("case_identity_unmapped")
        else:
            # Inspect the entire bounded raw response, before any display cuts.
            for tag in tags:
                if not isinstance(tag, str):
                    gaps.add("case_identity_invalid")
                    continue
                match = _TAG.fullmatch(tag)
                if match:
                    identities.add("v1:" + match[1])
                elif tag.startswith("hotwash:finding:"):
                    gaps.add("case_identity_invalid")
            if not identities:
                gaps.add("case_identity_unmapped")
        if len(identities) > 1:
            gaps.add("case_identity_conflict")
        status, stage = row.get("status"), row.get("stage")
        lifecycle = _LIFECYCLES.get(status, "unknown") if isinstance(status, str) else "unknown"
        lifecycle_conflict = False
        if "stage" in row:
            stage_lifecycle = _STAGES.get(stage, "unknown") if isinstance(stage, str) else "unknown"
            if "unknown" in (stage_lifecycle, lifecycle):
                lifecycle = "unknown"
            elif stage_lifecycle != lifecycle:
                gaps.add("case_lifecycle_conflict")
                lifecycle_conflict = True
                lifecycle = "unknown"
        if lifecycle == "unknown" and not lifecycle_conflict:
            gaps.add("case_lifecycle_unknown")
        if fingerprint in identities:
            matches.append(FindingCaseMatch(case_id=case_id, lifecycle=lifecycle))
    return matches, gaps


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate context field")
        result[key] = value
    return result


def _run_snapshot(db: Session, candidate: FindingCheckRequest):
    # Own a separate read connection so closing the snapshot cannot flush,
    # commit, or roll back caller-owned work. Materialize before returning;
    # connection cleanup releases the reader before any upstream request.
    with db.get_bind().engine.connect() as connection:
        # sqlite3's legacy transaction mode does not BEGIN on SELECT.
        if connection.dialect.name == "sqlite":
            connection.exec_driver_sql("BEGIN")
        if candidate.run_id is not None:
            existing = connection.execute(select(Execution.id).where(Execution.id == candidate.run_id)).scalar_one_or_none()
            if existing is None:
                raise FindingRunNotFound()
        size = func.length(cast(Execution.context_json, LargeBinary))
        bounded_context = case((size <= MAX_CONTEXT_BYTES, Execution.context_json), else_=None)
        return connection.execute(select(Execution.id, size, bounded_context)
                                  .order_by(Execution.id.asc()).limit(INVENTORY_LIMIT + 1)).all()


def _run_matches(rows, fingerprint: str, cases: list[FindingCaseMatch]) -> tuple[list[FindingRunMatch], set[str]]:
    gaps = {"runs_capped"} if len(rows) > INVENTORY_LIMIT else set()
    visible = {row.case_id for row in cases}
    matches = []
    for run_id, size, raw in rows[:INVENTORY_LIMIT]:
        if size is not None and size > MAX_CONTEXT_BYTES:
            gaps.add("run_context_oversized")
            continue
        try:
            context = json.loads(raw, object_pairs_hook=_unique_object) if raw is not None else {}
            if not isinstance(context, dict):
                raise ValueError("Invalid context")
        except (ValueError, TypeError, RecursionError):
            gaps.add("run_context_invalid")
            continue
        try:
            identity = _RunCandidate.model_validate(context.get("soc_finding_v1"))
        except ValidationError:
            gaps.add("run_identity_unmapped")
            continue
        if finding_fingerprint(identity) != fingerprint:
            if identity.case_id in visible:
                gaps.add("run_case_link_conflict")
            continue
        gaps.add("run_attempt_state_unverified")
        if identity.case_id is None:
            gaps.add("run_case_link_missing")
        elif identity.case_id not in visible:
            gaps.add("run_case_link_unresolved")
        matches.append(FindingRunMatch(run_id=run_id, case_id=identity.case_id))
    return matches, gaps


def check_finding(db: Session, client: TheHiveClient, candidate: FindingCheckRequest) -> FindingCheckResponse:
    """Read one case page and one all-status run snapshot, without committing."""
    fingerprint = finding_fingerprint(candidate)
    rows = _run_snapshot(db, candidate)
    cases, case_gaps = _case_matches(client.list_cases(offset=0, limit=INVENTORY_LIMIT), fingerprint)
    runs, run_gaps = _run_matches(rows, fingerprint, cases)
    ambiguous = {"case_identity_conflict", "case_lifecycle_conflict"}
    blocking = (case_gaps | run_gaps) - ambiguous
    if blocking:
        disposition = "blocked"
    elif (case_gaps & ambiguous) or len(cases) > 1:
        disposition = "ambiguous"
    elif cases:
        disposition = "one_open_candidate" if cases[0].lifecycle == "open" else "closed_only"
    else:
        disposition = "no_match_visible"
    gaps = case_gaps | run_gaps | {
        "source_binding_unverified", "visibility_unverified", "query_contract_unverified",
    }
    return FindingCheckResponse(
        fingerprint=fingerprint,
        candidate=FindingCandidate.model_validate(candidate.model_dump(exclude={"run_id"})),
        case_matches=cases, run_matches=runs,
        coverage=FindingCoverage(cases="incomplete" if case_gaps else "unverified",
                                 runs="incomplete" if run_gaps - {"run_attempt_state_unverified"} else "complete",
                                 observed_at=datetime.now(timezone.utc)),
        disposition=disposition, gaps=sorted(gaps),
    )
