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
    RootcheckCandidate, RootcheckCheckRequest, RootcheckCheckResponse, RootcheckCoverage,
    RootcheckCaseMatch, RootcheckRunMatch, RootcheckReceiptProjection, RootcheckReceiptRow,
    _RootcheckReceiptInput, validate_rootcheck_path,
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


def _case_matches(rows: object, fingerprint: str, *, rootcheck_scope: str | None = None) -> tuple[list[FindingCaseMatch], set[str]]:
    if not isinstance(rows, list) or len(rows) > INVENTORY_LIMIT + 1:
        raise TheHiveError("Invalid case inventory")
    gaps = {"cases_capped"} if len(rows) > INVENTORY_LIMIT else set()
    matches = []
    seen = set()
    tag_pattern = _TAG if rootcheck_scope is None else re.compile(
        rf"hotwash:rootcheck:v2:{rootcheck_scope}:([a-f0-9]{{64}})")
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
                match = tag_pattern.fullmatch(tag)
                if match:
                    identities.add(("v1:" if rootcheck_scope is None else "v2:") + match[1])
                elif rootcheck_scope is not None and (
                        re.fullmatch(r"hotwash:rootcheck:v2:(?:group|path):[a-f0-9]{64}", tag)
                        or tag.startswith("hotwash:finding:")):
                    # Legacy and cross-granularity hints cannot establish absence.
                    gaps.add("case_identity_unmapped")
                elif tag.startswith("hotwash:finding:" if rootcheck_scope is None else "hotwash:rootcheck:"):
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


def _run_snapshot(db: Session, candidate: FindingCheckRequest | RootcheckCheckRequest):
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


class _RootcheckRunCandidate(RootcheckCandidate):
    case_id: TheHiveReadId | None = None


def rootcheck_candidate_key(candidate: RootcheckCandidate) -> str:
    """Hash the exact scoped candidate tuple, never source authenticity."""
    encoded = json.dumps([
        "hotwash-rootcheck", 2, candidate.source, candidate.source_instance_ref,
        candidate.agent_registration_ref, candidate.agent_id, candidate.signature,
        candidate.scope, candidate.subject,
    ], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "v2:" + hashlib.sha256(encoded).hexdigest()


def _rootcheck_run_matches(rows, candidate: RootcheckCandidate, cases: list[RootcheckCaseMatch]):
    gaps = {"runs_capped"} if len(rows) > INVENTORY_LIMIT else set()
    visible = {row.case_id for row in cases}
    key = rootcheck_candidate_key(candidate)
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
            identity = _RootcheckRunCandidate.model_validate(context.get("soc_rootcheck_v2"))
        except ValidationError:
            gaps.add("run_identity_unmapped")
            continue
        if identity.scope != candidate.scope or "soc_finding_v1" in context:
            gaps.add("run_identity_unmapped")
        if rootcheck_candidate_key(identity) != key:
            if identity.case_id in visible:
                gaps.add("run_case_link_conflict")
            continue
        gaps.add("run_attempt_state_unverified")
        if identity.case_id is None:
            gaps.add("run_case_link_missing")
        elif identity.case_id not in visible:
            gaps.add("run_case_link_unresolved")
        matches.append(RootcheckRunMatch(run_id=run_id, case_id=identity.case_id))
    return matches, gaps


def check_rootcheck(db: Session, client: TheHiveClient, candidate: RootcheckCheckRequest) -> RootcheckCheckResponse:
    """Read bounded all-state inventories. Hints never authorize case creation."""
    key = rootcheck_candidate_key(candidate)
    rows = _run_snapshot(db, candidate)
    found, case_gaps = _case_matches(client.list_cases(offset=0, limit=INVENTORY_LIMIT), key,
                                     rootcheck_scope=candidate.scope)
    cases = [RootcheckCaseMatch(case_id=row.case_id, lifecycle=row.lifecycle) for row in found]
    runs, run_gaps = _rootcheck_run_matches(rows, candidate, cases)
    ambiguous = {"case_identity_conflict", "case_lifecycle_conflict"}
    if (case_gaps | run_gaps) - ambiguous:
        disposition = "blocked"
    elif case_gaps & ambiguous or len(cases) > 1:
        disposition = "ambiguous"
    elif cases:
        disposition = "one_open_candidate" if cases[0].lifecycle == "open" else "closed_only"
    else:
        disposition = "no_match_visible"
    return RootcheckCheckResponse(
        candidate_key=key,
        candidate=RootcheckCandidate.model_validate(candidate.model_dump(exclude={"run_id"})),
        case_matches=cases, run_matches=runs,
        coverage=RootcheckCoverage(cases="incomplete" if case_gaps else "unverified",
                                   runs="incomplete" if run_gaps - {"run_attempt_state_unverified"} else "complete",
                                   observed_at=datetime.now(timezone.utc)),
        disposition=disposition,
        gaps=sorted(case_gaps | run_gaps | {
            "source_binding_unverified", "visibility_unverified", "query_contract_unverified",
        }),
    )


_RECEIPT_OPEN = "<untrusted_siem_data>"
_RECEIPT_CLOSE = "</untrusted_siem_data>"
_ROOTCHECK_LOG = re.compile(r"File '([^']+)' present on /dev\. Possible hidden file\.")
_ENTITIES = {"&amp;": "&", "&lt;": "<", "&gt;": ">"}


def _receipt_path(log: str) -> str | None:
    if not log.startswith(_RECEIPT_OPEN) or not log.endswith(_RECEIPT_CLOSE):
        raise ValueError("Invalid receipt wrapper")
    body = log[len(_RECEIPT_OPEN):-len(_RECEIPT_CLOSE)]
    if _RECEIPT_OPEN in body or _RECEIPT_CLOSE in body:
        raise ValueError("Nested receipt wrapper")
    # A single substitution decodes only the documented entities once.
    body = re.sub(r"&(?:amp|lt|gt);", lambda match: _ENTITIES[match[0]], body)
    match = _ROOTCHECK_LOG.fullmatch(body)
    if match:
        path = match[1]
        if path.startswith("/dev/.lxc/proc/") or path == "/dev/.lxc/proc":
            return validate_rootcheck_path(path)
    # An attempted group observation must not silently become a non-group row.
    if "/dev/.lxc/proc" in body or body.lstrip().startswith("File '") and match is None:
        raise ValueError("Ambiguous rootcheck log")
    return None


def _receipt_time(value: str) -> datetime:
    # Accept the retained ISO forms while preserving the original strings.
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
                    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])", value) is None:
        raise ValueError("Invalid receipt timestamp")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def project_rootcheck_receipt(payload: object) -> RootcheckReceiptProjection:
    """Project already-loaded recovery data offline, atomically and without logs."""
    def failure(disposition):
        return RootcheckReceiptProjection(disposition=disposition)

    if not isinstance(payload, dict):
        return failure("receipt_invalid")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 1048576:
            return failure("receipt_capped")
        raw_rows = payload.get("records")
        if isinstance(raw_rows, list):
            if len(raw_rows) > INVENTORY_LIMIT:
                return failure("receipt_capped")
            for row in raw_rows:
                log = row.get("source_signature_log") if isinstance(row, dict) else None
                if isinstance(log, str) and len(log.encode("utf-8")) > 8192:
                    return failure("receipt_capped")
        receipt = _RootcheckReceiptInput.model_validate(payload)
    except (ValidationError, ValueError, TypeError, OverflowError, RecursionError):
        return failure("receipt_invalid")
    page = receipt.pagination
    if receipt.total > INVENTORY_LIMIT or page.total > INVENTORY_LIMIT or page.has_more or page.offset != 0:
        return failure("receipt_capped")
    if receipt.result_is_error:
        return failure("receipt_invalid")
    if not (receipt.total == receipt.returned == page.total == len(receipt.records)
            and page.limit == receipt.request.limit and receipt.returned <= page.limit):
        return failure("receipt_inconsistent")
    try:
        request_at = _receipt_time(receipt.request_observed_at)
        result_at = _receipt_time(receipt.result_observed_at)
        recovered_at = _receipt_time(receipt.recovered_at)
        row_times = [(_receipt_time(row.date_first), _receipt_time(row.date_last)) for row in receipt.records]
    except ValueError:
        return failure("receipt_invalid")
    if not request_at <= result_at <= recovered_at:
        return failure("receipt_inconsistent")
    if any(first > last or last > result_at for first, last in row_times):
        return failure("receipt_inconsistent")
    if receipt.request.status == "outstanding" and any(row.status != "outstanding" for row in receipt.records):
        return failure("receipt_inconsistent")
    rows, other_indexes = [], []
    for index, row in enumerate(receipt.records):
        if row.receipt_index != index:
            return failure("receipt_inconsistent")
        try:
            path = _receipt_path(row.source_signature_log)
        except ValueError:
            return failure("receipt_invalid")
        if row.proc_paths != ([] if path is None else [path]):
            return failure("receipt_inconsistent")
        if path is None:
            other_indexes.append(index)
        else:
            rows.append(RootcheckReceiptRow(
                receipt_index=index, source_record_id=None, path=path, status=row.status,
                date_first=row.date_first, date_last=row.date_last,
            ))
    paths = sorted({row.path for row in rows})
    if (receipt.exact_proc_paths != paths or receipt.proc_path_records != len(rows)
            or receipt.other_records != len(other_indexes)):
        return failure("receipt_inconsistent")
    metadata = receipt.model_dump(include={
        "source_session", "cache_offset", "tool_name", "tool_call_id", "request",
        "request_observed_at", "result_observed_at", "recovered_at", "result_is_error",
        "total", "returned", "pagination", "source_payload_sha256",
    })
    return RootcheckReceiptProjection(disposition="projected", rows=rows, exact_proc_paths=paths,
                                      other_records=len(other_indexes), other_receipt_indexes=other_indexes, **metadata)
