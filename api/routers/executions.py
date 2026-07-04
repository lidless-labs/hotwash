"""
Executions Router

REST + WebSocket endpoints for running incident playbooks step by step.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import PlainTextResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from api.auth import get_api_key, is_valid_api_key
from api.database import get_db, SessionLocal
from api.orm_models import Execution, ExecutionEvent, Playbook, RunEvent
from api.services import replay
from api.schemas import (
    ExecutionCreate,
    ExecutionDetail,
    ExecutionStep,
    ExecutionStepUpdate,
    ExecutionSummary,
    ExecutionUpdate,
    TimelineEventOut,
)
from api.services.executions import (
    TERMINAL_EXECUTION_STATUSES,
    broadcaster,
    build_steps_from_playbook,
    find_step,
    load_steps,
    now_iso,
    serialize_steps,
    step_progress,
)

logger = logging.getLogger(__name__)

EVIDENCE_ROOT = Path(__file__).resolve().parent.parent / "data" / "evidence"
MAX_EVIDENCE_BYTES = 25 * 1024 * 1024  # 25 MB
SAFE_NODE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
MAX_EVIDENCE_FILENAME_LENGTH = 255

VALID_EXECUTION_STATUSES = {"active", "paused", "completed", "abandoned"}
VALID_STEP_STATUSES = {"not_started", "in_progress", "completed", "skipped", "blocked"}

router = APIRouter(dependencies=[Depends(get_api_key)])

# Websocket route registered without auth so the existing client can connect;
# tighten with per-run tokens when the roadmap's auth design lands.
ws_router = APIRouter()


def _ensure_execution(db: Session, execution_id: int) -> Execution:
    execution = db.query(Execution).filter(Execution.id == execution_id).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    return execution


def _summary(execution: Execution, steps: List[Dict[str, Any]]) -> ExecutionSummary:
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


def _record_event(
    db: Session,
    execution: Execution,
    event_type: str,
    description: str,
    actor: Optional[str] = None,
) -> ExecutionEvent:
    event = ExecutionEvent(
        execution_id=execution.id,
        event_type=event_type,
        actor=actor,
        description=description,
    )
    db.add(event)
    db.flush()
    return event


def _record_run_event(
    db: Session,
    execution: Execution,
    event_type: str,
    payload: Dict[str, Any],
) -> RunEvent:
    """Append a structured, replayable event alongside the prose timeline event.

    ActiveGraph-inspired: these carry machine payloads sufficient to replay the
    run's step state (see api/services/replay.py). Emitted in addition to the
    existing steps_json write, so normal reads are unaffected and the projection
    can be diffed against steps_json as a correctness oracle.
    """
    event = RunEvent(
        execution_id=execution.id,
        event_type=event_type,
        payload_json=json.dumps(payload),
    )
    db.add(event)
    db.flush()
    return event


def _run_event_dicts(db: Session, execution_id: int, up_to_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Load an execution's run events in order as plain dicts for the reducer."""
    query = db.query(RunEvent).filter(RunEvent.execution_id == execution_id)
    if up_to_id is not None:
        query = query.filter(RunEvent.id <= up_to_id)
    rows = query.order_by(RunEvent.id).all()
    events: List[Dict[str, Any]] = []
    for row in rows:
        try:
            payload = json.loads(row.payload_json) if row.payload_json else {}
        except json.JSONDecodeError:
            payload = {}
        events.append({"id": row.id, "event_type": row.event_type, "payload": payload})
    return events


def _diff_step_state(a: Execution, b: Execution) -> Dict[str, Any]:
    """Structural diff of two runs' step state, keyed by node id."""
    steps_a = {s.get("node_id"): s for s in load_steps(a)}
    steps_b = {s.get("node_id"): s for s in load_steps(b)}
    fields = ["status", "assignee", "decision_taken", "notes", "evidence"]
    differences: List[Dict[str, Any]] = []
    for node_id in sorted(set(steps_a) | set(steps_b), key=lambda n: str(n)):
        x = steps_a.get(node_id)
        y = steps_b.get(node_id)
        if x is None:
            differences.append({"node_id": node_id, "issue": "only-in-b"})
            continue
        if y is None:
            differences.append({"node_id": node_id, "issue": "only-in-a"})
            continue
        field_diffs = {f: {"a": x.get(f), "b": y.get(f)} for f in fields if x.get(f) != y.get(f)}
        if field_diffs:
            differences.append({"node_id": node_id, "issue": "differs", "fields": field_diffs})
    return {"a": a.id, "b": b.id, "identical": not differences, "differences": differences}


async def _broadcast(execution_id: int, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
    payload = {"type": event_type, "timestamp": now_iso()}
    if data:
        payload["data"] = data
    await broadcaster.broadcast(execution_id, payload)


def _validate_node_id_for_path(node_id: str) -> None:
    if not SAFE_NODE_ID_RE.fullmatch(node_id):
        raise HTTPException(status_code=400, detail="Unsafe node_id for evidence storage")


def _validate_evidence_filename(filename: str | None) -> str:
    safe_name = (filename or "evidence.bin").strip()
    if (
        not safe_name
        or safe_name in {".", ".."}
        or len(safe_name) > MAX_EVIDENCE_FILENAME_LENGTH
        or "/" in safe_name
        or "\\" in safe_name
        or any(ord(ch) < 32 for ch in safe_name)
        or Path(safe_name).name != safe_name
    ):
        raise HTTPException(status_code=400, detail="Unsafe evidence filename")
    return safe_name


def _unique_evidence_path(target_dir: Path, filename: str) -> tuple[Path, str]:
    candidate = target_dir / filename
    if not candidate.exists():
        return candidate, filename

    parsed = Path(filename)
    stem = parsed.stem or "evidence"
    suffix = parsed.suffix
    for idx in range(1, 10000):
        unique_name = f"{stem}-{idx}{suffix}"
        candidate = target_dir / unique_name
        if not candidate.exists():
            return candidate, unique_name
    raise HTTPException(status_code=500, detail="Could not allocate evidence filename")


def _parse_dt(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if not value:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _format_duration_ms(milliseconds: Optional[float]) -> Optional[str]:
    if milliseconds is None or milliseconds < 0:
        return None
    if milliseconds < 60_000:
        return f"{round(milliseconds / 1000)}s"
    if milliseconds < 3_600_000:
        return f"{round(milliseconds / 60_000)}m"
    return f"{milliseconds / 3_600_000:.1f}h"


def _step_duration(step: Dict[str, Any]) -> Optional[float]:
    started = _parse_dt(step.get("started_at"))
    completed = _parse_dt(step.get("completed_at"))
    if not started or not completed:
        return None
    return (completed - started).total_seconds() * 1000


def _build_report(execution: Execution) -> Dict[str, Any]:
    steps = load_steps(execution)
    summary = _summary(execution, steps)
    durations = [
        (step, duration)
        for step in steps
        if (duration := _step_duration(step)) is not None
    ]
    bottleneck = max(durations, key=lambda item: item[1], default=None)
    total_duration = None
    if execution.started_at and execution.completed_at:
        total_duration = (execution.completed_at - execution.started_at).total_seconds() * 1000
    timeline = [
        TimelineEventOut(
            timestamp=event.timestamp,
            event_type=event.event_type,
            actor=event.actor,
            description=event.description,
        ).model_dump(mode="json")
        for event in execution.events
    ]

    report_steps = []
    for step in steps:
        duration = _step_duration(step)
        report_steps.append({
            **step,
            "duration": _format_duration_ms(duration),
        })

    return {
        "execution": summary.model_dump(mode="json"),
        "playbook_title": execution.playbook.title if execution.playbook else None,
        "metrics": {
            "total_duration": _format_duration_ms(total_duration),
            "steps_completed": summary.steps_completed,
            "steps_total": summary.steps_total,
            "mean_step_time": _format_duration_ms(
                sum(duration for _, duration in durations) / len(durations)
                if durations
                else None
            ),
            "bottleneck_step": bottleneck[0].get("node_label") if bottleneck else None,
            "bottleneck_time": _format_duration_ms(bottleneck[1]) if bottleneck else None,
        },
        "timeline": timeline,
        "steps": report_steps,
    }


def _report_to_markdown(report: Dict[str, Any]) -> str:
    execution = report["execution"]
    metrics = report["metrics"]
    lines = [
        "# After-Action Report",
        "",
        f"## {execution['incident_title']}",
        "",
        f"- Playbook: {report.get('playbook_title') or 'Unknown'}",
        f"- Status: {execution['status']}",
        f"- Started by: {execution.get('started_by') or 'Unknown'}",
        f"- Started at: {execution['started_at']}",
        f"- Completed at: {execution.get('completed_at') or 'Not completed'}",
        f"- Duration: {metrics.get('total_duration') or 'Unknown'}",
        f"- Steps completed: {metrics.get('steps_completed', 0)}/{metrics.get('steps_total', 0)}",
        "",
        "## Timeline",
        "",
    ]
    timeline = report.get("timeline") or []
    if timeline:
        for event in timeline:
            actor = f" ({event['actor']})" if event.get("actor") else ""
            lines.append(f"- {event['timestamp']}{actor}: {event['description']}")
    else:
        lines.append("- No timeline events recorded.")

    lines.extend(["", "## Steps", ""])
    for step in report.get("steps") or []:
        lines.append(f"### {step.get('node_label') or step.get('node_id')}")
        lines.append(f"- Status: {step.get('status')}")
        if step.get("assignee"):
            lines.append(f"- Assignee: {step['assignee']}")
        if step.get("duration"):
            lines.append(f"- Duration: {step['duration']}")
        notes = step.get("notes") or []
        if notes:
            lines.append("- Notes:")
            lines.extend(f"  - {note}" for note in notes)
        evidence = step.get("evidence") or []
        if evidence:
            lines.append("- Evidence:")
            lines.extend(f"  - {item.get('filename')} ({item.get('size')} bytes)" for item in evidence)
        lines.append("")

    return "\n".join(lines).strip() + "\n"


@router.post("/executions", response_model=ExecutionSummary, status_code=status.HTTP_201_CREATED)
async def create_execution(payload: ExecutionCreate, db: Session = Depends(get_db)):
    playbook = db.query(Playbook).filter(Playbook.id == payload.playbook_id, Playbook.is_deleted.is_(False)).first()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")

    steps = build_steps_from_playbook(playbook)

    execution = Execution(
        playbook_id=playbook.id,
        incident_title=payload.incident_title.strip(),
        incident_id=payload.incident_id,
        started_by=payload.started_by,
        status="active",
        steps_json=serialize_steps(steps),
        context_json=json.dumps(payload.context) if payload.context is not None else None,
    )
    db.add(execution)
    db.flush()

    _record_event(
        db,
        execution,
        event_type="execution_started",
        description=f"Execution started for playbook '{playbook.title}'",
        actor=payload.started_by,
    )
    # Genesis lives in the run_started event, so replay reproduces the exact
    # initial step state without depending on the (mutable) playbook graph.
    _record_run_event(db, execution, replay.RUN_STARTED, {"genesis": steps})
    db.commit()
    db.refresh(execution)

    summary = _summary(execution, steps)
    await _broadcast(execution.id, "execution_started", {"execution_id": execution.id})
    return summary


@router.get("/executions", response_model=List[ExecutionSummary])
def list_executions(
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    playbook_id: Optional[int] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    query = db.query(Execution)
    if status_filter:
        query = query.filter(Execution.status == status_filter)
    if playbook_id is not None:
        query = query.filter(Execution.playbook_id == playbook_id)
    executions = query.order_by(desc(Execution.started_at)).limit(limit).all()
    return [_summary(execution, load_steps(execution)) for execution in executions]


@router.get("/executions/{execution_id}", response_model=ExecutionDetail)
def get_execution(execution_id: int, db: Session = Depends(get_db)):
    execution = _ensure_execution(db, execution_id)
    steps = load_steps(execution)
    return ExecutionDetail(
        execution=_summary(execution, steps),
        steps=[ExecutionStep(**step) for step in steps],
        playbook_title=execution.playbook.title if execution.playbook else None,
    )


@router.patch("/executions/{execution_id}", response_model=ExecutionSummary)
async def update_execution(
    execution_id: int,
    payload: ExecutionUpdate,
    db: Session = Depends(get_db),
):
    execution = _ensure_execution(db, execution_id)

    if payload.status is not None:
        if payload.status not in VALID_EXECUTION_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status: {payload.status}")
        execution.status = payload.status
        if payload.status in TERMINAL_EXECUTION_STATUSES and execution.completed_at is None:
            execution.completed_at = datetime.now(timezone.utc)
        event_map = {
            "paused": ("execution_paused", "Execution paused"),
            "active": ("execution_resumed", "Execution resumed"),
            "completed": ("execution_completed", "Execution completed"),
            "abandoned": ("execution_abandoned", "Execution abandoned"),
        }
        event_type, description = event_map.get(payload.status, ("execution_updated", f"Status changed to {payload.status}"))
        _record_event(db, execution, event_type=event_type, description=description)
        _record_run_event(db, execution, replay.EXECUTION_STATUS_CHANGED, {"status": payload.status})

    if payload.notes is not None:
        execution.notes = payload.notes
        _record_event(db, execution, event_type="notes_updated", description="Execution notes updated")
        _record_run_event(db, execution, replay.EXECUTION_NOTES_UPDATED, {})

    db.commit()
    db.refresh(execution)
    steps = load_steps(execution)
    summary = _summary(execution, steps)
    await _broadcast(execution.id, "execution_updated", {"status": execution.status})
    return summary


@router.delete("/executions/{execution_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_execution(execution_id: int, db: Session = Depends(get_db)):
    execution = _ensure_execution(db, execution_id)
    db.delete(execution)
    db.commit()
    return None


@router.patch("/executions/{execution_id}/steps/{node_id}", response_model=ExecutionDetail)
async def update_step(
    execution_id: int,
    node_id: str,
    payload: ExecutionStepUpdate,
    db: Session = Depends(get_db),
):
    execution = _ensure_execution(db, execution_id)
    steps = load_steps(execution)
    step = find_step(steps, node_id)
    if step is None:
        raise HTTPException(status_code=404, detail="Step not found")

    now = datetime.now(timezone.utc).isoformat()
    events_to_emit: List[tuple[str, str]] = []
    # Structured, replayable counterparts to the prose events above. Carrying the
    # same `now` timestamp for started_at/completed_at lets the reducer reproduce
    # steps_json byte-for-byte.
    run_events_to_emit: List[tuple[str, Dict[str, Any]]] = []

    if payload.status is not None:
        if payload.status not in VALID_STEP_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid step status: {payload.status}")
        previous = step.get("status")
        step["status"] = payload.status
        if payload.status == "in_progress" and not step.get("started_at"):
            step["started_at"] = now
            events_to_emit.append(("step_started", f"Step '{step.get('node_label')}' started"))
        if payload.status in {"completed", "skipped"} and previous != payload.status:
            step["completed_at"] = now
            label = "completed" if payload.status == "completed" else "skipped"
            events_to_emit.append(("step_completed", f"Step '{step.get('node_label')}' {label}"))
        run_events_to_emit.append(
            (replay.STEP_STATUS_CHANGED, {"node_id": node_id, "status": payload.status, "at": now})
        )

    if payload.assignee is not None:
        step["assignee"] = payload.assignee or None
        events_to_emit.append(("assignee_changed", f"Assignee set to {payload.assignee or 'unassigned'} for '{step.get('node_label')}'"))
        run_events_to_emit.append((replay.STEP_ASSIGNEE_CHANGED, {"node_id": node_id, "assignee": payload.assignee or None}))

    if payload.notes:
        existing_notes = list(step.get("notes") or [])
        existing_notes.append(payload.notes)
        step["notes"] = existing_notes
        events_to_emit.append(("note_added", f"Note added to '{step.get('node_label')}'"))
        run_events_to_emit.append((replay.STEP_NOTE_ADDED, {"node_id": node_id, "note": payload.notes}))

    if payload.decision_taken is not None:
        step["decision_taken"] = payload.decision_taken
        events_to_emit.append(("decision_taken", f"Decision '{payload.decision_taken}' on '{step.get('node_label')}'"))
        run_events_to_emit.append((replay.STEP_DECISION_TAKEN, {"node_id": node_id, "decision": payload.decision_taken}))

    execution.steps_json = serialize_steps(steps)
    for event_type, description in events_to_emit:
        _record_event(db, execution, event_type=event_type, description=description)
    for run_event_type, run_payload in run_events_to_emit:
        _record_run_event(db, execution, run_event_type, run_payload)

    db.commit()
    db.refresh(execution)
    steps = load_steps(execution)

    detail = ExecutionDetail(
        execution=_summary(execution, steps),
        steps=[ExecutionStep(**s) for s in steps],
        playbook_title=execution.playbook.title if execution.playbook else None,
    )
    await _broadcast(execution.id, "step_updated", {"node_id": node_id})
    return detail


@router.post("/executions/{execution_id}/steps/{node_id}/evidence", response_model=ExecutionStep)
async def upload_evidence(
    execution_id: int,
    node_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    execution = _ensure_execution(db, execution_id)
    steps = load_steps(execution)
    step = find_step(steps, node_id)
    if step is None:
        raise HTTPException(status_code=404, detail="Step not found")

    body = await file.read()
    if len(body) > MAX_EVIDENCE_BYTES:
        raise HTTPException(status_code=413, detail="Evidence file exceeds size limit")

    _validate_node_id_for_path(node_id)
    target_dir = EVIDENCE_ROOT / str(execution.id) / node_id
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _validate_evidence_filename(file.filename)
    target_path, stored_name = _unique_evidence_path(target_dir, safe_name)
    target_path.write_bytes(body)

    uploaded_at = datetime.now(timezone.utc).isoformat()
    entry = {
        "filename": stored_name,
        "size": len(body),
        "uploaded_at": uploaded_at,
    }
    evidence_list = list(step.get("evidence") or [])
    evidence_list.append(entry)
    step["evidence"] = evidence_list

    execution.steps_json = serialize_steps(steps)
    _record_event(
        db,
        execution,
        event_type="evidence_attached",
        description=f"Evidence '{stored_name}' attached to '{step.get('node_label')}'",
    )
    _record_run_event(db, execution, replay.STEP_EVIDENCE_ATTACHED, {"node_id": node_id, "evidence": entry})
    db.commit()
    await _broadcast(execution.id, "evidence_attached", {"node_id": node_id, "filename": stored_name})
    return ExecutionStep(**step)


@router.get("/executions/{execution_id}/timeline", response_model=List[TimelineEventOut])
def get_timeline(execution_id: int, db: Session = Depends(get_db)):
    execution = _ensure_execution(db, execution_id)
    events = (
        db.query(ExecutionEvent)
        .filter(ExecutionEvent.execution_id == execution.id)
        .order_by(desc(ExecutionEvent.timestamp))
        .all()
    )
    return [
        TimelineEventOut(
            timestamp=event.timestamp,
            event_type=event.event_type,
            actor=event.actor,
            description=event.description,
        )
        for event in events
    ]


@router.get("/executions/{execution_id}/report")
def get_execution_report(execution_id: int, db: Session = Depends(get_db)):
    execution = _ensure_execution(db, execution_id)
    return _build_report(execution)


@router.get("/executions/{execution_id}/report/markdown")
def get_execution_report_markdown(execution_id: int, db: Session = Depends(get_db)):
    execution = _ensure_execution(db, execution_id)
    return PlainTextResponse(
        content=_report_to_markdown(_build_report(execution)),
        media_type="text/markdown",
    )


@router.get("/executions/{execution_id}/replay")
def replay_execution(execution_id: int, db: Session = Depends(get_db)):
    """Rebuild step state from the run_events log and report whether it matches.

    The built-in correctness oracle for the event stream: if ``matches_persisted``
    is ever false, the reducer and the router's mutation rules have drifted.
    """
    execution = _ensure_execution(db, execution_id)
    events = _run_event_dicts(db, execution.id)
    projected = replay.build_steps(events)
    persisted = load_steps(execution)
    return {
        "execution_id": execution.id,
        "event_count": len(events),
        "matches_persisted": projected == persisted,
        "steps": projected,
    }


@router.post("/executions/{execution_id}/fork", response_model=ExecutionSummary, status_code=status.HTTP_201_CREATED)
async def fork_execution(
    execution_id: int,
    at_event_id: Optional[int] = Query(default=None, description="Fork at this run_event id (default: latest)."),
    db: Session = Depends(get_db),
):
    """Branch a run at a chosen event and replay it into a new execution.

    ActiveGraph-inspired fork: copy the run_events up to the cut point into a new
    execution and replay them to seed its step state. The fork diverges freely
    without touching the parent. Genesis travels in the copied run_started event.
    """
    execution = _ensure_execution(db, execution_id)
    events = _run_event_dicts(db, execution.id, up_to_id=at_event_id)
    if not events:
        raise HTTPException(status_code=400, detail="No run events to fork from")

    projected = replay.build_steps(events)
    fork = Execution(
        playbook_id=execution.playbook_id,
        incident_title=f"{execution.incident_title} (fork)",
        incident_id=execution.incident_id,
        started_by=execution.started_by,
        status="active",
        steps_json=serialize_steps(projected),
        context_json=execution.context_json,
    )
    db.add(fork)
    db.flush()

    for event in events:
        _record_run_event(db, fork, event["event_type"], event["payload"])
    cut_id = events[-1]["id"]
    _record_run_event(
        db, fork, replay.RUN_FORKED, {"parent_execution_id": execution.id, "forked_from_event_id": cut_id}
    )
    _record_event(
        db,
        fork,
        event_type="forked_from",
        description=f"Forked from execution {execution.id} at event {cut_id}",
    )
    db.commit()
    db.refresh(fork)

    steps = load_steps(fork)
    summary = _summary(fork, steps)
    await _broadcast(fork.id, "execution_started", {"execution_id": fork.id, "forked_from": execution.id})
    return summary


@router.get("/executions/{execution_id}/diff/{other_id}")
def diff_executions(execution_id: int, other_id: int, db: Session = Depends(get_db)):
    """Structurally compare two runs' step state (e.g. a fork against its parent)."""
    a = _ensure_execution(db, execution_id)
    b = _ensure_execution(db, other_id)
    return _diff_step_state(a, b)


@ws_router.websocket("/executions/{execution_id}/live")
async def execution_socket(websocket: WebSocket, execution_id: int):
    if not is_valid_api_key(websocket.query_params.get("api_key")):
        await websocket.close(code=4401)
        return

    db = SessionLocal()
    try:
        exists = db.query(Execution.id).filter(Execution.id == execution_id).first()
    finally:
        db.close()
    if not exists:
        await websocket.close(code=4404)
        return

    await broadcaster.connect(execution_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.disconnect(execution_id, websocket)
