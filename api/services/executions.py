"""Execution service: build step state from playbook graphs and broadcast live events."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import WebSocket

from api.orm_models import Execution, Playbook

logger = logging.getLogger(__name__)


COMPLETED_STEP_STATUSES = {"completed", "skipped"}
TERMINAL_EXECUTION_STATUSES = {"completed", "abandoned"}


def build_steps_from_playbook(playbook: Playbook) -> List[Dict[str, Any]]:
    """Derive the initial step list for an execution from a playbook graph.

    Walks the graph in declared node order. Phase nodes set the current phase
    for subsequent non-phase nodes. Decision nodes get decision_options
    populated from outgoing edge labels.
    """
    if not playbook.graph_json:
        return []
    try:
        graph = json.loads(playbook.graph_json)
    except json.JSONDecodeError:
        logger.warning("Playbook %s has invalid graph_json; starting with empty steps", playbook.id)
        return []

    nodes: List[Dict[str, Any]] = list(graph.get("nodes") or [])
    edges: List[Dict[str, Any]] = list(graph.get("edges") or [])

    outgoing_by_source: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        source = edge.get("source")
        if source:
            outgoing_by_source[source].append(edge)

    steps: List[Dict[str, Any]] = []
    current_phase: Optional[str] = None
    seen_node_ids: set[str] = set()

    for node in nodes:
        node_type = (node.get("type") or "step").lower()
        node_id = str(node.get("id") or "")
        if not node_id:
            continue
        # find_step() resolves a node_id to the first matching step, so a second
        # step with the same id would be unreachable (never startable, but still
        # counted in steps_total so a run could never reach 100%). Keep the first.
        if node_id in seen_node_ids:
            logger.warning(
                "Playbook %s has duplicate node id %r; keeping the first step and skipping the rest",
                playbook.id,
                node_id,
            )
            continue
        seen_node_ids.add(node_id)
        label = node.get("label") or node_id

        if node_type == "phase":
            current_phase = label
            steps.append({
                "node_id": node_id,
                "node_type": "phase",
                "node_label": label,
                "phase": label,
                "status": "not_started",
                "assignee": None,
                "notes": [],
                "evidence": [],
                "decision_taken": None,
                "decision_options": None,
                "started_at": None,
                "completed_at": None,
            })
            continue

        decision_options: Optional[List[str]] = None
        if node_type == "decision":
            options = [edge.get("label") for edge in outgoing_by_source.get(node_id, []) if edge.get("label")]
            decision_options = options or None

        steps.append({
            "node_id": node_id,
            "node_type": node_type,
            "node_label": label,
            "phase": current_phase,
            "status": "not_started",
            "assignee": None,
            "notes": [],
            "evidence": [],
            "decision_taken": None,
            "decision_options": decision_options,
            "started_at": None,
            "completed_at": None,
        })

    return steps


def load_steps(execution: Execution) -> List[Dict[str, Any]]:
    if not execution.steps_json:
        return []
    try:
        loaded = json.loads(execution.steps_json)
    except json.JSONDecodeError:
        logger.warning("Execution %s has invalid steps_json; treating as empty", execution.id)
        return []
    return loaded if isinstance(loaded, list) else []


def serialize_steps(steps: List[Dict[str, Any]]) -> str:
    return json.dumps(steps, default=_json_default)


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def find_step(steps: List[Dict[str, Any]], node_id: str) -> Optional[Dict[str, Any]]:
    for step in steps:
        if step.get("node_id") == node_id:
            return step
    return None


def step_progress(steps: List[Dict[str, Any]]) -> tuple[int, int]:
    """(total, completed) excluding phase markers."""
    countable = [s for s in steps if (s.get("node_type") or "").lower() != "phase"]
    total = len(countable)
    completed = sum(1 for s in countable if s.get("status") in COMPLETED_STEP_STATUSES)
    return total, completed


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecutionBroadcaster:
    """In-memory websocket fan-out per execution id.

    Single-process only. If the API ever runs multi-worker, swap this for a
    pub/sub backend (Redis, NATS) without changing callers.
    """

    def __init__(self) -> None:
        self._connections: Dict[int, set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, execution_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections[execution_id].add(websocket)

    async def disconnect(self, execution_id: int, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections[execution_id].discard(websocket)
            if not self._connections[execution_id]:
                self._connections.pop(execution_id, None)

    async def broadcast(self, execution_id: int, payload: Dict[str, Any]) -> None:
        message = json.dumps(payload, default=_json_default)
        async with self._lock:
            targets = list(self._connections.get(execution_id, ()))
        for ws in targets:
            try:
                await ws.send_text(message)
            except Exception:
                async with self._lock:
                    self._connections[execution_id].discard(ws)


broadcaster = ExecutionBroadcaster()
