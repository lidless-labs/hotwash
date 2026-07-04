"""Pure reducer that folds run_events into execution step state.

ActiveGraph-inspired (see docs/design/activegraph-inspiration.md): the run's
step state is a projection of an append-only event log. ``build_steps`` replays
the events over the genesis carried in the ``run_started`` event, exactly the
way ActiveGraph's ``apply_event`` folds its log into current state.

Everything here is pure: it takes plain event dicts (event_type + payload) and
returns a step list, so it can reproduce ``steps_json`` independently and be
diffed against it as a correctness oracle.
"""

from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional

# Event type constants. Step-level events are folded into step state; the others
# carry genesis, lineage, or execution-level changes that the step reducer skips.
RUN_STARTED = "run_started"
RUN_FORKED = "run_forked"
STEP_STATUS_CHANGED = "step_status_changed"
STEP_ASSIGNEE_CHANGED = "step_assignee_changed"
STEP_NOTE_ADDED = "step_note_added"
STEP_DECISION_TAKEN = "step_decision_taken"
STEP_EVIDENCE_ATTACHED = "step_evidence_attached"
EXECUTION_STATUS_CHANGED = "execution_status_changed"
EXECUTION_NOTES_UPDATED = "execution_notes_updated"

COMPLETED_STEP_STATUSES = {"completed", "skipped"}


def _payload(event: Dict[str, Any]) -> Dict[str, Any]:
    raw = event.get("payload")
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _find(steps: List[Dict[str, Any]], node_id: str) -> Optional[Dict[str, Any]]:
    for step in steps:
        if step.get("node_id") == node_id:
            return step
    return None


def apply_event(steps: List[Dict[str, Any]], event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Fold one event into the step list, mirroring the router's mutation rules.

    Returns the same list (mutated in place) for fold convenience. Non-step
    events are no-ops for step state.
    """
    etype = event.get("event_type")
    payload = _payload(event)

    if etype in (RUN_STARTED, RUN_FORKED, EXECUTION_STATUS_CHANGED, EXECUTION_NOTES_UPDATED):
        return steps

    node_id = payload.get("node_id")
    if not node_id:
        return steps
    step = _find(steps, node_id)
    if step is None:
        return steps

    if etype == STEP_STATUS_CHANGED:
        new_status = payload.get("status")
        at = payload.get("at")
        previous = step.get("status")
        step["status"] = new_status
        # started_at is set once, on the first transition into in_progress.
        if new_status == "in_progress" and not step.get("started_at"):
            step["started_at"] = at
        # completed_at is stamped on the transition into a terminal step status.
        if new_status in COMPLETED_STEP_STATUSES and previous != new_status:
            step["completed_at"] = at
    elif etype == STEP_ASSIGNEE_CHANGED:
        step["assignee"] = payload.get("assignee") or None
    elif etype == STEP_NOTE_ADDED:
        note = payload.get("note")
        if note:
            step["notes"] = list(step.get("notes") or []) + [note]
    elif etype == STEP_DECISION_TAKEN:
        step["decision_taken"] = payload.get("decision")
    elif etype == STEP_EVIDENCE_ATTACHED:
        entry = payload.get("evidence")
        if entry:
            step["evidence"] = list(step.get("evidence") or []) + [entry]

    return steps


def genesis_from(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The initial step list carried by the run_started event (deep-copied)."""
    for event in events:
        if event.get("event_type") == RUN_STARTED:
            genesis = _payload(event).get("genesis")
            if isinstance(genesis, list):
                return copy.deepcopy(genesis)
            return []
    return []


def build_steps(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Replay an ordered event list into the step state it projects to."""
    steps = genesis_from(events)
    for event in events:
        apply_event(steps, event)
    return steps
